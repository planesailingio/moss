# Architecture

moss is a thin Rust CLI over the Kopia command line. Kopia is the engine; the profile model is the
product. This document maps the source tree, traces a backup and a restore, and records the rules
that keep the Kopia coupling and the OS-specific code contained. Section references (§n) are to
[spec.md](spec.md).

## Module map

| Module | Responsibility |
|---|---|
| `cli/` | clap definitions (`mod.rs`: global flags and the command enum) and one file per command group: `init`, `doctor`, `inspect`, `backup`, `snapshots`, `restore`, `maintenance` (`status`, `verify`, `prune`, `maintenance`), `misc` (`config`, `include`, `exclude`, `recovery`, `yubikey`, `kopia`). `context.rs` holds per-invocation state and the connect path. |
| `config/` | `model.rs`: the YAML schema (`deny_unknown_fields`, no secrets). `paths.rs`: where config, state and cache live per OS. `mod.rs`: load, save (atomic, 0600), render. |
| `credentials/` | `CredentialStore` trait; `keyring_store` (Keychain, Secret Service, Credential Manager via `keyring` 4); `env_store` (`MOSS_REPOSITORY_PASSWORD`); `mock` for tests. Holds the repository password only. |
| `security/` | `secret.rs`: `Secret`, a zeroising string whose `Debug` and `Display` print `[redacted]`. `recovery.rs`: 32 bytes of entropy to a 24-word BIP39 sentence, and back. |
| `backup/` | `kopia.rs`: the subprocess runner, version pin, environment allowlist, stderr classification. `json.rs`: defensive views of Kopia's `--json`. `repository.rs`: typed operations (create, connect, status, policy, snapshot create/list/restore/verify/expire, maintenance). `run.rs`: the backup run. `manifest.rs`: the per-run manifest. `tags.rs`: the tag scheme. |
| `profile/` | `model.rs`: `ProfileSource`, `ProfileCategory`, `Portability`, `SemanticId`. `discovery.rs`: the known-source table and user includes. `rules.rs`: one gitignore matcher built from `patterns.rs` (default exclusions), tool-reported caches (`tools.rs`), moss's and Kopia's own state, and user excludes. `sensitive.rs`: metadata-only classification. `xdg.rs`: in-tree XDG user-dirs parser. `macos.rs`, `linux.rs`, `windows.rs`: the three `PlatformAdapter` implementations. |
| `platform/` | `Platform`, `HostInfo`, the `PlatformAdapter` trait and `current_adapter()`. `tcc.rs`: errno classification (`EPERM` is TCC, `EACCES` is permissions) and the Full Disk Access probe. |
| `scan/` | `walker.rs`: parallel walk with exclusions applied during descent and partial failure recorded inline. `index.rs`: the scan index. `collisions.rs`: case, normalisation, Windows-illegal-name and path-length detection. `progress.rs`: fixed-rate progress that degrades off a TTY. |
| `restore/` | `select.rs`: run selection. `stage`: Kopia restore into staging. `place.rs`: placement through containment. `conflict.rs`: skip/overwrite/backup/interactive. `journal.rs`: the write-ahead restore journal. `translate.rs`: semantic id to destination path. `report.rs`: the embedded-path report. `contain/`: the per-OS containment primitives. |
| `lock.rs` | The moss-level lock (`std::fs::File::try_lock`) with PID, start time and a liveness check. |
| `endpoints.rs` | Static, cited table of S3-compatible vendors for `init list-backup-endpoints`. |
| `yubikey/` | `HardwareKeyProvider` trait, a `NoneProvider` for v1 and a `MockProvider` for tests. Phase 2 implements it with `age-plugin-yubikey`. |
| `output/` | `Console`: TTY, `NO_COLOR`, `--quiet`, `--json` decided once; `json_report` prefixes `schema_version`; prompts that fail with exit 13 when no terminal is available. `human.rs`: tables, byte and age formatting. |
| `error.rs` | `MossError` and `ExitCode`; the only place Kopia failures become exit codes. |

## A backup run

```text
moss backup
  │
  ├─ Lock            <state>/lock via File::try_lock; exit 10 naming the holder (lock.rs)
  ├─ Connect         config → repository config → password (env, then store) → KopiaContext
  ├─ Gates           recovery sheet acknowledged? (13)  sources selected? (1)
  ├─ Scan            profile::discovery → scan::build_rules → scan::scan (walker, index)
  ├─ Gates           sensitive data (6, or prompt/--yes/13)  guardrails (prompt/--yes/13)
  ├─ Manifest        run::build_manifest → <state>/manifests/<run>/moss-manifest.json
  ├─ Policies        kopia policy set <source> --clear-ignore
  │                  kopia policy set <source> --ignore-file-errors=true --ignore-dir-errors=true
  │                                            --ignore-unknown-types=true --add-ignore=… (one per rule)
  ├─ Snapshots       for each source: kopia snapshot create --json --tags … <path>
  │                    read rootEntry.summ.numFailed (absent ⇒ Integrity error, 8)
  │                    read rootEntry.summ.numIgnoredErrors (absent ⇒ 0)
  │                    fold unpredicted errors into manifest.skipped
  ├─ Manifest        rewrite with snapshot ids; kopia snapshot create --json --tags … <manifest dir>
  └─ Exit            0 if no skipped paths and no errors, else 9
```

Kopia's exit code is never used to decide completeness (§18): fatal errors exit 1 but the snapshot
manifest has already been written, and ignored errors exit 0. `repository.rs::snapshot_create`
therefore parses whatever JSON Kopia printed regardless of exit status.

`--dry-run` stops after the manifest is built and prints it.

## A restore

```text
moss restore [latest | <run-id prefix>] [--from-host H] [--category C] [--source S]
  │
  ├─ Lock
  ├─ Select          snapshot list --all --json, grouped by moss-run; pick the run and its members
  ├─ Stage manifest  kopia snapshot restore <manifest snapshot> <state>/staging/<run>/manifest
  │                  validate schema_version, run id, sources; treat every path as untrusted
  ├─ Collisions      probe the destination (create `Case`/`case`, NFC/NFD) → exit 5 unless --rename-collisions
  ├─ Per source      kopia snapshot restore --write-sparse-files --no-ignore-permission-errors
  │                    --write-files-atomically [--skip-owners] <id> <state>/staging/<run>/<source>
  │                  translate semantic id → destination via the current PlatformAdapter
  │                  check the category matches the destination
  │                  journal entry (fsync) → place via contain/ → conflict policy → journal complete
  ├─ Report          embedded absolute paths that will not resolve here, by file and line
  └─ Exit            0, or 5 for an unresolved conflict or collision
```

Placement opens the destination through a containment primitive and writes to the resulting
descriptor or handle. No path string is re-resolved after validation (§16 TOCTOU); on Windows the
walk, rename and delete are all `NtCreateFile`/`NtSetInformationFile` calls relative to the verified
parent handle, and the one path-based operation Win32 forces — symlink creation — is re-verified
through that handle immediately afterwards (`restore/contain/windows.rs`). Symlinks in staging are
recreated as symlinks, never followed. Staging is on the same volume as the home directory so
placement can `rename`.

## One moss run = N Kopia snapshots + 1 manifest snapshot

Kopia snapshots are per source path. A moss run snapshots every selected source separately, then
the manifest directory, and tags them all identically. Kopia splits `--tags` on the first colon and
rejects duplicate keys, so the keys use hyphens (verified against 0.23.1):

| Tag key | Value |
|---|---|
| `moss-run` | ULID of the run; this is the id `moss snapshots` shows |
| `moss-profile` | profile identity (§22), colons and whitespace replaced by `_` |
| `moss-source` | semantic id of the source, or `manifest` for the manifest snapshot |
| `moss-os` | `macos`, `linux` or `windows` |
| `moss-schema` | `1` |

`snapshot list --json` returns the keys as `tag:moss-run` and so on; `json.rs::SnapshotManifest::tag`
accepts both forms. `snapshots.rs::group_runs` groups by `moss-run`, sums error counts over the
data members, and labels the run `complete`, `partial (n skipped)` or `incomplete (no manifest)`.
A member whose `numFailed` is absent counts as one error, never as zero.

## Where files live

From `config/paths.rs`. `directories` appends `\config`, `\data`, `\cache` on Windows; moss strips
them so there is one directory per purpose on every OS.

| | macOS | Linux | Windows |
|---|---|---|---|
| config | `~/Library/Application Support/moss` | `$XDG_CONFIG_HOME/moss` (`~/.config/moss`) | `%APPDATA%\moss` |
| state | `~/Library/Application Support/moss` | `$XDG_STATE_HOME/moss` (`~/.local/state/moss`) | `%LOCALAPPDATA%\moss` |
| cache | `~/Library/Caches/moss` | `$XDG_CACHE_HOME/moss` (`~/.cache/moss`) | `%LOCALAPPDATA%\moss\cache` |

| File | Purpose |
|---|---|
| `<config>/config.yaml` | the configuration; `--config` or `MOSS_CONFIG` overrides |
| `<state>/lock` | the moss-level lock (PID and start time inside) |
| `<state>/index.json` | the scan index |
| `<state>/manifests/<run>/moss-manifest.json` | the manifest for each run; the directory is the manifest snapshot's source |
| `<state>/restore-journal.json` | the restore journal |
| `<state>/staging/` | restore staging |
| `<state>/kopia/<repository id>.config` | Kopia's config file for this repository (`--config-file`); holds S3 keys if any; 0600 |
| `<state>/kopia-logs/` | Kopia's file logs, written only under `--verbose` |
| `<cache>/kopia/` | Kopia's cache (`--cache-directory`) |

Directories are created 0700 and files 0600 on Unix. `MOSS_HOME=<dir>` puts all three under
`<dir>/config`, `<dir>/state`, `<dir>/cache` (tests and schedulers); `MOSS_STATE_DIR` and
`MOSS_CACHE_DIR` override individually. The repository id is a hash of the storage location, so
it is stable across machines that point at the same repository.

All of these directories, plus the user's own Kopia config and cache (`~/Library/Application
Support/kopia`, `~/.config/kopia`, `%APPDATA%\kopia` and their caches), are excluded from backups
by construction (`scan::build_rules`).

## Kopia process hygiene

`backup/kopia.rs::KopiaContext::command` builds every Kopia command line; nothing else spawns
Kopia. Each invocation:

- starts from `env_clear()` and an explicit allowlist: `PATH`, `HOME`, `USERPROFILE`, `TMPDIR`,
  `TMP`, `TEMP`, `LANG`, `LC_ALL`, the six `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` variants, and on
  Windows `SYSTEMROOT`, `SystemRoot`, `APPDATA`, `LOCALAPPDATA`, `COMSPEC`. The parent
  environment is never copied wholesale;
- sets `KOPIA_CHECK_FOR_UPDATES=false` (§33);
- adds `KOPIA_PASSWORD` from a `Secret` for repository commands, and `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` on `repository create`/`connect` only, never as
  flags;
- passes `--config-file=<state>/kopia/<id>.config`, `--no-persist-credentials`,
  `--no-use-keychain`, `--no-progress`, and either `--disable-file-logging` or, under
  `--verbose`, `--log-dir=<state>/kopia-logs`;
- on create/connect also passes `--no-check-for-updates` and `--cache-directory=<cache>/kopia`;
- closes stdin, captures stdout and stderr, and drops the `Command` (and its copy of the
  password) as soon as the child exits.

After create/connect, moss re-tightens the config file to 0600. Stderr is translated into typed
errors by `classify_failure`; raw Kopia text is attached as `detail` and shown only under
`--verbose`. `repository status --json` output is parsed and never logged (§5).

## Version pin and JSON fixtures

`backup/kopia.rs` declares `KOPIA_MIN = (0, 23, 0)` and `KOPIA_MAX_MINOR = (0, 23)`. The version
is probed once per process (`OnceLock`) with `kopia --version`; any repository command outside the
range fails with exit 12 unless `--skip-version-check`. Kopia missing entirely is exit 11.

Kopia's `--json` is `json.Marshal` over internal structs with no stability promise. `json.rs`
uses `#[serde(default)]` everywhere and never `deny_unknown_fields`. Values critical to
correctness are `Option` so absence is detectable: `numFailed` absent is an error, not zero.
Captured output from the pinned version lives in `tests/fixtures/kopia/<version>/` and is what the
unit tests parse. Bumping the pin means capturing new fixtures, diffing them, and reviewing
`json.rs` (see [docs/kopia-compat.md](docs/kopia-compat.md)).

## Boundaries

- **OS-specific code.** `cfg(target_os = …)` is confined to `platform/` and the three adapters
  `profile/{macos,linux,windows}.rs`; everything else asks the `PlatformAdapter`. Family gates
  (`cfg(unix)`, `cfg(windows)`) are allowed where a std API differs: file modes in
  `config/paths.rs` and `cli/maintenance.rs`, process liveness in `lock.rs`, the Windows
  environment additions in `backup/kopia.rs`, and the containment primitives under
  `restore/contain/`. One exception is known and deliberate: `cli/doctor.rs` has a macOS-only
  check for running under launchd without a terminal (§32), which has no adapter equivalent yet.
- **Kopia.** Only `backup/kopia.rs` spawns it; only `backup/repository.rs` knows its flags; only
  `backup/json.rs` knows its JSON. Kopia's exit code never becomes moss's exit code.
- **Secrets.** The password exists as a `Secret` from the store to the child environment and
  nowhere else. There is no `--password` flag, and a test asserts none is ever added.
- **Errors.** Every failure crossing a module boundary is a `MossError`; `error.rs` is the only
  mapping to exit codes, and messages are written for the user (§37).
- **Configuration.** `config.yaml` holds no secrets and rejects unknown keys. The source list is
  written by `init` so the user can read and edit it; the scan index is machine-managed and lives
  in state.
