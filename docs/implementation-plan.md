# moss implementation plan

Companion to [`spec.md`](../spec.md) revision 3 (2026-09-03). The spec says *what*; this document
says *in what order, in which files, and how each step is verified*. Section references (§n) are to
the spec.

## Status (2026-09-04)

Steps 0–12 are implemented and committed. Verified on macOS 26.5.1 with Kopia 0.23.1: the
full gate (`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`: 117 unit tests, 6
end-to-end tests), the §39 walk by hand (`init`, `doctor`, `inspect`, `backup`, `snapshots`,
`status`, `verify`, `restore` with dry-run, `--to`, conflict policies and exit codes), the
second-machine bootstrap by recovery code, and both halves of the CI cross-platform script.

Not yet verified: compilation on Linux and Windows (no cross toolchain on the dev machine; the
Windows containment code has never been compiled), the GitHub Actions workflows themselves, the
Homebrew tap push, S3 against MinIO, and the §38 open assumptions (`sync-to` reuse, ext4 on CI).
The first push to GitHub exercises most of these.

## Scope

This plan covers the §41 MVP. Phase 2 (§42) items are mentioned only where v1 must leave room for
them. Nothing here is built yet: the repository holds `.gitignore` and `LICENSE`.

Environment at the time of writing (macOS 26.5.1): Rust 1.97.1; Kopia **not installed** (Homebrew
has 0.23.1); `age` present, `age-plugin-yubikey` absent, no YubiKey attached; no MinIO.

## Step 0 — Prerequisites

1. `brew install kopia` (0.23.1). Pin `KOPIA_MIN = "0.23.0"` and `KOPIA_MAX_MINOR = 23` in one
   constant in `src/backup/kopia.rs`.
2. Capture JSON fixtures from the pinned Kopia into `tests/fixtures/kopia/0.23.1/`:
   `snapshot create --json` (clean, with ignored errors, with fatal errors), `snapshot list --json`,
   `repository status --json` (scrubbed by hand before committing), `maintenance info --json`.
3. Start `docs/assumptions.md` with the six open items from §38 and fill each in as it is tested.
4. Dependencies are listed in spec §3 with verified versions. Do not add others without a reason
   recorded in `ARCHITECTURE.md`.

## Step 1 — Skeleton, CLI, config, output

**Files:** `Cargo.toml`, `src/main.rs`, `src/cli/{mod,args}.rs`, `src/config/{mod,model,paths}.rs`,
`src/output/{mod,human,json}.rs`, `src/error.rs`, `src/security/secret.rs`,
`src/platform/{mod,macos,linux,windows}.rs`.

- `Cargo.toml`: edition 2024, `rust-version = "1.89"`, name `moss` (final).
- clap derive with every §44 global flag; `-v` counts; no `--password` flag exists anywhere.
- `ExitCode` enum for codes 0–13 (§23) and `MossError` → `ExitCode` mapping in one place. Kopia's
  exit code is never propagated.
- Config model matching §24; resolution order `--config`, `MOSS_CONFIG`, platform default from
  `directories::ProjectDirs::from("", "", "moss")`. State dir is `state_dir()` on Linux and
  `data_local_dir()` elsewhere; strip the Windows `\config`/`\data`/`\cache` suffixes consistently.
- `Report` trait implemented per command for human and JSON (`schema_version: 1`); TTY, `NO_COLOR`
  and `--quiet` handled once in `output`.
- `Secret` newtype over `zeroize::Zeroizing<String>` whose `Debug` and `Display` print `[redacted]`.

**Verify:** `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test`;
`assert_cmd` tests for `--help`, exit 2 on bad usage, config round-trip, `insta` snapshot of an
empty JSON report.

## Step 2 — Kopia adapter

**Files:** `src/backup/kopia.rs`, `src/backup/repository.rs`, `src/backup/json.rs`.

- `KopiaRunner`: finds the binary with `which`, probes `--version` once (`OnceLock`), enforces the
  version range unless `--skip-version-check` (exit 11 / 12).
- One function builds every command line and child environment per §5 "Kopia process hygiene":
  explicit env allowlist, `KOPIA_PASSWORD` from `Secret`, `AWS_*` passed through on create/connect
  only, `--config-file`, `--disable-file-logging` or `--log-dir`, and on create/connect
  `--no-persist-credentials --no-check-for-updates --cache-directory`.
- After create/connect: assert `<state>/kopia` is 0700 and `repository.config` is 0600, tightening
  them if Kopia did not (§5, assumption 6). Kopia keeps the S3 keys in that file by decision; moss
  never copies them elsewhere and `doctor` re-checks the modes.
- Typed operations: `repository create|connect` (filesystem, s3), `repository status`,
  `snapshot create --json --tags`, `snapshot list --all --json --tags`, `snapshot restore`,
  `snapshot verify`, `policy set --ignore-file-errors=true --ignore-dir-errors=true`,
  `maintenance info --json`.
- JSON structs: `#[serde(default)]` everywhere, never `deny_unknown_fields`. `numFailed` absent is
  an error; `numIgnoredErrors` absent is zero (§18).
- Error translation from Kopia stderr into `RepositoryUnreachable` (3), `AuthFailed` (4),
  `NotInitialised` (3), each with a §37-style message; raw Kopia text only under `--verbose`, and
  never for `repository status`.

**Verify:** unit tests over the fixtures; integration tests in `tests/kopia_*.rs` (skipped unless
`kopia` is on `PATH`) that create a temporary filesystem repository, snapshot a temporary tree,
list it, and restore it.

## Step 3 — Credentials and recovery

**Files:** `src/credentials/{mod,store,keyring_store,env_store}.rs`, `src/security/recovery.rs`.

- `CredentialStore` trait with `get/set/delete` for the repository password, namespaced by
  repository id. `KeyringStore` on `keyring` 4 (features per spec §3); `EnvStore` reads
  `MOSS_REPOSITORY_PASSWORD`. The env store takes precedence when the variable is set.
- Password generation: 32 bytes via `getrandom::fill` → `bip39::Mnemonic::from_entropy` → the
  canonical 24-word sentence is both the Kopia password and the recovery code (§6). Entry parses
  with `Mnemonic::parse_in_normalized` and reports the first word not in the list.
- Recovery gate: `repository.recovery_acknowledged_at` in config; `backup` exits 13 until set;
  `init --non-interactive` requires `--recovery-acknowledged`.
- `moss recovery show` re-reads the store and reprints the sheet with moss and Kopia versions.

**Verify:** mnemonic round-trip; a swapped or misspelled word is rejected with the word position
named; mixed case and spacing normalise to the same password; a `MockStore` used by all later
tests; `insta` snapshot of the sheet.

## Step 4 — Profile model and discovery

**Files:** `src/profile/{mod,model,discovery,rules,patterns,sensitive,tools}.rs`,
`src/profile/{macos,linux,windows}.rs`.

- Types from §9 verbatim; semantic ids from §15 plus `custom:<home-relative path>`.
- `PlatformAdapter` trait: `home()`, `known_dirs()`, `default_sources()`, `own_state_dirs()`.
  `cfg(target_os)` appears only in `src/platform/` and these three files.
  - macOS: the eight template directories; `video` → `~/Movies`; `~/Library` allowlist of
    `Application Support` and `Preferences`; `Containers`, `Group Containers`, `Caches` off by default.
  - Linux: in-tree XDG parser for `user-dirs.dirs` then `/etc/xdg/user-dirs.defaults` then English
    (§8). `video` → `XDG_VIDEOS_DIR`.
  - Windows: `known-folders` per FOLDERID, each individually fallible.
- Every candidate path is checked to exist before it becomes a source; absent ones are dropped
  with a `tracing::debug`.
- Sensitive classification table (path, filename, extension only, §14).
- Exclusions: one `ignore::gitignore::Gitignore` built from §10 directory patterns, known cache
  paths, tool-reported cache paths (time-boxed queries, cached in the index), and user `exclude`
  entries; user `include` entries override.
- `init` writes the source list into `config.yaml` (§8 "Discovery output").

**Verify:** the largest test module. Fixture trees under `tests/fixtures/profiles/{macos,linux,windows}`
built with `tempfile`; localized XDG names (`~/Vidéos`); disabled XDG entries; sensitive
classification; include/exclude precedence; every default path in the adapter tables exists on the
CI runner for that OS or is marked unvalidated.

## Step 5 — Scanner, scan index, `inspect`

**Files:** `src/scan/{mod,walker,index,collisions,progress}.rs`, `src/cli/inspect.rs`.

- `ignore::WalkBuilder` with `standard_filters(false)`, `follow_links(false)`, overrides from
  Step 4, `build_parallel` across top-level sources bounded by `available_parallelism`.
- Per-entry io errors classified by `raw_os_error`: `EPERM` (TCC/SIP), `EACCES` (mode/ACL), other.
  Recorded as `Skipped { path, reason, errno }` and never abort the walk.
- Collision detection per directory: case-fold duplicates, NFC/NFD duplicates, Windows-illegal
  names (§12 list, reserved device names with any extension, trailing dot or space), paths over
  260 characters.
- Scan index at `<state>/index.json`: per-directory size, count, mtime, classification, refresh
  timestamp. Re-walk only subtrees whose mtime changed; `--rescan` forces a full walk.
- Progress via `indicatif` at a fixed refresh rate; plain periodic lines when not a TTY.
- Guardrails from `limits:`; warn interactively, fail under `--non-interactive`.
- `inspect` output per §13, with the mandatory Skipped block and index age.

**Verify:** fixtures for each §38 failure mode (case pair, NFC/NFD pair, `aux.txt`, `trailing.`,
`trailing `, long path, symlink escapes, sparse file). EPERM classification is unit-tested on a
synthetic `io::Error`; real TCC is exercised only in the manual walk.

## Step 6 — `doctor`

**Files:** `src/cli/doctor.rs`, `src/platform/macos/tcc.rs`.

Checks: Kopia found and version in range; repository reachable if configured; credential store
writable (sentinel entry) and readable without a prompt; recovery acknowledged; Full Disk Access on
macOS by attempting `opendir` on `~/Library/Mail` and reading errno; YubiKey placeholder; scan index
age. Non-zero exit if any check fails; `--json`.

## Step 7 — `backup`

**Files:** `src/cli/backup.rs`, `src/backup/{run,manifest}.rs`, `src/lock.rs`.

- Lock at `<state>/lock` using std `File::try_lock`, with PID and start time written inside;
  liveness via `kill(pid, 0)` on Unix and `OpenProcess` on Windows; exit 10 naming the holder.
- Flow: lock → recovery gate → scan → sensitive-data gate (exit 6 under `--non-interactive` unless
  `allow_sensitive`) → guardrails → write `<state>/manifests/<run>.json` (§27) → `policy set` per
  source → one `snapshot create --json --tags …` over all sources plus the manifest directory →
  read per-snapshot `numFailed` / `numIgnoredErrors` → exit 0 or 9.
- Tags exactly as §19. `--dry-run` prints the §29 report and stops before Kopia.

**Verify:** integration test on a fixture tree and temporary repository asserting tags, manifest
contents, and exit 9 when a subtree is made unreadable.

## Step 8 — `snapshots`, `status`, `verify`

- `snapshots`: `snapshot list --all --json`, grouped by `moss:run`; STATUS from member error counts
  and the manifest's `skipped` length; `--host`, `--latest`, `--json`.
- `status`: repository summary, maintenance owner from `maintenance info --json`, last run per host.
- `verify`: `snapshot verify` over the run's members, plus mode checks on credential paths after
  a restore (§12: `~/.ssh/*` not group- or world-readable, `~/.ssh/config` not writable by others).
- `prune`: wraps `kopia snapshot expire --all` (with `--delete` only when moss's `--yes` or a TTY
  confirmation is given). `maintenance`: wraps `kopia maintenance run` (`--full` passthrough) and
  prints the owner from `maintenance info --json`; refuses `--safety=none` (§30).

## Step 9 — `restore`

**Files:** `src/restore/{mod,select,stage,place,conflict,journal,translate,report}.rs`,
`src/restore/contain/{mod,unix,macos,linux,windows}.rs`.

- Selection: `latest`, run-id prefix, `--from-host`, `--category`, `--source`.
- Fetch and validate the manifest first; treat every path in it as untrusted.
- Two-stage per §16: `snapshot restore` into `<state>/staging/<run>/<source>` with
  `--write-sparse-files`, then placement through the containment layer.
- Containment: Linux `rustix::fs::openat2` with `ResolveFlags::IN_ROOT`, falling back on `ENOSYS`
  to a component-wise `O_NOFOLLOW | O_DIRECTORY` walk; macOS `openat` with a locally defined
  `O_RESOLVE_BENEATH = 0x1000`; Windows component-wise traversal checking reparse points and
  comparing volume serial plus file index from `winapi-util`. The validated descriptor or handle is
  the thing written to; no path string is re-resolved.
- Semantic mapping through the destination `PlatformAdapter`; `user_home` and `custom:*` map to the
  current user's home; `video` maps to `~/Movies` or `~/Videos`; category/destination sanity check.
- Conflict policy `skip | overwrite | backup | interactive`; diff only for text.
- Journal at `<state>/restore-journal.json`, entry written and fsynced before each file; incomplete
  journal on start offers resume or rollback.
- Collisions recorded in the manifest fail with exit 5 on a case- or normalization-insensitive
  destination (probe by creating `a` and `A` in staging) unless `--rename-collisions`.
- Windows symlinks attempted and recorded as skipped on `ERROR_PRIVILEGE_NOT_HELD`.
- Post-restore report of embedded absolute paths (§15) from read-only scanners for `~/.ssh/config`,
  `~/.gitconfig`, `~/.kube/config`, `~/.aws/config`, shell rc files, `~/.docker/config.json`.

**Verify:** containment tests with `../`, absolute, and chained symlink escapes on the host OS;
conflict policy tests; journal resume test; translation tests; integration test restoring a
temporary-repository snapshot into a temporary home.

## Step 10 — Remaining v1 commands, docs, CI

- `include`, `exclude`, `config show|path`, `recovery show`, `kopia` escape hatch (which sets the
  same env and `--config-file` so the user's Kopia sees moss's repository), `init
  list-backup-endpoints` with a static cited table (Wasabi, Cloudflare R2, Backblaze B2, MinIO,
  DigitalOcean Spaces, Scaleway, Hetzner, Linode, Storj, Vultr). Reserved Phase 2 names print
  "not available in this version".
- S3 init flow: parse `s3://bucket/prefix`, `--endpoint`, `--region`; keys via prompt or `AWS_*`
  passed to Kopia once at connect and persisted by it (§5); if a repository already exists at the
  location, take the §6 bootstrap path.
- Docs: `README.md`, `ARCHITECTURE.md`, `SECURITY.md` (all §45 limitations), `CONTRIBUTING.md`,
  `CHANGELOG.md`, `docs/exit-codes.md`, `docs/json-schema.md`, `docs/assumptions.md`,
  `docs/kopia-compat.md`.
- CI: the cross-platform restore job, the Kopia JSON diff job against
  `tests/fixtures/kopia/<version>/`, and the opt-in MinIO job are defined in Step 12's `ci.yml`.

## Step 11 — Phase 2 hooks kept in v1

`HardwareKeyProvider` trait and `MockProvider` under `src/yubikey/`; `yubikey` subcommands present
but reporting "not configured". The `moss/envelope.age` location next to the repository (§36) is
reserved so YubiKey support needs no migration.

## Step 12 — Release automation and Homebrew tap

Mirror the workflows in `planesailingio/twig` (`.github/workflows/ci.yml`, `release.yml`) and its
`scripts/update-tap.sh`, adapted for moss. The tap is **`planesailingio/homebrew-tools`**; the name
`homebrew-tap` does not exist on GitHub and twig's script already targets `homebrew-tools`.

**Files:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `scripts/update-tap.sh`,
`scripts/install-kopia.sh`, and in the tap `Formula/moss.rb`.

### `ci.yml` (push to `main`, pull requests)

- `lint-test` matrix on `ubuntu-latest`, `macos-latest`, `windows-latest`: `dtolnay/rust-toolchain@stable`
  with `rustfmt, clippy`, `Swatinem/rust-cache@v2`, then `cargo fmt --all --check`,
  `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`.
- `scripts/install-kopia.sh` runs before tests on every OS and installs the **pinned** Kopia
  (0.23.1) from its GitHub release assets, verifying the published checksum, so the integration
  tests and JSON-fixture diff (Step 10) run in CI rather than being skipped. Do not `brew install
  kopia` in CI: it floats to the newest version and would defeat the pin.
- `msrv` job on `1.89.0` (the `rust-version` in `Cargo.toml`), `cargo check --all-features`.
- `cross-platform-restore` job from Step 10 lives here: macOS backs up a fixture tree to a
  filesystem repository uploaded as an artifact; Ubuntu and Windows download it and restore.
- `s3` job, opt-in via `workflow_dispatch` or a label, runs MinIO as a service container on Ubuntu
  for the S3 and, later, `sync-to` tests.

### `release.yml` (tags `v*`)

- `build` matrix identical to twig's five targets (`x86_64-apple-darwin`, `aarch64-apple-darwin`,
  `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` with the `gcc-aarch64-linux-gnu` linker,
  `x86_64-pc-windows-msvc`). Archives are named `moss_<version>_<target>.tar.gz` (`.zip` on
  Windows) containing `bin/moss`, `README.md`, `LICENSE`, plus a `.sha256` sidecar — the same layout
  twig uses, so the tap generator is a near-copy.
- `release` job publishes the archives and sidecars with `softprops/action-gh-release@v2`.
  Tags containing `-` (for example `v0.1.0-rc1`) are marked as prereleases.
- `tap` job, `needs: release`, skipped for prereleases: runs `MOSS_TAP_CONFIRM=1
  scripts/update-tap.sh <version>`, which fetches the four Unix sidecars from the published
  release, renders `Formula/moss.rb`, clones `homebrew-tools` and pushes. It authenticates with a
  short-lived installation token for the org's tap GitHub App, minted by
  `actions/create-github-app-token` from the org variable `TAP_APP_ID` and secret
  `TAP_APP_PRIVATE_KEY` (see `docs/releasing.md`). The default `GITHUB_TOKEN` cannot push to another
  repository. Twig's script keeps the interactive confirmation for local use; the workflow sets the
  confirm variable.

### `Formula/moss.rb`

- Generated, marked "do not edit", placed under `Formula/` (Homebrew's preferred layout; the tap
  currently mixes root-level and `Formula/` files, and `gannet.rb` already uses `Formula/`).
- `depends_on "kopia"` — Kopia is in homebrew-core on both macOS and Linux, so `brew install
  planesailingio/tools/moss` pulls it in. The formula's `test do` block runs `moss --version` and
  `moss doctor --json` and asserts the Kopia check passes, which proves the dependency is wired.
  Note the tension with the CI pin: Homebrew installs whatever Kopia is current, so `doctor`'s
  version-range warning (§5) is what protects users when homebrew-core moves ahead of the tested
  range. Widen `KOPIA_MAX` in the same release that bumps the pin.
- Binary-only formula, per-target `url`/`sha256` blocks exactly as twig's; `license "MIT"`;
  `homepage "https://github.com/planesailingio/moss"`.
- Shell completions (Phase 2, §42) are added to `install` when they exist, following `gannet.rb`.

### Order and verification

1. Land `ci.yml` in Milestone 1 so every later step runs under it; the Kopia installer script is
   needed by Step 2's integration tests.
2. Land `release.yml` and `scripts/update-tap.sh` in Milestone 4, but with the `tap` job's push
   disabled (`if: false`) until the first real tag.
3. Dry run: push a `v0.0.1-rc1` tag, confirm five archives and sidecars appear on a prerelease and
   the tap job is skipped. Run `scripts/update-tap.sh 0.0.1-rc1` locally without confirming and
   inspect the rendered formula; `brew install --formula ./Formula/moss.rb` then `brew test moss`
   on this machine.
4. Enable the `tap` job, tag `v0.1.0`, and verify `brew install planesailingio/tools/moss` on a
   clean machine installs Kopia as a dependency and `moss doctor` reports it found.

## Milestones

| Milestone | Steps | Exit criterion |
|---|---|---|
| 1 | 0, 1, 2 | `moss --help`; temporary-repository integration test green |
| 2 | 3, 4, 5, 6 | `init` on a local repository, `doctor`, `inspect` with real numbers on the dev machine |
| 3 | 7, 8 | `backup` then `snapshots` end to end, exit 9 on an unreadable subtree |
| 4 | 9, 10 | `restore` into a scratch home; docs; CI cross-platform job green |
| 5 | 12 | tagged prerelease builds five archives; `v0.1.0` updates `homebrew-tools` and installs with Kopia |

Every milestone ends with `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`
and `cargo test` clean.

## Release verification

- The §39 walk by hand on this machine against a local filesystem repository, then against MinIO
  in Docker, then the CI cross-platform job as the gate.
- Security review of `src/restore/contain`, `src/credentials`, `src/backup/kopia.rs` before the
  first tag.
- Leak test: run every command with `--verbose` and `MOSS_LOG=trace` against a repository whose
  password and S3 keys are known sentinels; assert the password never appears anywhere on disk or
  in output, and that the S3 keys appear **only** in `repository.config` (mode 0600) and nowhere
  else: not stdout, stderr, moss logs, Kopia logs, or `config.yaml`.
