# Kopia compatibility

moss is coupled to another project's CLI contract, and Kopia's `--json` is `json.Marshal` over
internal Go structs with no stability promise (spec §5). This file records the pin, the procedure
for moving it, and every Kopia flag moss depends on, so a bump is a checklist rather than a hunt.

## The pin

| Constant (`src/backup/kopia.rs`) | Value | Meaning |
|---|---|---|
| `KOPIA_MIN` | `(0, 23, 0)` | lowest tested version |
| `KOPIA_MAX_MINOR` | `(0, 23)` | highest tested minor; any patch of it is accepted |

Displayed as `0.23.0 – 0.23.x`. The version is probed once per process with `kopia --version`
(cached in a `OnceLock`). Any command that touches the repository fails with exit 12 outside the
range unless `--skip-version-check`; a missing binary is exit 11. `MOSS_KOPIA=<path>` overrides
the `PATH` lookup.

Fixtures captured from the pinned version live in `tests/fixtures/kopia/0.23.1/`:
`snapshot-create-clean.json`, `snapshot-create-ignored-errors.json`,
`snapshot-create-fatal.json`, `snapshot-list.json`, `repository-status.json` (scrubbed),
`maintenance-info.json`. The unit tests in `src/backup/json.rs` parse them.

Homebrew installs whatever Kopia is current, so `moss doctor`'s range check is what protects users
when homebrew-core moves ahead of the tested range. CI installs the pinned version from Kopia's
release assets (`scripts/install-kopia.sh`) so the pin holds there.

## Bumping the pin

1. Install the candidate version locally.
2. Run `scripts/capture-kopia-fixtures.sh <version>` to capture the six fixtures into
   `tests/fixtures/kopia/<version>/`. Scrub paths, hostname and username; confirm
   `repository-status.json` carries no credentials.
3. `diff -ru tests/fixtures/kopia/<old> tests/fixtures/kopia/<new>` and read every change.
   Renamed or removed fields matter only if `src/backup/json.rs` reads them; use the table below.
4. Review `json.rs` and its tests. Keep `#[serde(default)]`; never add `deny_unknown_fields`.
   Re-check the behaviours in [assumptions.md](assumptions.md) (tag splitting, `--clear-ignore`
   ordering, ignore-rule syntax, absence of `stats` on create, exit 1 with manifest).
5. Check the flag table below against `kopia <cmd> --help` for the new version.
6. Widen `KOPIA_MAX_MINOR` (and raise `KOPIA_MIN` if the old version is dropped). Update the
   fixture path in `json.rs` tests and `repository.rs` tests.
7. Run the three CI commands with the new Kopia on `PATH`.
8. Record the version, the date, and a summary of the JSON diff in the history below and in
   `CHANGELOG.md`. Release the widened range in the same release that updates the Homebrew formula.

## JSON fields moss reads

| Command | Field | Use | Absent means |
|---|---|---|---|
| `snapshot create --json` | `id` | snapshot id in manifest and reports | error (no manifest) |
| | `rootEntry.summ.numFailed` | fatal error count | **error** (exit 8) |
| | `rootEntry.summ.numIgnoredErrors` | ignored error count | zero (`omitempty`) |
| | `rootEntry.summ.errors[]` `{path, error}` | folded into `skipped` (Kopia caps at 10) | none |
| | `rootEntry.summ.size`, `.files` | sizes in reports (whole tree) | fall back to `stats` |
| `snapshot list --all --json` | `id`, `source{host,userName,path}`, `startTime`, `endTime`, `tags` (`tag:<key>`), `incomplete`, `stats{totalSize,fileCount,errorCount,ignoredErrorCount}`, `rootEntry.summ` | grouping into runs, STATUS column | as above |
| `repository status --json` | `uniqueIDHex`, `configFile`, `clientOptions{hostname,username}` | `status`; never logged | empty string |
| `maintenance info --json` | `owner`, `schedule{nextFullMaintenance,nextQuickMaintenance}`, `quick.enabled`, `full.enabled` | `status`, `maintenance` owner check | empty / `null` |

## Every Kopia flag moss uses

Global flags on every invocation (`KopiaContext::command`):

| Flag | Purpose |
|---|---|
| `--config-file=<state>/kopia/<repository id>.config` | moss owns Kopia's config; never collides with the user's own Kopia |
| `--no-persist-credentials` | never write the base64 password sidecar |
| `--no-use-keychain` | never touch the OS keychain from Kopia; moss owns credential storage |
| `--no-progress` | no progress output on stderr |
| `--disable-file-logging` | default: Kopia's debug-level file log records every path |
| `--log-dir=<state>/kopia-logs` | instead of the above, under `--verbose` only |

Environment on every invocation: allowlist (see ARCHITECTURE.md), `KOPIA_CHECK_FOR_UPDATES=false`,
`KOPIA_PASSWORD` for repository commands, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`
on create/connect only.

| Command | Flags and arguments | Where |
|---|---|---|
| `kopia --version` | | `kopia::version` |
| `kopia repository create` / `connect` | `filesystem --path=<p>` or `s3 --bucket=<b> [--prefix=<p>/] [--endpoint=<host>] [--disable-tls] [--region=<r>] [--disable-tls-verification] [--root-ca-pem-path=<p>]`; then `--override-hostname=<h> --override-username=<u> --description="moss profile repository"`; plus `--no-check-for-updates --cache-directory=<cache>/kopia` | `repository.rs::connect_or_create` |
| `kopia repository status --json` | | `repository.rs::status` |
| `kopia policy set <path> --clear-ignore` | first call, alone | `repository.rs::set_source_policy` |
| `kopia policy set <path> --ignore-file-errors=true --ignore-dir-errors=true --ignore-unknown-types=true --add-ignore=<rule>...` | second call | same |
| `kopia snapshot create --json --tags <k>:<v>... <path>` | one source per invocation; five tags | `repository.rs::snapshot_create` |
| `kopia snapshot list --all --json [--tags <k>:<v>...]` | | `repository.rs::snapshot_list` |
| `kopia snapshot restore --write-sparse-files --no-ignore-permission-errors --write-files-atomically [--skip-owners] <id> <staging dir>` | always into moss's staging directory, never the profile | `repository.rs::snapshot_restore` |
| `kopia snapshot verify --verify-files-percent=<n> <id>...` | | `repository.rs::snapshot_verify` |
| `kopia snapshot expire --all [--delete]` | | `repository.rs::snapshot_expire` (`moss prune`) |
| `kopia maintenance info --json` | | `repository.rs::maintenance_info` |
| `kopia maintenance run --safety=full [--full]` | `--safety=none` is never used | `repository.rs::maintenance_run` |
| `kopia <anything>` | user-supplied, with moss's global flags and environment | `repository.rs::passthrough` (`moss kopia`) |

`--override-hostname` and `--override-username` fix the snapshot source identity to what moss
reports (`MOSS_HOSTNAME` overrides the hostname for tests), so grouping and `--from-host` are
stable.

## Error strings moss recognises

`kopia::classify_failure` matches Kopia's stderr, lowercased, to typed errors. If a bump changes
these messages the fallback is a generic exit 1 with the raw text under `--verbose`, so re-check
them:

| Substring | Error | Exit |
|---|---|---|
| `invalid repository password`, `invalid password` | `AuthFailure` | 4 |
| `found existing data in storage location` | `RepositoryExists` | 3 |
| `repository not initialized`, `not a kopia repository`, `kopia.repository`, `no such file or directory`, `cannot access storage path` | `RepositoryNotInitialised` | 3 |
| `not connected to a repository`, `open repository`, `unable to open repository` | `RepositoryUnreachable` | 3 |
| `access denied`, `accessdenied`, `invalidaccesskeyid`, `signaturedoesnotmatch`, `403` | `AuthFailure` (S3 keys) | 4 |
| `connection refused`, `no such host`, `timeout`, `i/o timeout`, `network is unreachable`, `tls` | `RepositoryUnreachable` | 3 |

## History

| Date | Kopia | Change |
|---|---|---|
| 2026-09-04 | 0.23.1 | Initial fixtures captured. Verified: `--tags` colon splitting and duplicate-key rejection; `--clear-ignore` ordering; gitignore rules in policies; no `stats` on `snapshot create --json`; exit 1 with manifest on fatal errors; config file created 0600 on macOS. Pin set to 0.23.0 – 0.23.x. |
