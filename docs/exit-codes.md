# Exit codes

Defined in `src/error.rs` (`ExitCode`) and mapped from `MossError` in exactly one place. They are a
contract like the JSON schema: stable within a major version, additions only. Kopia's own exit code
is never propagated; it is 0 or 1 and carries almost no information (spec §18).

Do not parse human-readable error text. Under `--json`, errors are also emitted as an object with
`exit_code` and `exit_code_name` (see [json-schema.md](json-schema.md)).

| Code | Name | When it fires | What a scheduler should do |
|---|---|---|---|
| 0 | success | The command completed and, for `backup`, nothing was skipped. | Nothing. |
| 1 | general failure | Any failure without a more specific code: configuration errors, credential store errors, I/O errors, an untranslated Kopia error, a declined guardrail prompt, `doctor` with at least one failed check, `prune`/`maintenance` declined at the prompt. | Alert. Re-run with `--verbose` to see Kopia's stderr. |
| 2 | invalid CLI usage | clap rejected the arguments; a Phase 2 command (`upload`, `profiles`, `backup --local-only`) or `--profile` other than `default` was used; `--endpoint` given for a non-S3 repository; `recovery show --json`; `verify` or `restore` selector matched no run; `moss kopia` with no arguments. | Fix the invocation. Never retry unchanged. |
| 3 | repository unavailable | No repository configured (`moss init` not run); Kopia cannot reach the path or endpoint; nothing is initialised at the location; a repository already exists where `init` tried to create one; network, DNS, TLS or timeout errors. | Alert. Check mount, network, endpoint. Retry is reasonable for transient network failures. |
| 4 | authentication failure | The stored password does not open the repository, or the storage provider rejected the S3 keys (403, `InvalidAccessKeyId`, `SignatureDoesNotMatch`). | Alert; do not retry. Run `moss recovery show` or `moss init` with the recovery code; rotate S3 keys if needed. |
| 5 | restore conflict | `restore` hit an existing file with no applicable policy, or a recorded case or normalisation collision targets an insensitive filesystem and `--rename-collisions` was not given. | Re-run interactively, or with `--conflict <policy>` or `--rename-collisions`. |
| 6 | sensitive-data safety refusal | The scan found sensitive files and `safety.allow_sensitive` is `false`, or the user answered no to the sensitive-data prompt. | Do not retry unchanged. Review `moss inspect`, then set `safety.allow_sensitive: true` or exclude the paths. |
| 7 | YubiKey unavailable | `yubikey setup`/`remove` in v1 (not available); in Phase 2, a configured YubiKey is absent or refused. | Not applicable to scheduled runs in v1. |
| 8 | integrity/verification failure | `kopia snapshot verify` failed; `verify --check-modes` found unsafe modes on credential files; Kopia's `snapshot create` output had no `numFailed` count; the manifest snapshot did not complete; a manifest failed validation on restore (unreadable, newer schema, empty). | Alert; investigate before the next backup. Never treat as success. |
| 9 | partial success | `backup` completed and the run is recorded, but at least one path was skipped (TCC denial, permission error, vanished file, Kopia error) or a snapshot reported errors. The manifest lists every skipped path. | Alert, distinct from 1. `moss inspect --all` lists what was skipped; on macOS check Full Disk Access. The snapshot is valid but incomplete. |
| 10 | already running | Another moss process holds `<state>/lock`. The message names the PID, start time and lock path. A stale lock from a dead process is reclaimed automatically. | Retry at the next scheduled slot; do not queue or kill the holder. |
| 11 | Kopia not found | No `kopia` on `PATH` (or `MOSS_KOPIA` points at a missing file). | Alert. Install Kopia; check the scheduler's `PATH`, which is often narrower than a login shell's. |
| 12 | Kopia version incompatible | `kopia --version` is outside the tested range (0.23.0 to 0.23.x). | Alert. Install a tested version, or pass `--skip-version-check` knowingly. |
| 13 | interaction required | A prompt was needed under `--non-interactive` or without a terminal: recovery sheet not acknowledged (`init` without `--recovery-acknowledged`, or `backup` before acknowledgement); guardrail exceeded without `--yes`; sensitive-data confirmation with no terminal and no `--yes`; second-machine `init` needing the recovery code; any confirmation prompt. | Fix interactively once; then the scheduled run proceeds. |

## Notes for automation

- Always pass `--non-interactive` to scheduled runs. Without it, a run with no terminal can still
  end in 13 rather than hanging, but a run *with* a terminal (an interactive shell in CI) may
  block on a prompt.
- Under `--non-interactive`, the sensitive-data prompt is skipped when `safety.allow_sensitive` is
  `true` (the default): the configuration is the standing consent. Set it to `false` to get 6
  instead.
- `backup --yes` answers the guardrail and sensitive-data prompts; it does not acknowledge the
  recovery sheet.
- `doctor` exits 1 if any check fails and 0 otherwise; warnings (stale index, no repository
  configured) do not affect the code. Use `doctor --json` and inspect `ok` and `checks[].status`.
- `--help` and `--version` exit 0; clap usage errors exit 2.
