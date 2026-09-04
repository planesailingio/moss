# Security

moss backs up the most sensitive directory a user has and restores it with the user's full
privileges. This document states who it defends against, what it does about each threat, and
where it falls short. Section references (§n) are to [spec.md](spec.md).

## Threat model

### In scope

| Threat | Why it matters | Controls |
|---|---|---|
| Malicious or tampered repository contents during restore | Restore writes attacker-influenceable data into `$HOME` with the user's privileges. The highest-severity threat. | Two-stage restore; per-OS containment primitives; symlinks never followed; manifest validated and its paths treated as untrusted; restored files never executed; credentials never imported into agents. |
| Compromised or hostile object storage | A bucket may be read or modified by a third party. | Kopia's repository encryption for file data; the manifest is stored inside the repository so it inherits encryption and integrity; moss stores no plaintext metadata in the bucket. |
| Stolen or lost device, powered off | The laptop should not yield the repository. | Password lives only in the OS credential store; Kopia's own base64 sidecar is never written (`--no-persist-credentials`, `--no-use-keychain`). |
| A local process running as the same user | Partial defence only. | No secrets in arguments, files, logs or `--verbose`; the environment leak on Linux is documented below, not papered over. |
| Accidental disclosure by the tool itself | The most likely real-world failure. | `Secret` type redacts by construction; explicit env allowlist for Kopia; Kopia file logging off by default; `repository status --json` never logged; recovery sheet never emitted as JSON. |
| Shoulder-surfing and screen sharing | Sensitive values must not appear merely because a command was verbose. | `--verbose` adds Kopia's stderr only; `inspect` reports counts and paths, never contents. |

### Explicitly out of scope

- A compromised machine at backup time. If the host is owned, the profile is already readable.
- A malicious Kopia binary. moss trusts the Kopia it finds on `PATH` (or `MOSS_KOPIA`).
- Coercion. No duress mechanisms, no plausible deniability.
- Traffic analysis against the object store. Access patterns leak approximate size and frequency.
- Multi-user hostile machines. moss assumes the user owns the account it runs as.

## The recovery code

`moss init` draws 32 bytes from the OS CSPRNG (`getrandom`) and renders them as a 24-word BIP39
English mnemonic. The canonical sentence, lowercase words separated by single spaces, is the Kopia
repository password. There is no second encoding and no derivation: **the recovery code and the
password are the same string.**

Words were chosen over a bech32-style string because a recovery sheet is transcribed by hand and
read back over the phone. BIP39's 8-bit checksum is weaker than a proper error-detecting code;
that is accepted, and moss compensates by validating each word against the list and reporting
*which* word failed, with suggestions, before checking the checksum. Input is accepted in any
case or spacing, with or without the sheet's numbering.

The first backup refuses to run until the sheet has been acknowledged (`init` prompts, or
`--recovery-acknowledged` under `--non-interactive`). Without the code and without this machine's
credential store, the repository cannot be recovered. There is no reset and no vendor.

## Credential storage

| OS | Store | Entry |
|---|---|---|
| macOS | Keychain | service `moss`, account `<repository id>/repository-password` |
| Linux | Secret Service (libsecret) | as above |
| Windows | Credential Manager | as above |

The store holds the repository password only. `doctor` and `init` probe it by writing and
deleting a sentinel entry, because the `keyring` crate reports a missing Secret Service as a
generic failure.

`--credential-store=env` opts out of the store entirely: moss persists nothing and the user
supplies `MOSS_REPOSITORY_PASSWORD` on every run. On every platform, `MOSS_REPOSITORY_PASSWORD`
set in the environment takes precedence over the store; this is the documented fallback for
schedulers that cannot unlock a keychain. A file holding it must be mode 0600 and the user must
understand it is weaker than the credential store.

## What is never logged or printed

- The repository password or recovery code, in any form, in any output, log, diagnostic, temp
  file or crash dump. It is a `Secret` whose `Debug` and `Display` print `[redacted]`.
- S3 access keys, secret keys and session tokens. They are passed to Kopia in the child
  environment at `init` only; the argument logger redacts key flags defensively even though moss
  never uses them.
- The output of `kopia repository status --json`. It leaked storage credentials unscrubbed
  before Kopia 0.16 (GHSA-j5vm-7qcc-2wwg) and still prints the S3 access key id. moss parses it
  and discards it.
- File contents. Sensitive classification is by path, filename and extension only.
- `moss recovery show --json` is refused; the sheet is plain text only, so it never lands in a
  JSON log by accident.

Kopia's own file logging is on by default at debug level and records every source path and
per-file error path. moss passes `--disable-file-logging` normally and `--log-dir=<state>/kopia-logs`
(0700) only under `--verbose`. Kopia's upload of its logs into the (encrypted) repository is left
enabled.

## Caveats, stated plainly

### 1. The repository password transits the child process environment

Kopia has no `--password-stdin`, no password file and no external key hook; its interactive
prompt is a raw terminal read. `KOPIA_PASSWORD` in the child environment is the only
non-interactive mechanism. moss sets it on the child only, never in its own environment, and drops
the `Command` immediately after the child exits.

**On Linux, environment variables are readable by other processes running as the same user** via
`/proc/<pid>/environ` and `ps e`, for as long as the Kopia process lives. This cannot be
engineered away while Kopia is the engine. The environment is better than argv, which is
world-readable, but it is not private. On macOS and Windows the equivalent interfaces require
elevated privileges.

### 2. S3 keys are stored in plaintext on disk

Kopia binds `--access-key`, `--secret-access-key` and `--session-token` to `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, and writes whatever value it ends up with into
its repository config at create or connect time. `--no-persist-credentials` covers the repository
password only.

Decision: let Kopia persist them, and own the file that holds them. `moss init` passes the keys
in the child environment once; Kopia writes them into `<state>/kopia/<repository id>.config`
(the file Kopia would otherwise call `repository.config`); moss creates the directory 0700 and
re-tightens the file to 0600; `doctor` checks the mode on every run. The keys are never copied
into `config.yaml`, the credential store or anywhere else. This is the same posture as
`~/.aws/credentials`, protected by file permissions and disk encryption only.

To rotate: issue new keys at the provider, revoke the old ones, then run
`moss init --repository <same location>` with the new keys in `AWS_*` (or at the prompt). Kopia
reconnects and overwrites the stored keys. If no keys are supplied, Kopia's IAM or instance-role
chain applies.

### 3. Filesystem metadata that does not survive

Verified against the Kopia source (§12): extended attributes, POSIX ACLs, Windows security
descriptors, Linux capabilities and SELinux labels are not implemented; hardlinks are broken into
separate files; setuid, setgid and sticky bits are dropped on restore (Kopia applies permission
bits only); sockets, FIFOs and device nodes are not backed up; macOS resource forks, Finder flags
and quarantine flags are xattrs and are lost. `~/Public/Drop Box` depends on an inherited ACL and
will exist with the wrong semantics after a restore.

Mode bits *are* preserved exactly, which matters: OpenSSH hard-fails on a private key at 0644.
`moss verify --check-modes` checks `~/.ssh/*`, `~/.aws/credentials`, `~/.kube/config` and
`~/.docker/config.json` after a restore.

### 4. Case and normalisation collisions

`Makefile` and `makefile` restored to APFS or NTFS produce one file, last writer wins, with no
error at any layer. `café.txt` in NFC and NFD forms are two files on ext4 and one on APFS. moss
detects both at backup time, where both members are visible, records them in the manifest, and at
restore probes the destination and fails with exit 5 unless `--rename-collisions` is given. It
never lets the filesystem resolve a collision silently. Windows-illegal names (reserved device
names with any extension, trailing dots or spaces, illegal characters) and paths over 260
characters are recorded the same way.

### 5. macOS Full Disk Access

TCC denies a CLI access to `~/Library/Mail`, Safari, Messages and other paths silently, with
`EPERM`. Grants attach to the responsible process by bundle id, so granting access to the `moss`
binary does nothing; grant it to the terminal application. A launchd job does not inherit the
terminal's grant, so a scheduled backup may capture less than an interactive one. moss
distinguishes `EPERM` (TCC) from `EACCES` (permissions), records every denied path with its
reason, reports it in `inspect`, `backup` and the manifest, and exits 9. A partial snapshot is
never presented as complete.

## Restore safety

Restore is two-stage. Kopia's `snapshot restore` knows nothing about containment, conflicts or
journals, so it is never allowed to write into the profile: it restores into
`<state>/staging/<run>/<source>` (with `--write-sparse-files` and `--write-files-atomically`), and
moss walks the staged tree and places each entry.

Placement validates and opens in one operation, then acts on the descriptor or handle. It never
re-derives a path from a string after validation, which closes the TOCTOU window where an attacker
who controls a directory in the chain swaps a component. `O_NOFOLLOW` alone is not containment; it
guards only the final path component.

| Platform | Primitive |
|---|---|
| Linux | `openat2(2)` with `RESOLVE_IN_ROOT` (kernel 5.6+, via `rustix`); absolute symlinks are reinterpreted against the root. On `ENOSYS` the fallback is a component-wise `O_NOFOLLOW \| O_DIRECTORY` walk. |
| macOS | `openat` with `O_RESOLVE_BENEATH` (`0x1000`), **defined locally** under `cfg(target_os = "macos")`. The `libc` crate defines a FreeBSD constant of the same name with a different value; `libc::O_RESOLVE_BENEATH` is never used. Verified on macOS 26.6 against `..` escapes, absolute paths, symlinks to `/etc` and chains climbing out via `../..`. |
| Windows | No per-open containment exists. Component-by-component traversal with `FILE_FLAG_OPEN_REPARSE_POINT` (and `FILE_FLAG_BACKUP_SEMANTICS` for directories), checking the reparse tag, and verifying containment by comparing volume serial and file index from `GetFileInformationByHandle`, never by string prefix. Own writes use `\\?\`-prefixed canonical paths. |

Other rules:

- Symlinks in staging are recreated as symlinks; nothing is followed. Where symlink creation is
  unavailable (Windows without Developer Mode), the link is recorded as skipped rather than
  materialised as a copy.
- The manifest is fetched and validated first (`schema_version`, run id, sources); every path it
  supplies still goes through containment.
- A source's category must match its destination: a `credentials` source cannot land outside the
  expected directory.
- Restoring outside the profile root (`--to <dir>`) is an explicit choice.
- Existing files are never silently overwritten. The default policy is interactive on a terminal
  and `skip` otherwise; `backup` keeps the existing file.
- The journal entry for each write is fsynced before the file is written; an interrupted restore
  is detected on the next run and can be resumed or rolled back.

What restore never does: execute a restored file; import restored keys into `ssh-agent` or
`gpg-agent`; rewrite file contents (embedded absolute paths are reported, not changed).

## Process hygiene summary

Every Kopia invocation: `env_clear()` plus an allowlist; `KOPIA_CHECK_FOR_UPDATES=false`;
`--config-file` under moss's state directory; `--no-persist-credentials`; `--no-use-keychain`;
`--disable-file-logging` unless `--verbose`; `--cache-directory` and `--no-check-for-updates` on
create/connect. moss itself has no telemetry, no update check and no account. The S3 endpoint
table is static and in-tree.

## Reporting a vulnerability

Email **rhys@rhysevans.co.uk**. Include the moss and Kopia versions, the OS, and steps to
reproduce. Please do not open a public issue for anything that could expose a user's repository
or credentials before a fix is available.

There is no bug bounty.
