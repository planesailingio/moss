# Profile Backup - LLM Implementation Specification

Section numbers (§n) are referenced throughout. When adding or removing a section, renumber every
reference; `grep -o '§[0-9]*' spec.md | sort -u` against the heading list is the check. Revision 3
(2026-09-03) corrected eleven stale references left by an earlier renumbering.

# 1. Project intent

Build a Rust CLI called `moss` (the name is final: it fixes the binary, crate, Homebrew formula, config directory, keychain namespace and recovery-code prefix) that provides an **OS-agnostic user-profile backup and restore experience** on macOS, Linux, and Windows.

The project is **not a backup engine**. Backup storage, chunking, deduplication, encryption at rest, snapshots, retention, repository maintenance, and S3/local storage are delegated to **Kopia**.

The product's value is the layer above Kopia:

- discover a user's profile correctly on each OS
- understand useful configuration, credentials, development state, and application state
- provide sensible cross-platform include/exclude rules
- expose what will be backed up before doing it
- preserve portable profile semantics rather than treating the profile as an arbitrary directory
- restore intelligently onto another machine or operating system
- detect sensitive material and make it obvious
- optionally require/use a YubiKey for repository encryption-key protection
- provide a clean, scriptable CLI
- keep the implementation deliberately small and avoid reimplementing backup primitives

## Core principle

> Backup is solved. Profile discovery, portability, safety, and UX are the product.

Do not implement a new backup format, deduplication algorithm, repository, chunker, object store, or cryptographic storage system.

## How it fits together

```text
 moss CLI ──── profile discovery, scan index, manifest, restore placement
   │
   ├── OS credential store   repository password only                    §6
   ├── config.yaml           sources, rules, repository location, no secrets §24
   ├── state dir             scan index, manifests, lock, restore journal,
   │                         Kopia's repository.config and logs (isolated) §10
   │
   └── kopia (subprocess) ── KOPIA_PASSWORD in child env only            §5
         │
         └── storage: local filesystem and/or S3-compatible bucket
               ├── Kopia blobs (encrypted, deduplicated)
               └── moss/envelope.age  (Phase 2, YubiKey-wrapped password) §36
```

One `moss backup` run produces one Kopia snapshot per semantic source plus one for the manifest, all
tagged with the same run id (§19). Restore is two-stage: Kopia restores into a moss-owned staging
directory, then moss places files with containment and conflict handling (§16).

---

# 2. Target platforms

First-class support:

- macOS
- Linux
- Windows

The implementation must use OS-specific adapters behind a common abstraction.

Do not scatter `cfg(target_os = ...)` throughout business logic.

Preferred architecture:

```text
src/
  cli/
  profile/
    mod.rs
    model.rs
    discovery.rs
    macos.rs
    linux.rs
    windows.rs
  backup/
    mod.rs
    kopia.rs
    repository.rs
  restore/
  security/
  credentials/
  yubikey/
  config/
  output/
  platform/
```

The exact module layout can differ, but the separation of concerns must remain.

---

# 3. Rust requirements

Use modern stable Rust: **edition 2024, `rust-version = "1.89"`** (std file locking landed in 1.89). CI runs an MSRV job at exactly that version.

Dependency set, verified against crates.io and docs.rs on 2026-09-03. Re-verify before pinning;
several crates in the previous revision of this list were deprecated or had changed API.

| Purpose | Crate | Notes |
|---|---|---|
| CLI | `clap` 4.6 (`derive`, `env`, `wrap_help`) | `init` needs `subcommand_negates_reqs` and `args_conflicts_with_subcommands` (§7) |
| Config | `serde` + `serde_yaml_ng` 0.10 | **`serde_yaml` and `serde_yml` are both deprecated.** Do not use either. |
| JSON | `serde_json` | Kopia structs use `#[serde(default)]`; never `deny_unknown_fields` (§5) |
| Errors | `thiserror` 2; `anyhow` 1 in `main` only | |
| Diagnostics | `tracing`, `tracing-subscriber` 0.3 (`env-filter`) | |
| Platform dirs | `directories` 6 | On Windows `ProjectDirs` appends `\config`, `\data`, `\cache`; `state_dir()` is `Some` on Linux only, use `data_local_dir()` elsewhere |
| XDG user dirs | own parser (~40 lines) | The `dirs` crate reads `user-dirs.dirs` but has **no** `/etc/xdg/user-dirs.defaults` fallback (§8). Do not depend on `dirs`. |
| Windows known folders | `known-folders` 1.4 | Returns `None` on any HRESULT failure including `E_INVALIDARG` |
| Walk and match | `ignore` 0.4 | `standard_filters(false)`; `overrides()` with `!glob` entries prunes directories; parallel visitor API; per-entry io errors expose `raw_os_error` |
| Unicode | `unicode-normalization` 0.1 | NFC/NFD collision detection (§12) |
| Secrets | `zeroize` 1.9, `secrecy` 0.10 | `SecretString` / `SecretBox<[u8]>` redact `Debug` by construction (§34) |
| Randomness | `getrandom` 0.4 (`fill`) | `rand` 0.10 renamed `OsRng`; not needed |
| Recovery code | `bip39` 2.2 (`std`, `zeroize`, English) | 32 bytes of entropy → 24 words (§6) |
| Credential store | `keyring` 4.2 | Holds the repository password only. v4 is a facade over `keyring-core` plus store crates; features are `apple-native-keyring-store`, `windows-native-keyring-store`, `zbus-secret-service-keyring-store` (+ one async-runtime feature). The v3 feature names no longer exist. |
| Containment | `rustix` 1.1 (`fs`, `process`) on Unix; `windows-sys` 0.61 + `winapi-util` 0.1 on Windows | `rustix::fs::openat2` + `ResolveFlags::IN_ROOT`; macOS `O_RESOLVE_BENEATH` is **not in `libc`**, define it locally (§16) |
| Lock | std `File::try_lock` (stable since Rust 1.89) | no crate |
| Progress / TTY | `indicatif` 0.18; `std::io::IsTerminal`; `owo-colors` 4 (`supports-colors`) | honours `NO_COLOR` |
| Binary lookup | `which` 8 | only for locating `kopia` |
| Tests | `assert_cmd` 2, `predicates` 3, `tempfile` 3, `insta` 1 | |
| Phase 2 | `age` 0.12 (`plugin`) driving the external `age-plugin-yubikey` binary | never the `yubikey` crate directly (§36) |

Avoid unnecessary dependencies.

Use `cargo fmt`, `cargo clippy`, and tests as first-class requirements.

The tool should compile cleanly with:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

---

# 4. Threat model

The security requirements in this document are meaningless without stating who they defend against. Implement to this model; do not add controls that defend against nothing on this list.

## In scope

**Malicious or tampered repository contents during restore.**
Restore writes attacker-influenceable data to the user's home directory. This is the highest-severity threat in the product because restore runs with the user's full privileges. Defences: path containment (§16), symlink handling (§17), manifest integrity (§27), never executing restored files.

**Compromised or hostile object storage.**
The S3 bucket may be read by a third party, or its contents modified. Kopia's repository encryption defends confidentiality and integrity of file data. moss must not weaken this by storing plaintext metadata outside the repository, and must treat the manifest as attacker-modifiable unless independently authenticated.

**Stolen or lost device, powered off.**
The repository password is in the OS keychain, protected at rest by the OS login credential. A stolen laptop should not yield the backup repository. Defence: never persist the password outside the keychain in a recoverable form; explicitly disable Kopia's own weaker persistence (§6).

**A local process running as the same user.**
This is a *partial* defence only, and the limits must be documented honestly to the user rather than papered over. See §6 for the `KOPIA_PASSWORD` limitation, which is forced by Kopia and cannot be engineered away.

**Accidental disclosure by the tool itself.**
Secrets in terminal output, logs, diagnostics, crash dumps, shell history, or process arguments. This is the most likely real-world failure and the cheapest to prevent. See §34 and §35.

**Shoulder-surfing and screen sharing.**
Sensitive values must not be printed merely because a command was verbose.

## Explicitly out of scope

- **A compromised machine at backup time.** If the host is owned, the profile is already readable by the attacker. moss does not defend this and must not claim to.
- **Malicious Kopia binary.** moss trusts the Kopia it invokes. Verifying the binary is the user's responsibility.
- **Coercion / rubber-hose.** No duress mechanisms, no plausible deniability.
- **Traffic analysis against the object store.** Repository access patterns leak approximate profile size and backup frequency. Accepted.
- **Multi-user hostile machines.** moss assumes the user owns the account it runs as.

## Consequences

Any requirement in §35 that does not map to a threat above should be questioned. Any threat above without a corresponding control is a gap.

---

# 5. Kopia integration

Kopia is the backup engine.

## Integration mechanism: subprocess

**Shell out to the Kopia CLI.** This is settled, not open for investigation.

Rationale, verified against Kopia master:

- Kopia is Go. There is no Rust binding, no crate, and no C ABI to bind against.
- The Go library (`github.com/kopia/kopia/repo`) is real and public, but the module is pre-1.0 with no documented API-compatibility policy, and much of the useful surface sits under `internal/` and is un-importable.
- Kanister, the most prominent third-party Kopia integration, shells out to the CLI rather than linking the library.

Do not fork Kopia. Do not reimplement repository operations. Do not attempt a `c-shared` cgo wrapper.

## Version coupling

moss is coupled to another project's CLI contract. Manage that coupling explicitly.

- Declare a **minimum tested Kopia version** and a **maximum tested version** in one constant.
- Probe `kopia --version` at startup for any command that touches a repository. Cache the result for the process lifetime.
- Below minimum, or above maximum: fail with a clear message and a distinct exit code (§23). Provide `--skip-version-check` for users who accept the risk.
- Kopia missing entirely is a **different** failure from a repository being unreachable, and gets its own exit code.

## JSON output is best-effort, not an API

Kopia's `--json` has **no stable or versioned contract**. It is `json.Marshal` over internal Go structs, so field names follow struct tags and change with internal refactors. The shape has changed across releases.

Therefore:

- Parse defensively. Ignore unknown fields. Never fail on an unexpected addition.
- Never rely on field ordering.
- Pin the Kopia version in CI and diff `--json` output on every upgrade.
- Where a value is critical to correctness (snapshot error counts, §18), validate its presence explicitly and fail loudly if absent rather than defaulting to zero.

Field names verified against Kopia master (2026-09-03); re-verify against the pinned version and
keep captured fixtures in `tests/fixtures/kopia/<version>/`:

| Command | Field | Meaning |
|---|---|---|
| `snapshot create --json` | `rootEntry.summ.numFailed` | fatal error count; **absent ⇒ error** |
| `snapshot create --json` | `rootEntry.summ.numIgnoredErrors` | ignored error count; `omitempty`, absent ⇒ zero |
| `snapshot create --json` | `rootEntry.summ.errors[]` | `{path, error}`, **capped at 10** by Kopia |
| `snapshot create/list --json` | `stats.errorCount`, `stats.ignoredErrorCount` | cross-check |
| `snapshot list --json` | `id`, `source{host,userName,path}`, `startTime`, `endTime`, `tags`, `incomplete`, `description` | |
| `repository status --json` | `uniqueIDHex`, `configFile`, `clientOptions{hostname,username}` | there is **no cache-directory field** |
| `maintenance info --json` | `owner` | maintenance owner (§30) |

**Never log the output of `kopia repository status --json`.** It leaked storage credentials unscrubbed before 0.16 (GHSA-j5vm-7qcc-2wwg) and still prints the S3 access key id.

## Repository backends

Kopia repositories must support:

- local filesystem repository
- S3
- S3-compatible storage

Examples include Amazon S3, MinIO, Cloudflare R2, Wasabi, and other S3-compatible providers.

Repository configuration must allow:

```text
backend
endpoint
bucket
prefix
region
credentials source
TLS configuration
```

Never require AWS specifically.

### S3 credentials — verified behaviour, not the earlier draft's assumption

Verified against Kopia master (`cli/storage_s3.go`, `repo/connect.go`, `repo/blob/s3/s3_options.go`):

- There is **no `KOPIA_S3_CREDS`**. The earlier draft invented it.
- `--access-key`, `--secret-access-key` and `--session-token` are bound by kingpin to
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`. Whatever value they end up with
  — flag **or environment** — is **written to `repository.config` in plaintext** at connect/create
  time. `--no-persist-credentials` does not cover this; it covers the repository password only.
- At runtime Kopia resolves credentials through a chain: static values from `repository.config`,
  then `AWS_*` environment, then IAM/instance role.

Decision (revision 3): **let Kopia persist them, and own the file that holds them.**

1. `moss init` takes S3 keys by prompt or from `AWS_*` in its own environment and passes them to
   `repository create`/`connect` **in the child environment only**, never as flags. Kopia writes
   them into `repository.config`.
2. That file lives under moss's state directory (`--config-file`, below), which moss creates with
   mode 0700 and the file with mode 0600. moss does not scrub the keys or copy them anywhere else.
   This is the same posture as `~/.aws/credentials`, and `doctor` checks the modes on every run.
3. Later invocations inject nothing; Kopia reads the keys from its config. If the user supplies no
   keys, Kopia's IAM/instance-role path applies unchanged.
4. `SECURITY.md` states plainly that S3 keys are stored in plaintext on disk under the state
   directory, protected only by file permissions and disk encryption. The OS credential store holds
   the repository password only (§6).

Do not store raw cloud credentials in the moss configuration file (`config.yaml`).

### Kopia process hygiene

Every Kopia invocation is built by one function and carries:

- `--config-file <state>/kopia/repository.config` — moss owns Kopia's config; it never collides with
  a user's own Kopia installation and moss knows exactly what to exclude (§10).
- `--cache-directory <cache>/kopia` on create/connect, for the same reason.
- `--log-dir <state>/kopia-logs` (mode 0700). **Kopia's file logging is on by default at `debug`
  level** and records snapshot source paths and per-file error paths; without `--verbose`, pass
  `--disable-file-logging` instead.
- `--no-persist-credentials` and `--no-check-for-updates` on create/connect (§6, §33).
- An **explicit environment allowlist** (`PATH`, `HOME`, `TMPDIR`, proxy variables, plus
  `KOPIA_PASSWORD`, `KOPIA_CHECK_FOR_UPDATES=false`, and `AWS_*` on create/connect only). The parent
  environment is never copied wholesale.

Kopia already provides encrypted repositories, snapshots, deduplication, content-addressable storage, local caching, and S3-compatible storage. Use those capabilities instead of reproducing them.

## Concurrency

**Concurrent `kopia snapshot create` against one repository is safe by design.** Kopia is content-addressable and append-only; pack blob IDs embed a session ID, so concurrent writers produce disjoint blob namespaces. Multiple hosts on one repository is a supported, intended use case.

Do not build locking to prevent repository corruption from concurrent snapshots. It is unnecessary. The moss-level lock in §18 exists for a different reason.

Maintenance is the genuine exclusion concern, and Kopia handles it itself with a local flock plus a designated maintenance owner. Do not reimplement this. Do not use `--safety=none`.

---

# 6. Credentials and recovery

This section resolves the circular dependency that would otherwise make cross-machine restore impossible: Kopia's own credential storage lives *inside* the profile being backed up, so a user restoring onto a new machine would need the very thing they are trying to recover.

## What Kopia forces on us

These are verified constraints, not design choices. Work within them.

**No password on stdin.** Kopia has no `--password-stdin` and no `--password-file`. Its interactive prompt performs a raw terminal read on stdin's file descriptor, so piping does not work. The resolution order (verified in `cli/password.go`) is `--password` / `KOPIA_PASSWORD`, then the persisted store, then the interactive prompt — prompt last, not second. A non-TTY with no password fails at the prompt.

**`KOPIA_PASSWORD` is therefore the only non-interactive mechanism.** moss must use it, and must never pass the password as a command-line argument.

**This leaks on Linux.** Environment variables are readable via `/proc/<pid>/environ` and `ps e` by processes running as the same user. There is no way around this while Kopia remains the engine. Document it plainly in `SECURITY.md`; do not pretend §35's "never put secrets in process arguments" fully covers it. The environment is better than argv (which is world-readable) but is not private.

**No external key hook.** Kopia derives a scrypt key-encryption key from the password, which unwraps a random master key stored in the repository format blob. A real envelope exists internally, but the only unwrapping input is a password string — there is no KMS interface and no pluggable KEK. This determines the YubiKey architecture in §36.

**Kopia's own password persistence is weak.** Its fallback sidecar file `repository.config.kopia-password` is **base64-encoded, not encrypted**. On Linux the keyring is off by default.

Therefore moss must always connect with `--no-persist-credentials` and own credential storage itself. Never allow Kopia to write the sidecar.

## moss credential design

`moss init` generates a high-entropy repository password (256 bits from `getrandom`). The user never chooses it and never needs to type it in normal operation.

**The recovery code and the password are the same string.** The 32 random bytes are rendered once
as a 24-word BIP39 English mnemonic (`bip39` crate), and the **canonical sentence** — lowercase words
separated by single spaces — is what Kopia receives as its password. There is no second encoding, no
derivation, and nothing to translate at recovery time: the user types the words in any spacing or
case, moss parses them with the `bip39` crate (which validates the 8-bit checksum and the word
list), re-renders the canonical sentence, and hands that to Kopia. Words were chosen over a bech32m
string because a recovery sheet is transcribed by hand and read back over the phone; the weaker
checksum is accepted, and moss compensates by reporting *which* word failed to match the list.

Storage, by platform:

| OS | Store |
|---|---|
| macOS | Keychain |
| Linux | Secret Service / libsecret |
| Windows | Credential Manager |

The store holds the repository password only, namespaced per repository
(`moss/<repository id>/repository-password`). S3 keys are persisted by Kopia in its own config file
under the state directory (§5).

If no credential store is available (headless Linux without a session bus is the common case), `moss init` must say so and require an explicit `--credential-store=env` opt-in, documenting that the user is now responsible for supplying `MOSS_REPOSITORY_PASSWORD` themselves. On every platform, `MOSS_REPOSITORY_PASSWORD` set in the environment takes precedence over the credential store, so a scheduler can supply it (§32). The `keyring` crate reports a missing Secret Service as a generic platform failure, so `doctor` probes the store by writing and deleting a sentinel entry rather than trusting an availability flag.

## The recovery sheet

**The first backup must not succeed until the user has acknowledged a recovery sheet.** This is a hard gate, not a warning. A backup whose credential exists in exactly one place, on the machine being backed up, is not a backup.

```text
RECOVERY SHEET — store this offline, away from this machine

  Repository:  s3://bucket/rhys
  Endpoint:    https://s3.example.com
  Created:     2026-09-02
  Profile:     rhys
  moss:        0.1.0     Kopia: 0.23.1

  Recovery code (24 words, in this order):
     1. abandon    2. ability    3. able       4. about
     5. above      6. absent     7. absorb     8. abstract
     9. absurd    10. abuse     11. access    12. accident
    13. account   14. accuse    15. achieve   16. acid
    17. acoustic  18. acquire   19. across    20. act
    21. action    22. actor     23. actress   24. actual

  Without this code, and without access to this machine's
  keychain, the repository CANNOT be recovered. There is no
  reset, no vendor, and no backdoor.

  [ ] I have stored this somewhere safe   (required to continue)
```

Requirements:

- The recovery code is the repository password itself as a 24-word BIP39 mnemonic (above). Use the `bip39` crate; do not invent an encoding. Number the words on the sheet so order survives transcription. Record the moss and Kopia versions on the sheet — they matter when recovering years later.
- Printing to stdout is acceptable; the user redirects or copies it. Consider a `--print` flag that pages it.
- `moss recovery show` re-displays it, requiring keychain unlock. It is not stored anywhere additional.
- Under `--non-interactive`, the gate cannot be satisfied interactively. `moss init --non-interactive` must therefore require `--recovery-acknowledged` and document that the caller has taken responsibility.

## Bootstrap on a second machine

This is the §39 Definition of Done path, and it must be explicit:

```bash
moss init --repository s3://bucket/rhys --endpoint https://s3.example.com
# → repository already exists at this location
# → prompts: enter recovery code, or connect a configured YubiKey
# → validates against the repository, stores in this machine's keychain
moss snapshots
moss restore latest
```

The recovery code is the only input required. No file needs to be copied from machine A.

## Runtime handling

- Read from keychain, pass via `KOPIA_PASSWORD` on the child process environment only, never the parent's.
- Zeroize the buffer after spawning.
- Never write it to a temp file.
- Never include it in `--verbose` output, `moss doctor`, or error diagnostics.
- Never place it in shell history — this is why there is no `--password` flag on moss.

---

# 7. CLI design

The CLI should feel like a native modern Unix/Windows developer tool.

Primary commands:

```text
moss init
moss doctor
moss inspect
moss backup
moss upload
moss snapshots
moss restore
moss status
moss verify
moss config
moss yubikey
```

Potential aliases may be added later.

## `init`

Configure a repository.

```bash
moss init --repository /Volumes/Backups/profile
```

```bash
moss init --repository s3://bucket/profile
```

`init` always writes the repository into the local configuration. There is no `--default` flag:
v1 supports exactly one repository per configuration (§24), so there is nothing to choose between.

For S3-compatible storage:

```bash
moss init \
  --repository s3://bucket/profile \
  --endpoint https://s3.wasabi.com
```

Endpoint discovery: rather than making users reason about regions, ship a small static table of known S3-compatible vendors and their endpoint patterns.

```bash
moss init list-backup-endpoints
moss init list-backup-endpoints --name wasabi
```

Keep this table in-tree and static. Do not fetch it at runtime — that would violate §33 (no phoning home). Research existing published endpoint lists and vendor documentation when building the table, and cite sources in a comment.

`list-backup-endpoints` is a subcommand of a command that otherwise takes flags. In clap this is
`#[command(subcommand_negates_reqs = true, args_conflicts_with_subcommands = true)]` with an
`Option<InitSubcommand>` field.

`init` guides the user through repository setup, generates and stores the repository password (§6), and gates on the recovery sheet.

Configuration is saved to a platform-appropriate location, overridable with `MOSS_CONFIG` or `--config`. See §24.

Do not make users understand Kopia internals.

## `doctor`

One diagnostic command covering every environmental precondition. For a tool that depends on an external binary, OS permission grants, a credential store, and optional hardware, this is the highest-value UX in the product.

```text
$ moss doctor

Kopia
  ✓ found            /opt/homebrew/bin/kopia
  ✓ version          0.23.1  (tested: 0.23.0 – 0.23.x)

Repository
  ✓ reachable        s3://bucket/rhys
  ✓ credentials      keychain
  ✓ recovery         acknowledged 2026-09-02

Platform
  ✗ full disk access NOT granted
      ~/Library/Mail and other protected paths will be skipped.
      Grant Full Disk Access to your terminal application in
      System Settings → Privacy & Security → Full Disk Access.

YubiKey
  – not configured

Scan index
  ✓ fresh            last scanned 2026-09-02 09:14
```

Also check: the credential store can be written (sentinel entry, §6) and can be read without a
prompt — a locked keychain or absent session bus is what makes scheduled runs fail (§32).

Exit non-zero if any check fails. Support `--json`. The version range shown is the pinned constant
from §5, not a literal; the values above are illustrative for Kopia 0.23.1.

---
# 8. Profile discovery

This is the heart of the product.

The application must discover the current user's profile automatically.

**The path lists below are a starting point, not gospel.** Validate each against the running system before including it. The previous revision of this document listed `~/Videos` on macOS, which does not exist — that class of error is exactly what discovery must avoid. Every path in the shipped table must be one of: verified present, cited to a platform authority, or explicitly marked as unvalidated.

## macOS

Primary profile: `/Users/<user>`

The standard home directories are exactly these eight, from Apple's own user template at `/System/Library/User Template/Non_localized/`:

```text
Desktop
Documents
Downloads
Library
Movies
Music
Pictures
Public
```

**It is `~/Movies`. There is no `~/Videos` on macOS.** Do not include one.

`~/Public` is standard and carries an `everyone deny delete` ACL; `~/Public/Drop Box`, when present, is mode 733 with an inherited ACL. Restoring mode bits alone silently breaks Drop Box — see §12. (Drop Box was absent on the development machine at revision 3; treat it as optional.)

`~/Desktop`, `~/Documents` and `~/Downloads` also carry `everyone deny delete` ACLs (verified).

**`~/Downloads` is opt-in on every platform.** It is a landing zone for installers, archives and
transient files rather than a place people keep things. `inspect` lists it under Opt-in and
`moss include ~/Downloads` turns it on, keeping the `downloads` semantic id.

The standard directories may contain a `.localized` marker (on the development machine all eight do, Desktop included — an earlier draft claimed Desktop did not). Finder displays a translated name while the on-disk name stays English. **Back up the on-disk name.**

Other relevant locations:

```text
~/.aws
~/.azure
~/.bash_history
~/.bash_profile
~/.bashrc
~/.claude
~/.codex
~/.config
~/.config/k9s                     (nested under ~/.config; same `k9s` id as the App Support path)
~/.docker
~/.gitconfig
~/.gnupg
~/.kube
~/.ssh
~/.talos
~/.terraform.d
~/.zshrc
~/Library/Application Support/k9s
~/Library/Preferences
```

`~/Library/Application Support` is discovered but **opt-in**: it is large, mostly app-managed
state that reinstalls regenerate, and it holds moss's and Kopia's own state. `moss include
"~/Library/Application Support"` turns it on with the `app_support` semantic id. Individual
tools that keep state there are listed as their own sources with their own ids (`k9s`) so they are
backed up by default and restore onto the platform's equivalent path (`~/.config/k9s` on Linux,
`%LOCALAPPDATA%\k9s` on Windows).

Never include cloud-drive roots (Nextcloud, OneDrive, Dropbox, Box, iCloud Drive) — they are already replicated, frequently enormous, and often contain reparse-point-like placeholder files.

Do not blindly include every `~/Library` subdirectory. `~/Library/Containers` measured 97 GB and `~/Library/Caches` 62 GB on the development machine.

### macOS TCC — mandatory reading

Transparency, Consent and Control will silently deny a CLI access to parts of the profile. Handled naively, moss produces a snapshot that looks complete and is not. This is a correctness bug, not an inconvenience.

**Detect denial by errno.** Apple's rule:

| errno | Meaning |
|---|---|
| `EACCES` (13) | BSD mode bits or ACL |
| `EPERM` (1) | TCC, SIP, or Data Vault |

**Never conflate the two.** That distinction is precisely what separates "the user cannot read this" from "this process has not been granted access". Verified empirically on macOS 26.6.2: both `opendir` and `open(2)` under a TCC-protected path return EPERM.

**Denied directories still appear in their parent's listing.** A protected directory is returned by `readdir` on its parent and fails only on entry. A naive recursive walk will descend and error. Partial-failure handling is mandatory, not optional.

**Grants key on the responsible process, by bundle ID.** TCC attributes access to the responsible process (`p_responsible_pid`, inherited across fork/spawn), identified by bundle ID rather than binary path. Consequences:

- A CLI invoked from Terminal inherits Terminal's grants.
- Granting Full Disk Access to the `moss` binary directly **does not work**.
- Signing, notarization, and the hardened runtime change none of this.

**A plain CLI cannot prompt.** TCC prompts appear only in a GUI login session; otherwise the operation is denied by default. moss must therefore detect the denial, explain it, and tell the user to grant FDA to their terminal application. `moss doctor` reports this.

Paths known to require Full Disk Access, by evidence strength:

| Path | Evidence |
|---|---|
| `~/Library/Mail` | Apple DTS |
| `~/Library/Safari` | well corroborated |
| `~/Library/Messages` | well corroborated |
| `~/Library/Application Support/AddressBook` | well corroborated |
| `~/Library/Calendars` | well corroborated |
| `~/Library/Cookies` | well corroborated |
| `~/Library/Containers`, `~/Library/Group Containers` | well corroborated |
| `~/Library/Suggestions` | **unverified** — no citable authority |

Apple has never published a canonical list. Treat the table as incomplete and rely on errno detection as the real mechanism.

**Default-skip `Containers` and `Group Containers`.** Since Sonoma these are gated per-container and grants last only for the process lifetime, so a walk across thirty apps fires thirty prompts on every single run. Opt-in only.

## Linux

Primary profile: `/home/<user>`

**XDG user directory names are localized.** A French desktop has literally `~/Vidéos`. Never assume English names.

Resolve in this order:

1. Read `$XDG_CONFIG_HOME/user-dirs.dirs` (default `~/.config/user-dirs.dirs`). Lines are
   `XDG_VIDEOS_DIR="$HOME/Vidéos"`; a value of exactly `$HOME/` means the directory is disabled.
2. Fall back to `/etc/xdg/user-dirs.defaults` (lines are `VIDEOS=Videos`, relative to home).
3. Fall back to English defaults only as a last resort.

Write this parser in-tree. The `dirs` crate does step 1 but not step 2 (verified in `dirs-sys`).

The variables are `XDG_DESKTOP_DIR`, `XDG_DOWNLOAD_DIR`, `XDG_TEMPLATES_DIR`, `XDG_PUBLICSHARE_DIR`, `XDG_DOCUMENTS_DIR`, `XDG_MUSIC_DIR`, `XDG_PICTURES_DIR`, `XDG_VIDEOS_DIR`.

Linux uses `XDG_VIDEOS_DIR` → `~/Videos`. There is no `~/Movies` and no `XDG_MOVIES_DIR`. This is the mirror image of macOS; the two must not be merged into a shared rule.

Base directories (XDG spec 0.8): `XDG_CONFIG_HOME` → `~/.config`, `XDG_DATA_HOME` → `~/.local/share`, `XDG_CACHE_HOME` → `~/.cache`, `XDG_STATE_HOME` → `~/.local/state`.

Other relevant locations:

```text
~/.ssh
~/.aws
~/.gnupg
~/.config
~/.local/share
~/.kube
~/.docker
~/.gitconfig
~/.terraform.d
~/.mozilla
~/.var
```

Desktop-environment-specific paths should be treated carefully.

## Windows

Primary profile: `C:\Users\<user>`

**Use `SHGetKnownFolderPath`. Never hardcode paths.** Every documented path is a *default*. Folder Redirection and OneDrive Known Folder Move relocate Documents, Desktop and Pictures in the field, and enterprise deployments do this routinely.

`FOLDERID_Videos` → `%USERPROFILE%\Videos`. "Movies" does not appear anywhere in the KNOWNFOLDERID reference.

Note `FOLDERID_Objects3D` returns `E_INVALIDARG` on systems predating Windows 10 1703 — handle the error rather than assuming every known folder resolves.

Other relevant locations:

```text
%USERPROFILE%\.ssh
%USERPROFILE%\.aws
%USERPROFILE%\.gnupg
%USERPROFILE%\.kube
%USERPROFILE%\.docker
%USERPROFILE%\.gitconfig
%APPDATA%
%LOCALAPPDATA%
```

Do not assume Unix dotfiles are the only form of hidden configuration on Windows.

## Discovery output

Discovered sources are written into the configuration at `init` time so the user can see and edit them, rather than being recomputed invisibly on every run.

Two different things are persisted, in two different places:

- The **source list** (semantic id, path, category, default action, sensitivity) goes into
  `config.yaml`. It is small, human-editable, and changes only when the user changes it.
- The **scan index** (per-directory sizes, counts, mtimes, classification, §11) goes into the state
  directory. It is large, machine-managed, and never in config.

User includes that have no semantic id (`moss include ~/Projects`) get the id
`custom:<home-relative path>` with portability `PortableWithPathTranslation`; restore maps them
under the destination user's home (§15).

---

# 9. Profile model

Do not represent the discovered profile as merely `Vec<PathBuf>`.

Create a semantic model.

```rust
enum ProfileCategory {
    PersonalData,
    Configuration,
    Credentials,
    Development,
    ApplicationState,
    SystemIntegration,
    Cache,
    Generated,
    Unknown,
}
```

Each discovered source should have metadata:

```rust
struct ProfileSource {
    id: String,
    path: PathBuf,
    category: ProfileCategory,
    platform: Platform,
    reason: String,
    default_action: Inclusion,
    sensitive: bool,
    portable: Portability,
}
```

Portability values:

```text
Portable
PortableWithPathTranslation
PlatformSpecific
MachineSpecific
Unknown
```

The `id` is the semantic key that makes cross-platform restore work (§15). It is stable across operating systems; the path is not.

This semantic layer is what enables the tool to restore intelligently.

---

# 10. Default profile and exclusions

The default profile should be conservative but useful.

Include:

- normal user documents, desktop, downloads, pictures, and the platform's video directory
- common development configuration
- SSH, AWS, GPG, Git, Kubernetes, Docker configuration
- common shell configuration
- common application configuration/state where useful

## Exclusions are patterns, not paths

A flat path list cannot express the actual problem. `node_modules` is not at a known location — it is at hundreds of unknown depths beneath the user's project directories. The development machine has 120 `node_modules` directories under `~/git` alone.

Use **gitignore-style recursive glob matching** evaluated during the walk, not a list of absolute paths. Reuse an existing matcher (the `ignore` crate) rather than writing one.

Directory-name patterns, matched at any depth:

```text
node_modules/
target/
.venv/
venv/
__pycache__/
vendor/
.gradle/
build/
dist/
.next/
.nuxt/
.terraform/
.cache/
DerivedData/
```

## Known cache locations

Measured on the development machine (macOS), largest first:

| Path | Size |
|---|---|
| `~/.cache/uv` | 18 GB |
| `~/.npm/_cacache` | 7.0 GB |
| `~/.nuget/packages` | 2.9 GB |
| `~/go/pkg/mod` | 2.8 GB |
| `~/Library/Caches/Homebrew` | 2.6 GB |
| `~/Library/pnpm` | 2.2 GB |
| `~/.gradle/caches` | 1.6 GB |
| `~/.cargo/registry` | 1.2 GB |
| `~/Library/Caches/pip` | 718 MB |

Also exclude by default: `~/.rustup/toolchains`, `~/.m2/repository`, `~/Library/Developer/Xcode/DerivedData`, and iOS Simulator runtimes.

**On macOS these tools do not use XDG paths.** Verified by querying the tools directly: `pip cache dir` → `~/Library/Caches/pip`; `pnpm store path` → `~/Library/pnpm/store/v3`; `go env GOCACHE` → `~/Library/Caches/go-build`.

**Query the tool for its cache location where a query exists.** Do not hardcode a path that the tool will tell you. Fall back to the table only when the tool is absent or the query fails. Queries run only for binaries found on `PATH`, with a two-second timeout each, and the answers are cached in the scan index so `inspect` does not spawn a dozen interpreters on every run.

## Resolving the §8 / §10 contradiction

Several paths listed as included in §8 contain predominantly disposable data. Resolve them explicitly rather than letting include and exclude rules fight:

| Path | Rule |
|---|---|
| `~/.npm` | include `~/.npm` config, exclude `~/.npm/_cacache` |
| `~/.docker` | include config and contexts, exclude `~/.docker/desktop` and all VM images |
| `~/.config` | include, minus any `Cache`/`cache` subdirectories |
| `~/.local/share` | include, minus `Trash` |

## Docker Desktop

```text
~/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw
```

Measured at **104 GB apparent, 79 GB actual** — it is sparse (§12). Reading it naively writes 104 GB of mostly zeros and destroys sparseness. Exclude by default. Older or alternate installs use `Docker.qcow2`, and the `vms/0` path differs under the Apple Virtualization framework, so match on the containing directory rather than the exact filename.

## Kopia's own state

moss passes `--config-file`, `--cache-directory` and `--log-dir` explicitly on every invocation
(§5), so the Kopia state moss creates lives under moss's own state and cache directories and is
excluded by construction. Do not try to discover it: `kopia repository status --json` has no
cache-directory field (verified), and it is the one command whose output must never be logged.

Also exclude the user's *own* Kopia installation, if any, so a user who runs Kopia directly does not
back up its cache into the repository:

| OS | Config | Cache |
|---|---|---|
| macOS | `~/Library/Application Support/kopia` | `~/Library/Caches/kopia` |
| Linux | `~/.config/kopia` | `~/.cache/kopia` |
| Windows | `%APPDATA%\kopia` | `%LOCALAPPDATA%\kopia` |

Exclude moss's own scan index, state directory, cache directory and restore staging directory for the same reason.

## Guardrails

Do not silently back up an unbounded profile.

- Warn when any single source exceeds a configurable threshold (default 10 GB).
- Warn when the total selection exceeds a configurable threshold (default 100 GB).
- Warn when the file count exceeds a configurable threshold (default 1,000,000).
- Under `--non-interactive`, exceeding a hard limit fails rather than proceeding.

The implementation combines: known platform paths, known application paths, category rules, and user overrides. Do not create an enormous hard-coded exclusion list without evidence.

---
# 11. Scan performance

`moss inspect` promises per-category sizes over a profile that may hold millions of inodes. On a cold cache that walk takes minutes. A spinner does not fix a slow walk; it only makes waiting visible.

## Requirements

**Cache the scan.** Maintain a scan index in moss's state directory holding per-directory size, file count, mtime, and classification. Subsequent `inspect` runs read the index and re-walk only subtrees whose mtime has changed.

**Report index age.** `inspect` and `doctor` state when the index was last refreshed. `--rescan` forces a full walk.

**Apply exclusions during the walk, not after.** Never descend into an excluded directory. This is the single largest performance factor: skipping `node_modules` at the top saves the entire subtree.

**Parallelise the walk** across independent top-level sources, bounded by available parallelism.

**Do not stat what you do not need.** Size and count come from directory metadata where the platform provides it.

**Handle partial failure inline** (§18). A TCC-denied directory is recorded as skipped-with-reason and does not abort the scan.

## Interactive display

While scanning, show a live status with progress and per-source ticks. Requirements:

- Refresh at a fixed rate, not per file.
- Detect non-TTY and degrade to periodic plain lines.
- Honour `--quiet` and `NO_COLOR`.
- Never let rendering block the walk.

---

# 12. Filesystem fidelity

What survives a backup-and-restore cycle, and what provably does not. Every limitation here is a **product limitation caused by Kopia** and must be documented in `SECURITY.md` and `README.md` rather than discovered by a user whose restore silently lost data.

## Preserved by Kopia

- File mode bits
- UID and GID
- Modification time
- Device and rdev info
- Symlinks as symlinks

## NOT preserved by Kopia

Verified by inspecting the Kopia source tree. These are absent entirely, not merely off by default.

| Feature | Status |
|---|---|
| Extended attributes (xattrs) | **not implemented** |
| POSIX ACLs | **not implemented** (they are stored as xattrs) |
| Linux capabilities, SELinux labels | **not implemented** |
| Windows ACLs / security descriptors | **not implemented** (kopia#3884) |
| Hardlinks | broken into separate files, dedup at content level |
| Sockets, FIFOs, device nodes | not backed up |
| setuid / setgid / sticky | nominally supported, **reported broken** (kopia#544, open since 2020) |
| macOS resource forks, Finder flags, quarantine | not preserved (they are xattrs) |

Kopia documents none of this. There is no "what metadata is preserved" page.

**Concrete consequence to state in the docs:** macOS `~/Public/Drop Box` relies on an inherited ACL. Restoring mode bits alone does not recreate it. The directory will exist with the wrong access semantics.

**setuid/setgid/sticky are dropped on restore** — resolved from source at revision 3:
`snapshot/restore/local_fs_output.go` applies `Mode() & ModBits & ^modclear`, permission bits only.
kopia#544 and kopia#3884 remain open; the hardlink PR kopia#4460 is open and unmerged. Keep an
empirical test at the pinned version so a future Kopia change is noticed, and state the limitation
in the docs now.

## File modes matter more than they look

Verified on OpenSSH 10.3p1: a private key at mode 0644 causes a **hard failure**, exit 1:

```text
WARNING: UNPROTECTED PRIVATE KEY FILE!
Permissions 0644 for '...' are too open.
This private key will be ignored.
```

GnuPG 2.4.9 differs — a homedir at 0777 produces only a warning and **exit 0**.

So: ssh hard-fails, gpg warns. A restore that widens modes silently disables SSH authentication while appearing to succeed. Restore must preserve modes exactly, and `moss verify` should check that restored credential paths have sane modes.

`~/.ssh/config` must not be group- or world-*writable* (world-readable is fine). `~/.ssh` itself is recommended 0700 but not enforced by the client.

## Case and Unicode collisions

**This causes silent data loss and must be handled at backup time.**

Verified on APFS: a source tree containing `Makefile` and `makefile`, restored to a case-insensitive volume, produced **two files instead of four, last-writer-wins, with no error raised at any layer**.

A second vector is subtler. APFS is Unicode normalization-**insensitive but preserving**: `café.txt` written NFC and then NFD produces **one file**, the second write clobbering the first. On ext4 those are two distinct files. Any Linux tree with mixed normalization loses data when restored to macOS.

Defaults, verified locally where possible:

| Filesystem | Case | Normalization |
|---|---|---|
| APFS (macOS) | insensitive, preserving | insensitive, preserving |
| NTFS (Windows) | insensitive, preserving | sensitive |
| ext4 (Linux) | sensitive | sensitive |

Requirements:

- **Detect collisions during the backup scan**, where both members are visible. Record them in the manifest (§27).
- **At restore, fail loudly** on a recorded collision targeting a case- or normalization-insensitive destination. Offer a deterministic renaming scheme (`name.1`, `name.2` by sorted original order) behind an explicit flag.
- **Never let the filesystem resolve a collision silently.**

Windows per-directory case sensitivity (`fsutil file setCaseSensitiveInfo`) is not a solution: it needs elevation, requires the directory be empty, and Microsoft warns that directories created by Windows applications inside the tree are not case-sensitive.

## Windows path and name constraints

Illegal characters: `< > : " / \ | ? *`, NUL, and **0x01–0x1F**. (0x7F is not documented as illegal.)

Reserved device names: `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, plus the superscript variants `COM¹ COM² COM³ LPT¹ LPT² LPT³`. **Reserved with any extension** — `NUL.txt` is equivalent to `NUL`. `COM0`/`LPT0` are not in the documented list; treat as unconfirmed and sanitize defensively.

Trailing dots and spaces: NTFS stores them, but Win32 normalization strips them before the call reaches the filesystem. A Linux file named `foo.` silently collides with `foo`.

`MAX_PATH` is 260 including the NUL terminator; the directory limit is 248. Long-path support requires **both** the `LongPathsEnabled` registry DWORD and a `longPathAware` manifest entry, is Windows 10 1607+, is cached per process on first call, and is honoured only by wide-character functions.

**Emit all Windows paths as `\\?\` plus a fully-qualified canonical backslash path.** This handles length, trailing dots and spaces, and normalization in one move, and removes the registry and manifest dependency entirely. Note that `\\?\` disables all normalization: no forward slashes, no `.` or `..`, no relative paths. UNC form is `\\?\UNC\server\share`. This applies to moss's own writes during restore placement (§16); Kopia's writes go to the staging directory, whose path moss chooses to be short.

Detect illegal names at backup time and record them in the manifest alongside collisions.

## Sparse files

Preserve sparseness where the platform allows; never materialise a sparse file into its apparent size. `Docker.raw` is the worked example: 104 GB apparent against 79 GB actual (§10).

---

# 13. `inspect`

This should be one of the best commands in the product.

```text
$ moss inspect

Profile
  User: rhys
  OS: macOS
  Home: /Users/rhys

Included
  Documents             4.2 GB
  Desktop               120 MB
  Development           1.8 GB
  Configuration          86 MB
  Application state      2.4 GB

Sensitive
  SSH                     5 files
  AWS                     4 files
  GPG                   182 files
  Kubernetes              2 files
  Docker                  1 file

Excluded
  Caches                 12.8 GB
  Build artifacts         3.2 GB
  Temporary files         1.1 GB

Skipped
  ~/Library/Mail          permission denied (Full Disk Access)

Estimated backup size
  Raw:                  25.7 GB
  Existing repository:  18.2 GB

Scan index: 4 minutes old
```

Estimation may initially be approximate. `inspect` never touches the repository and needs no
credentials unless `--estimate` is given; it must work offline.

The **Skipped** block is not optional. Anything the scan could not read appears there with a reason. A profile with unreadable regions must never present as complete.

Never print secret contents, private keys, access tokens, or credential file contents.

---

# 14. Sensitive data handling

The tool must explicitly recognise that a user profile can contain extremely sensitive material.

Known sensitive categories:

```text
SSH private keys
AWS credentials
GPG private keys
Kubernetes credentials
Docker credentials
cloud provider credentials
Git credential stores
password-manager exports
API tokens
.env files
credential caches
TLS private keys
```

Sensitive detection must be **metadata-based**: path, filename, and extension. Do not inspect file contents by default. Do not upload files merely to determine whether they contain secrets.

The tool should warn:

```text
This profile contains sensitive credentials.

Repository encryption is enabled.

Continue? [y/N]
```

Configurable:

```yaml
safety:
  warn_on_sensitive: true
  allow_sensitive: true
```

The default must be safe.

---
# 15. Cross-platform restore

This is a key differentiator.

A backup made on macOS should be restorable onto Linux or Windows.

Do not blindly recreate the original absolute paths.

```text
macOS:   /Users/rhys/.ssh
Linux:   /home/rhys/.ssh
Windows: C:\Users\rhys\.ssh
```

The semantic source is `ssh`, and the platform adapter maps it to the destination. Semantic ids:

```text
user_home
documents
desktop
downloads
pictures
video          (→ ~/Movies on macOS, ~/Videos on Linux/Windows)
music
public
aws
ssh
gnupg
kubernetes
docker
git
shell
```

Note `video` as the semantic id resolving to different directory names per platform. This is exactly why the model is semantic rather than path-based, and why the macOS and Linux rules cannot be merged.

## Path translation inside file contents

Directory mapping is the easy half. The hard half is that configuration files contain **absolute paths in their contents**, and a mechanically correct file restore produces a broken configuration.

Known cases:

| File | Embedded path |
|---|---|
| `~/.ssh/config` | `IdentityFile`, `ControlPath`, `UserKnownHostsFile`, `Include` |
| `~/.gitconfig` | `[includeIf "gitdir:..."]`, `core.excludesfile`, `credential.helper` |
| `~/.kube/config` | `client-certificate`, `client-key`, `certificate-authority`, `exec` command paths |
| `~/.aws/config` | `credential_process`, `ca_bundle` |
| `~/.zshrc`, `~/.bashrc`, `~/.bash_profile` | `PATH`, `source`, `export` of absolute paths |
| `~/.docker/config.json` | `credsStore` helper paths |

**Decision: do not rewrite file contents in v1.** Content rewriting requires a correct parser per format; a regex approach will corrupt files, and corrupting `~/.ssh/config` or `~/.kube/config` during a restore is worse than leaving them stale.

Instead:

1. **Detect** embedded absolute paths that will not resolve on the destination, using per-format read-only scanners.
2. **Report** them after restore, grouped by file, with the old and expected-new path.
3. **Offer** `moss restore --rewrite-paths` as an explicit opt-in, implemented per format with real parsers, deferred to Phase 2.

```text
Restored 4 files with paths that will not resolve on this system:

  ~/.ssh/config:12    IdentityFile /Users/rhys/.ssh/id_ed25519
                      → likely /home/rhys/.ssh/id_ed25519

  ~/.kube/config:31   client-certificate /Users/rhys/.minikube/client.crt
                      → likely /home/rhys/.minikube/client.crt

Review these manually, or re-run with --rewrite-paths (experimental).
```

Silent breakage is the failure mode to avoid. Reporting is honest and cheap; rewriting is neither.

## Username differences

Usernames differ across machines — `rhys` on one, `revans` on another. §22's identity model keeps profile identity independent of username, and restore must map `user_home` to the *destination* user's home rather than assuming the source username exists.

## Restore selectors

```bash
moss restore latest
moss restore latest --dry-run
moss restore latest --category credentials
moss restore latest --source ssh
moss restore --from-host macbook
```

---

# 16. Restore safety

Default restore behaviour must be non-destructive.

Before overwriting an existing file:

```text
~/.ssh/config exists

  [s] Skip
  [o] Overwrite
  [b] Backup existing
  [d] Diff
```

Bulk policies:

```text
--conflict skip
--conflict overwrite
--conflict backup
--conflict interactive
```

Default: interactive for a TTY, skip for non-interactive. `[d] Diff` applies to text files; for
binaries show size, mtime and hash of both sides instead.

Never silently overwrite credentials or configuration files.

## Restore mechanism: two stages

Kopia's `snapshot restore` writes files itself and knows nothing about containment, conflict
policies or the journal below. moss therefore never lets Kopia write into the profile:

1. **Stage.** For each selected semantic source, `kopia snapshot restore <id> <staging>/<source>`
   into a fresh, moss-owned directory under the state directory, on the same volume as the home
   directory so placement can `rename`. Use `--write-sparse-files`; leave `--skip-owners` to the
   user (§12). One source at a time bounds the temporary disk cost, which must be reported in
   `--dry-run`.
2. **Place.** moss walks the staged tree and moves each entry to its destination using the
   containment primitives below, the conflict policy, and the journal. Symlinks are recreated as
   symlinks; nothing in staging is followed.

Staging doubles the I/O for a restore. That is the price of §4's threat model and is accepted.

## Safe path resolution

Restore writes attacker-influenceable data with the user's full privileges (§4). Path containment is the primary control.

**`O_NOFOLLOW` is not containment.** Verified: it guards only the *final* component. Opening `link/file` through an intermediate symlink succeeds. A final-component symlink returns `ELOOP` on Linux and macOS, `EMLINK` on FreeBSD — portable code must accept both. `O_NOFOLLOW` alone is insufficient on every platform.

Use real containment primitives:

| Platform | Primitive |
|---|---|
| Linux | `openat2` with `RESOLVE_IN_ROOT` |
| macOS | `openat` with `O_RESOLVE_BENEATH` |
| Windows | manual component-by-component traversal |

**Linux.** `openat2(2)` landed in kernel 5.6 and has **no glibc wrapper** — call via `syscall(SYS_openat2, ...)` and handle `ENOSYS` on older kernels with a documented fallback. Prefer `RESOLVE_IN_ROOT` over `RESOLVE_BENEATH` for restore: it reinterprets absolute symlinks against the root rather than rejecting them outright, which is friendlier for archive extraction.

**macOS.** `O_RESOLVE_BENEATH` (0x1000) is real, documented in `man 2 open`, and returns `ENOTCAPABLE`. The `libc` crate does **not** define it for Apple targets (it defines a FreeBSD constant of the same name with a different value, `0x00800000`); moss defines `O_RESOLVE_BENEATH: c_int = 0x1000` locally under `cfg(target_os = "macos")` and must never use `libc::O_RESOLVE_BENEATH`. `libc::O_NOFOLLOW_ANY` is present. Verified working on macOS 26.6.2 against `..` escapes, absolute paths, symlinks to `/etc`, and symlink chains climbing out via `../..`. Internal `..` that stays within the root is permitted. Also available: `O_NOFOLLOW_ANY` (macOS 11+, `ELOOP` if *any* component is a symlink) and `O_UNIQUE` (fails if the file has multiple hardlinks).

**Windows** has no per-open containment. moss builds one from `NtCreateFile` *relative* opens: each component is opened relative to the **handle** of its verified parent (`OBJECT_ATTRIBUTES.RootDirectory`) with `FILE_OPEN_REPARSE_POINT`, so a symlink or junction is opened itself and never followed. The handle is checked for `FILE_ATTRIBUTE_REPARSE_POINT` (any tag is refused), its volume serial and file id (`GetFileInformationByHandleEx(FileIdInfo)`) are compared with the root's — **never by string prefix** — and it then becomes the parent for the next component. Every write, stat, rename (`NtSetInformationFile(FileRenameInformation)` with a `RootDirectory` handle) and delete (`FileDispositionInformationEx`) acts on such a handle; no path string is re-resolved after validation. The single exception is symlink creation, which Win32 offers only by path: the link is created under the path derived from the verified parent handle and immediately re-verified through that handle, and removed if it did not land there. The documented limit is 63 reparse points per path.

## TOCTOU

Validating a path and then opening it by name is a race: an attacker who controls any directory in the chain can swap a component in between. **Validate and open in one operation** using the primitives above, then act on the resulting file descriptor or handle. Never re-derive a path from a string after validation.

The destination being a pre-existing symlink placed by an earlier attack is the specific case to defend: opening `~/.ssh/config` for write must not follow a symlink to `/etc/cron.d/x`.

## Other restore rules

- Do not execute restored files.
- Do not automatically import restored credentials into running agents (`ssh-agent`, `gpg-agent`).
- Restore outside the profile root requires explicit user intent.
- Validate that a restored path's semantic category matches its destination — a `credentials` source must not land outside the expected directory.

---

# 17. Symlink handling

Default: **do not follow symlinks.** Back up the link itself, not its target.

Preserve symlink metadata where supported and safe.

Do not allow a malicious backup to restore `~/.ssh/config -> /etc/something`, or any equivalent traversal. Restore resolves and validates destination paths using §16's primitives before writing.

Windows symlink creation may require elevation or Developer Mode. Where it is unavailable, record the symlink as skipped rather than silently materialising a copy of the target.

---

# 18. Failure semantics

A backup tool is defined by what it does when things go wrong. Every case below must have specified behaviour.

## Kopia exit codes carry almost no information

**Kopia exits 0 or 1. There is no third code.** Worse, the mapping is not what it looks like:

- **Ignored errors** → warning on stderr, snapshot saved, **exit 0**
- **Fatal errors** → **exit 1**, but the snapshot manifest **has already been saved** by that point

So exit 1 does not mean "no snapshot was created", and exit 0 does not mean "everything was backed up".

**Never determine backup completeness from Kopia's exit code.** Parse `--json` for `rootEntry.summ.numFailed` (missing ⇒ error) and `rootEntry.summ.numIgnoredErrors` (`omitempty`, missing ⇒ zero), and cross-check `stats.errorCount` (§5 table). Kopia caps `summ.errors[]` at ten entries, so moss's own scan (§11) is the authoritative list of skipped paths; Kopia's counts exist to catch anything the scan did not predict.

Error-handling behaviour is controlled by *policy*, not by `snapshot create` flags: `kopia policy set --ignore-file-errors --ignore-dir-errors --ignore-unknown-types`. `--fail-fast` aborts on the first error without recording a manifest.

## Partial backups

Unreadable files are normal, not exceptional: macOS TCC denials (§8), files deleted mid-scan, permission errors, locked files on Windows.

Required behaviour:

- Continue past individual failures; do not abort the run.
- Record every skipped path with its reason and errno class.
- Report the skipped set in `inspect`, `backup` output, and the manifest.
- Exit with the **partial success** code (§23), never 0.
- Under `--non-interactive`, partial success is still non-zero so schedulers notice.

A snapshot that skipped part of the profile is a valid snapshot, clearly labelled. It is never presented as complete.

## Interrupted operations

**Backup.** Kopia handles interruption; a killed run leaves no corrupt state. Release the moss lock and report.

**Restore.** A killed restore leaves a partially written profile, and for credentials that is worse than nothing. Maintain a **restore journal** in the state directory recording each intended write, its conflict decision, and its completion. On the next run, detect the incomplete journal and offer to resume or roll back. Write the journal entry *before* the file, and fsync it.

## Concurrency

Take a **moss-level lock** for the duration of `backup`, `restore`, and `upload`.

This is not for repository safety — concurrent Kopia snapshots are safe (§5). It prevents a scheduled run and an interactive run from confusing the user with interleaved output, competing progress displays, and duplicated conflict prompts.

An already-running moss exits with a distinct code (§23) and names the holding PID and start time. Use a lock file with a liveness check so a stale lock from a killed process does not wedge the tool permanently.

## Repository unavailable

Distinguish, with different exit codes and messages: Kopia not installed, Kopia version incompatible, repository unreachable (network/endpoint), authentication failure (credentials rejected), repository not initialised at this location.

---
# 19. Snapshot semantics

Expose Kopia snapshots as user-friendly profile snapshots.

## One profile snapshot is a group of Kopia snapshots

Kopia snapshots are per source path. One `moss backup` run snapshots every selected semantic source
plus the manifest directory (§27) in a single `kopia snapshot create` invocation, and every
resulting Kopia snapshot carries the same tags:

```text
moss:run=<ulid>          identifies the run; this is the ID moss shows
moss:profile=<identity>  §22
moss:source=<semantic id>
moss:os=<macos|linux|windows>
moss:schema=1
```

`moss snapshots` lists `kopia snapshot list --all --json` grouped by `moss:run`; `--tags` filtering
on the Kopia side keeps it cheap. A run is `complete` only if every member snapshot has zero
`numFailed` and the manifest records no skipped paths.

```bash
moss snapshots
```

```text
ID          DATE                 HOST       SIZE      STATUS
a8f3c2      2026-09-02 10:30     macbook    24.1 GB   complete
9e71aa      2026-08-29 19:14     macbook    23.8 GB   partial (12 skipped)
4c8b11      2026-08-20 08:41     linux      21.4 GB   complete
```

The `STATUS` column is required — a partial snapshot (§18) must be visibly distinct at the point where a user chooses what to restore.

```bash
moss snapshots --host macbook
moss snapshots --latest
moss snapshots --json
```

---

# 20. Local and S3 repositories

Support `filesystem` and `s3`.

```bash
moss init --repository /mnt/backups/rhys
moss init --repository s3://bucket/rhys
moss init --repository s3://bucket/rhys --endpoint https://s3.example.com
```

Prefer path-style S3 endpoints.

Expose enough configuration for S3-compatible providers without forcing provider-specific logic into the profile layer.

---

# 21. Offline backup and deferred upload

The workflow: back up locally while offline or on a poor connection, then push to S3 later.

```bash
moss backup --local-only
moss upload
```

## Mechanism

`moss upload` wraps `kopia repository sync-to`. Understand exactly what that is before implementing.

`sync-to` is a **blob-level incremental copy** of one repository's blob store to another storage backend. It does not re-encrypt, re-chunk, or understand snapshots. It lists blobs on both sides and copies what is missing or newer. Think rsync for the blob layer.

## Hard constraints

**Same repository lineage, enforced.** Kopia compares the `uniqueID` field of the `kopia.repository` format blob on both sides. A mismatch is a hard error: `destination repository contains incompatible data`. Two independently created repositories can never be synced together.

This determines the setup flow. The local and S3 repositories are **one repository in two locations**, not two repositories. `moss init` must create them as such — either by creating local first and letting the first `upload` copy the format blob to an empty destination, or by explicitly configuring both at init time. If the destination already holds a different repository, fail with a clear explanation rather than a Kopia error.

**Directly-connected repositories only.** `sync-to` refuses to run against a repository-server connection.

**No locking exists in the sync path.** A snapshot running concurrently with `upload` copies a moving target: index blobs may reference pack blobs not yet transferred. Not corrupting — a later sync converges — but the destination is **not point-in-time consistent mid-run**. moss's own lock (§18) prevents this for moss-initiated operations.

**Garbage accumulates without `--delete`.** The destination retains blobs deleted from the source. Kopia's docs: the repository stays correct but does not benefit from compaction and runs more slowly. Expose `--delete` as an explicit flag with a clear warning; do not default it on.

**`--parallel` defaults to 1.** Raise it. A single-threaded upload of tens of gigabytes to S3 is needlessly slow.

**`--must-exist`** guards against an unmounted destination triggering a full re-upload. Use it whenever the destination has been synced before.

## Preflight

Before any transfer:

1. Both repositories reachable.
2. `uniqueID` matches, or destination is empty.
3. No maintenance in flight.
4. moss lock acquired.
5. Report bytes to transfer; `--dry-run` stops here.

## Assumption requiring validation

**Whether a `sync-to` destination is directly usable as a normal repository is not documented by Kopia.** The code copies blobs byte-for-byte and preserves the format blob verbatim, including `uniqueID`, which strongly implies the same password opens it and `kopia repository connect` works against it.

**Test this empirically before relying on it.** The entire value of `moss upload` depends on the S3 copy being restorable on another machine. Add an integration test that syncs a local repository to a MinIO instance, connects to the destination independently, and restores from it (§38).

Also note: maintenance runs against the source, so object-lock retention on the destination is not renewed by source-side maintenance (kopia#3759).

---

# 22. Host identity

A profile may be backed up from multiple machines.

Track:

```text
profile identity
host identity
OS
hostname
username
timestamp
tool version
profile schema version
```

**Profile identity is independent of both hostname and username.** It is an explicit, stable, user-chosen identifier assigned at `init` and stored in the repository. Usernames differ across machines — `rhys` on a laptop, `revans` on a corporate Linux box — and deriving identity from the username would fragment one logical profile into several.

```text
Profile: rhys
Hosts:
  macbook          macOS    user rhys
  linux-workstation Linux   user revans
  windows-desktop  Windows  user rhys
```

This enables `moss restore --from-host macbook`, and restore maps `user_home` to the destination user's home regardless of the source username (§15).

---

# 23. Exit codes

```text
0   success
1   general failure
2   invalid CLI usage
3   repository unavailable
4   authentication failure
5   restore conflict
6   sensitive-data safety refusal
7   YubiKey unavailable
8   integrity/verification failure
9   partial success — completed with skipped files
10  already running — another moss holds the lock
11  Kopia not found
12  Kopia version incompatible
13  interaction required — a prompt was needed under --non-interactive
```

Code 9 is what a scheduler checks to distinguish a clean backup from one that silently skipped the user's Mail directory. Code 13 covers every prompt that cannot be answered non-interactively (unacknowledged recovery sheet, restore conflict with no policy, guardrail confirmation); the sensitive-data gate keeps its own code 6.

Exit codes are a contract like the JSON schema (§26): stable within a major version, additions only.

Do not rely on parsing human-readable error strings. Do not propagate Kopia's exit code directly — it carries almost no information (§18).

---

# 24. Configuration

Use a predictable configuration location. Do not invent a custom global configuration system when the platform provides a standard directory.

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/moss/config.yaml` |
| Linux | `$XDG_CONFIG_HOME/moss/config.yaml`, else `~/.config/moss/config.yaml` |
| Windows | `%APPDATA%\moss\config.yaml` |

Overridable with `MOSS_CONFIG` or `--config`.

The configuration is **YAML**. Earlier drafts of this document mixed TOML assignment syntax into YAML blocks; that was an error.

```yaml
profile:
  name: default
  identity: rhys

repository:
  type: s3
  bucket: my-moss
  prefix: rhys
  endpoint: https://s3.example.com
  region: auto
  credential_store: keyring      # keyring | env
  recovery_acknowledged_at: 2026-09-02T09:14:00Z

  local:
    path: /Volumes/Backups/profile

backup:
  include_sensitive: true
  follow_symlinks: false

restore:
  conflict: backup

safety:
  warn_on_sensitive: true
  allow_sensitive: true

limits:
  max_source_size_gb: 10
  max_total_size_gb: 100
  max_file_count: 1000000

yubikey:
  enabled: true
  recipient: age1...

include:
  - path: ~/Projects

exclude:
  - path: ~/Movies
```

A single repository may have both a `local` path and an S3 backend — that is the §21 offline workflow, one repository in two locations, not two repositories.

**Do not put secrets in this file.** The repository password lives in the OS keychain (§6); S3 keys live in Kopia's own config file under the state directory (§5). The `sources:` list written by `init` (§8) also lives here.

The `--repository <name>` global flag in §44 implies named repositories. **v1 supports exactly one repository per configuration**; `--repository` accepts a URL override only. Multiple named repositories are Phase 3.

---

# 25. User overrides

Users must be able to include and exclude paths.

```bash
moss include ~/Projects
moss exclude ~/Videos
```

Or in configuration, as shown in §24.

Explicit user rules take precedence over default discovery rules. Exclusions use the same gitignore-style pattern matching as §10, so `moss exclude 'node_modules/'` works at any depth.

---

# 26. JSON output

Every information-oriented command supports `--json`:

```bash
moss inspect --json
moss snapshots --json
moss status --json
moss doctor --json
moss backup --json
```

`backup` and `restore` need JSON too — automation (§32) must consume progress and results, not scrape human output.

This enables scripting, CI, automation, shell integration, and future GUI work.

Human output is designed for humans. JSON output carries an explicit `schema_version` and is stable within a major version. **Unlike Kopia's JSON (§5), moss's JSON is a contract** — additive changes only within a major version.

---

# 27. Profile manifests

Every snapshot carries a small logical manifest describing the profile selection. This does not replace Kopia's snapshot metadata; it sits alongside it.

```json
{
  "schema_version": 1,
  "profile": "default",
  "profile_identity": "rhys",
  "source_os": "macos",
  "source_host": "macbook",
  "source_user": "rhys",
  "tool_version": "0.1.0",
  "categories": ["personal", "configuration", "credentials", "development"],
  "sources": [
    { "id": "ssh", "category": "credentials", "portable": "Portable" }
  ],
  "skipped": [
    { "path": "~/Library/Mail", "reason": "permission_denied", "errno": "EPERM" }
  ],
  "collisions": [
    { "kind": "case", "paths": ["src/Makefile", "src/makefile"] },
    { "kind": "normalization", "paths": ["café.txt"] },
    { "kind": "windows_illegal", "path": "notes:draft.md" }
  ]
}
```

The `skipped` and `collisions` arrays come from §18 and §12 and are what let restore fail loudly instead of losing data silently.

## Integrity

The manifest drives restore path mapping. An attacker who can write to the repository could redirect a restore by editing it — this is the §4 primary threat.

**Authenticate the manifest.** Store it as content inside the Kopia repository so it inherits repository encryption and integrity, rather than as a plaintext sidecar in the object store. If any deployment requires it outside the repository, it must carry a signature verified against a key derived from the repository secret.

Mechanism: moss writes the manifest to `<state>/manifests/<run>.json` and includes that directory
as one more source path in the run's `kopia snapshot create` invocation, tagged
`moss:source=manifest` alongside the run tags (§19). Restore fetches it first with
`kopia snapshot restore <manifest snapshot id> <staging>` and validates `schema_version` before
reading anything else. Kopia offers no other way to store arbitrary content, and this way needs no
extra repository primitive.

Never trust manifest-supplied paths without applying §16's containment.

## Privacy

The manifest may contain paths, categories, sizes, hashes, and metadata. It must never contain secret contents.

Consider privacy implications before storing absolute paths in a remote repository — they leak usernames and directory structure. Prefer semantic ids and home-relative paths; store absolute paths only where required for restore correctness.

---

# 28. Profiles

Support named profiles:

```bash
moss profiles
moss backup --profile default
moss backup --profile minimal
moss backup --profile developer
```

Ship one default profile plus a configuration mechanism. Potential profiles: `default`, `developer`, `minimal`, `full`.

Do not over-engineer profile inheritance.

---

# 29. Dry run

Every potentially destructive operation supports `--dry-run`:

```bash
moss backup --dry-run
moss restore latest --dry-run
moss upload --dry-run
```

Dry-run output shows files and categories included and excluded, destination paths, conflicts, sensitive material, skipped paths with reasons, recorded collisions, and estimated changes.

---
# 30. Repository lifecycle

```bash
moss status
moss verify
moss prune
moss maintenance
```

Delegate actual repository maintenance to Kopia. Do not implement pruning, garbage collection, repository checking, or repair.

Do not use `--safety=none`. It removes the time-based margins that make maintenance safe against eventual-consistency object stores, and requires a guarantee of no concurrent operations that moss cannot make.

Kopia designates a maintenance **owner** (`user@hostname`); only that identity runs maintenance automatically. Surface the owner in `moss status` so a multi-machine user can see which host is responsible.

Advanced Kopia-specific operations may be exposed through `moss kopia ...` as an escape hatch, not the primary UX.

---

# 31. First-run UX

Zero to first backup, quickly.

```bash
moss init
```

```text
Welcome to moss.

Detected:
  OS: macOS
  User: rhys
  Home: /Users/rhys

Choose repository:
  1. Local filesystem
  2. Amazon S3 / S3-compatible

Generating repository encryption key...

YubiKey detected.
Use YubiKey to protect repository encryption? [Y/n]

RECOVERY SHEET — store this offline, away from this machine
  ... (§6)
  [ ] I have stored this somewhere safe   (required to continue)
```

Then:

```bash
moss doctor
moss inspect
moss backup
```

`doctor` before `inspect` catches a missing Full Disk Access grant before the user's first backup silently skips half their Library.

Do not require users to understand Kopia.

---

# 32. Automation

Support non-interactive operation.

```bash
moss backup --non-interactive
```

If sensitive data requires confirmation and none is available, fail safely.

Requirements for schedulers:

- Never prompt under `--non-interactive`; fail with exit code 13 (§23) instead, or 6 for the sensitive-data gate.
- Partial success returns 9, not 0 (§23), so a scheduler notices skipped files.
- A scheduled job may be unable to unlock the credential store (locked macOS keychain, Linux job
  with no session bus). `doctor` reports whether the store is readable without a prompt. The
  documented fallback is `MOSS_REPOSITORY_PASSWORD` from a mode-0600 file that the scheduler
  sources, which the user must understand is weaker than the keychain (§6).
- Already-running returns 10 rather than queueing or failing generically.
- `--json` output is machine-parseable for every command.
- Honour `NO_COLOR` and detect non-TTY.

Support scheduled execution through the OS: cron, launchd, systemd timers, Windows Task Scheduler, CI.

**launchd note.** A launchd agent does not inherit the terminal's TCC grants (§8), so a scheduled macOS backup may skip protected paths that an interactive run captures. Document this, and make `doctor` report the difference where it can be detected.

Do not create a long-running service in v1.

---

# 33. Offline operation and privacy

A local repository must work without internet access. An S3 repository naturally requires network access.

The tool must not phone home. No telemetry, no mandatory account, no cloud control plane.

Do not collect telemetry, usage analytics, profile inventories, filenames, hostnames, credentials, or repository metadata.

Do not add update-checking unless explicitly enabled by the user. **Set `KOPIA_CHECK_FOR_UPDATES=false`** on every Kopia invocation — Kopia's update check defaults to on, and leaving it enabled would make moss phone home indirectly.

The project must be completely usable without a vendor account.

---

# 34. Logging

Normal output is concise.

```bash
moss --verbose backup
RUST_LOG=moss=trace moss backup
```

Never log repository passwords, access keys, secret keys, tokens, private keys, decrypted data, YubiKey PINs, recovery keys, or recovery codes.

**Never log the output of `kopia repository status --json`** — it has leaked storage credentials (GHSA-j5vm-7qcc-2wwg).

**Kopia writes its own log files, at `debug` level, by default.** They contain every snapshot source
path and every per-file error path. moss passes `--disable-file-logging` normally and
`--log-dir <state>/kopia-logs` (0700) only under `--verbose` (§5). Kopia also uploads a copy of its
logs into the repository (`--disable-repository-log` turns this off); leave that on, since the
repository is encrypted and the logs help diagnose a bad run from another machine.

Redact by construction: secrets should live in types whose `Debug` and `Display` implementations print a placeholder, so a stray `{:?}` cannot leak one.

---

# 35. Security requirements

Each requirement maps to a threat in §4.

- never print secrets
- never log secrets
- never store raw secrets unnecessarily
- use OS credential storage (§6)
- connect Kopia with `--no-persist-credentials` so it never writes its base64-only sidecar
- use secure memory handling for secrets where practical; zeroize buffers after use
- never put secrets in process arguments — pass the repository password via the child environment only, and document the Linux `/proc` limitation honestly (§6)
- never place secrets in shell history; provide no `--password` flag
- use restrictive permissions for generated files
- validate paths during restore using real containment primitives (§16)
- prevent path traversal
- never restore outside the intended profile without explicit user intent
- avoid symlink attacks during restore; `O_NOFOLLOW` alone is insufficient
- do not follow symlinks by default
- detect suspicious filesystem objects
- do not execute restored files
- do not automatically import restored credentials into running agents

Treat this application as security-sensitive.

---

# 36. YubiKey support

## Goal

If a YubiKey is connected, allow it to act as a hardware-backed protector for the backup encryption credential.

The YubiKey must **not** be the high-throughput encryption engine. Do not encrypt gigabytes directly with a PIV key. Use envelope encryption; the YubiKey protects a small key-wrapping operation, not bulk data.

```text
              Backup data
                   |
            Kopia encryption
                   |
           repository password
                   |
          age-encrypted envelope
                   |
            +------+------+
            |             |
        recovery       YubiKey
          code
```

## Architecture — settled, not open

Kopia **cannot** consume an externally protected repository secret. Verified: Kopia derives a scrypt KEK from a password string to unwrap its internal master key. There is no KMS interface, no pluggable KEK, and no CLI path to supply key material. The Go-library-only `BlockFormat.MasterKey` option sets the master key at creation but it remains wrapped by the password-derived KEK, so it does not help.

Therefore the envelope lives **entirely outside Kopia**:

```text
moss
  |
  +-- YubiKey ----+
  |               |
  +-- recovery ---+--> unwrap repository password --> KOPIA_PASSWORD --> Kopia
      code
```

moss stores the repository password inside an age envelope with multiple recipients, unwraps it at runtime, and passes it to Kopia via the environment (§6). Kopia never learns that a YubiKey exists.

Bulk encryption remains Kopia's responsibility.

## Protocol

Prefer the established `age` ecosystem over inventing anything. Evaluate `age`, `age-plugin-yubikey`, YubiKey PIV, PC/SC, and the Rust `yubikey` crate.

Do not invent cryptography.

YubiKey support is optional; the backup must remain fully usable without one.

**Do not claim YubiKey protection exists until end-to-end recovery has been tested** — including recovery on a machine that has never seen the YubiKey.

## Abstraction

```rust
trait HardwareKeyProvider {
    fn detect(&self) -> Result<Vec<HardwareKey>>;
    fn recipients(&self) -> Result<Vec<Recipient>>;
    fn decrypt(&self, identity: &Identity) -> Result<Secret>;
}
```

The production implementation uses age-plugin-yubikey/PIV. Keep the rest of the application unaware of PC/SC. Never implement PIV directly.

## UX

```bash
moss yubikey detect
```

```text
YubiKey detected

  Model: YubiKey 5
  Serial: ********
  PIV: available

No backup encryption identity configured.
```

```bash
moss yubikey setup
```

The setup process must: detect connected YubiKeys, verify PIV capability, let the user select or create a key, create or identify the age recipient, store **only the public recipient** in configuration, and never let the private key leave the device.

```text
YubiKey recipient: age1yubikey1...
```

## Where the envelope lives

The age-encrypted envelope must be recoverable on a machine that has never seen this configuration, so it cannot live only in the local config file.

**It cannot live inside the Kopia repository either.** The earlier draft said to store it alongside
the manifest "where it inherits repository encryption" — but on machine B the envelope is what
produces the password that opens the repository. It cannot sit behind the lock it opens.

**Store it next to the repository, outside Kopia's blob namespace**: `<prefix>/moss/envelope.age`
on S3, `<repository path>/moss/envelope.age` on a filesystem repository. It is already
age-encrypted; its only content is the wrapped password, useless without a YubiKey, so exposing the
ciphertext in the object store does not weaken the model. Kopia ignores objects it did not create.
The manifest (§27) genuinely can live inside the repository, because it is read only after connect.

Recovery code relationship: the recovery code *is* the password (§6). The envelope therefore has
one age recipient per YubiKey; the recovery code is not an age recipient but a bypass of the
envelope entirely. "Recovery code — offline" in the recipient list below is a presentation of that
fact, not a second ciphertext.

## Recovery

**Never design a system where losing the YubiKey loses the backup.**

Support multiple recipients:

```text
Backup encryption recipients:
  YubiKey        primary
  Recovery code  offline
```

Future: YubiKey A + YubiKey B + recovery passphrase + recovery key file.

The repository must be decryptable if **any** configured recovery mechanism is available.

The recovery sheet gate in §6 already enforces this — a YubiKey-only configuration is not reachable without an explicit override:

```text
WARNING

This repository is protected by your YubiKey.

No recovery recipient is configured.

If this YubiKey is lost or destroyed, the repository will become
permanently inaccessible. There is no reset and no vendor recovery.

Continue? [y/N]
```

---

# 37. Error UX

Errors explain what the user can do next.

Bad:

```text
error: subprocess failed
```

Good:

```text
Unable to connect to the S3 repository.

Repository: s3://my-bucket/rhys
Endpoint:   https://s3.example.com

Check:
  - credentials
  - bucket permissions
  - endpoint
  - network connectivity

Run `moss doctor` for a full diagnostic, or --verbose for details.
```

Never expose credentials in diagnostics. Never surface a raw Kopia error without translation — Kopia's messages assume knowledge of Kopia internals, which §1 promises the user will not need.

---

# 38. Testing

Tests must be extensive around profile discovery.

Fixtures representing macOS, Linux, and Windows profiles.

Unit tests:

- path discovery, inclusion, exclusion
- sensitive classification
- portability classification
- path translation
- restore conflict handling
- symlink handling
- configuration parsing
- JSON output and schema stability
- CLI exit codes

Fixtures for the failure modes that cause silent data loss:

- **case-collision trees** (`Makefile` + `makefile`)
- **Unicode normalization pairs** (NFC + NFD of the same name)
- **Windows-illegal names** (`aux.txt`, `notes:draft.md`, `trailing.`, `trailing `)
- **paths exceeding 260 characters**
- **TCC-denied paths** (mocked EPERM)
- **symlink escapes** (`../`, absolute, chained)
- **sparse files**

Integration tests use temporary directories and disposable local Kopia repositories, isolated from unit tests.

S3 integration tests are opt-in against local S3-compatible infrastructure (MinIO).

**The cross-platform restore test is mandatory.** §39 is the Definition of Done and is currently untested. CI must back up on one OS and restore on another against a shared repository, asserting that semantic sources land in the correct platform-specific locations with correct modes.

**The `sync-to` round-trip test is mandatory** (§21): sync a local repository to MinIO, connect to the destination independently, restore from it. This validates the one assumption `moss upload` rests on.

YubiKey tests must not require physical hardware in CI. Provide a mock `HardwareKeyProvider`. End-to-end YubiKey recovery must be tested manually before the feature ships (§36).

## Assumptions to validate during implementation

These were researched but could not be confirmed. Treat each as a task, not a fact, and record the
answer in `docs/assumptions.md`:

1. Whether a `sync-to` destination is directly usable as a normal repository (§21). **Open.** Source
   copies the format blob verbatim, which implies yes; the docs do not say so.
2. ~~Kopia's default cache path derivation~~ **Closed at revision 3**: moss passes
   `--cache-directory` itself (§5, §10); nothing to discover.
3. ~~Whether the setuid/setgid restore bug is fixed~~ **Closed at revision 3**: resolved from source,
   still dropped (§12). Keep the empirical test.
4. Whether `COM0`/`LPT0` are reserved on Windows (§12) — sanitize defensively regardless.
5. ext4 case and normalization behaviour (§12). **Dischargeable in CI** on `ubuntu-latest` along with
   the cross-platform restore test; no local Linux host is needed.
6. **New:** that Kopia creates `repository.config` with mode 0600 on Unix, and what it does on
   Windows; moss tightens the mode itself if not (§5). Verify at the pinned version.

---

# 39. Definition of done

A release is not complete until a user can, on macOS:

```bash
moss init
moss doctor
moss inspect
moss backup
```

then on Linux or Windows:

```bash
moss init          # enter recovery code from the sheet
moss snapshots
moss restore latest
```

and common configuration is restored to the correct platform-specific locations, with correct modes, and any path that could not be translated is reported rather than silently broken.

Machine B requires **only the recovery code**. No file is copied from machine A.

The user must not need to know how Kopia chunks files, how it stores objects, how S3 repositories work internally, how encryption is implemented, or where platform-specific configuration lives.

The CLI should make the correct thing easy.

---

# 40. Non-goals

Do NOT implement:

- custom backup engine, deduplication, chunking, repository format, or cryptographic primitives
- proprietary cloud service, account system, telemetry service
- web dashboard, GUI in v1, daemon in v1
- password manager, secret manager, cloud credential broker
- automatic application or package reinstallation
- full system image backup, OS disk cloning
- file-content rewriting during restore in v1 (§15 — detect and report instead)

---

# 41. MVP

1. Rust CLI
2. macOS/Linux/Windows profile detection, with TCC handling on macOS
3. semantic profile source model
4. pattern-based include/exclude rules
5. credential storage and recovery sheet (§6)
6. `doctor`
7. `inspect`
8. local Kopia repository
9. S3/S3-compatible Kopia repository
10. `backup` with partial-success reporting
11. `snapshots`
12. `restore` with safe path resolution and conflict policies
13. cross-platform path translation, with unresolvable-path reporting
14. collision detection at backup time
15. sensitive-data warnings
16. JSON output
17. dry-run
18. strong tests, including the cross-platform restore test
19. documentation

YubiKey is designed into the architecture from day one and may ship immediately after the basic repository flow is proven.

## v1 command surface

Of the §44 command reference, v1 ships: `init` (with `list-backup-endpoints`), `doctor`, `inspect`,
`backup`, `snapshots`, `restore`, `status`, `verify`, `config` (`show`, `path`), `include`,
`exclude`, `recovery show`, `prune` (wrapping `kopia snapshot expire`), `maintenance` (wrapping
`kopia maintenance run` and surfacing the owner), and the `kopia` escape hatch. `upload`, `profiles` and `yubikey *` are
Phase 2 (§42); their names are reserved and print "not available in this version" rather than
being unknown commands.

---

# 42. Phase 2

- YubiKey support and recovery recipients
- `moss upload` / `--local-only` offline workflow, once the §21 sync-to assumption is validated
- `--rewrite-paths` with real per-format parsers
- richer application-state discovery
- named profiles
- more restore selectors
- better size estimation
- repository health checks
- richer JSON schema
- shell completions

---

# 43. Phase 3

- migration mode, machine-to-machine profile cloning
- selective application migration
- package/application discovery
- secret-specific policies
- encrypted portable profile export
- multiple named repositories and destinations
- automatic repository replication
- TUI, optional GUI

Do not implement these until the core CLI is excellent.

---

# 44. Command reference

```text
moss
  init
    list-backup-endpoints
  doctor
  inspect
  backup
  upload
  snapshots
  restore
  status
  verify
  prune
  maintenance
  config
  profiles
  include
  exclude
  recovery
    show
  yubikey
    detect
    setup
    status
    remove
  kopia            (escape hatch)
```

Global flags:

```text
--config <path>
--profile <name>
--repository <url>
--json
--quiet
--verbose
--dry-run
--non-interactive
--skip-version-check
```

There is deliberately no `--password` flag (§6).

---

# 45. Documentation

Create `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, and `docs/`
(`exit-codes.md`, `json-schema.md`, `assumptions.md`, and `kopia-compat.md` holding the per-version
`--json` diffs produced by CI, §5).

README explains what the tool is, why it exists, why it uses Kopia, supported platforms, local and S3 repositories, YubiKey support, cross-platform restore, quick start, and the security model.

**README and SECURITY.md must state the known limitations plainly**, because each can cause silent data loss or a false sense of security:

- xattrs, ACLs, and hardlinks are not preserved (§12)
- case and normalization collisions are detected but cannot be losslessly restored to a case-insensitive filesystem (§12)
- macOS Full Disk Access is required for parts of the profile, and a scheduled run may capture less than an interactive one (§8, §32)
- the repository password transits the process environment, which is readable by same-user processes on Linux (§6)
- S3 keys, when configured, are stored in plaintext in Kopia's `repository.config` under moss's state directory, protected by file mode 0600 only (§5)
- setuid, setgid and sticky bits are not restored (§12)

## Distribution

Releases are built by GitHub Actions on tags `v*`, following the `planesailingio/twig` workflows:
one archive per target (`moss_<version>_<target>.tar.gz`, `.zip` on Windows) with a `.sha256`
sidecar, published as a GitHub release. The same workflow renders a binary-only Homebrew formula and
pushes it to the `planesailingio/homebrew-tools` tap as `Formula/moss.rb`. The formula declares
`depends_on "kopia"` so `brew install planesailingio/tools/moss` installs the engine too; `doctor`'s
version-range check (§5) is what protects users when homebrew-core ships a newer Kopia than the tested
range. CI installs the pinned Kopia from its release assets, never from Homebrew, so the pin holds.

Include a prominent section:

## Why not build another backup engine?

Because Kopia already solves that problem.

The project is about:

> "Remembering your digital environment, not merely your files."

---

# 46. Implementation philosophy

Prefer boring, explicit code. The project should be secure, understandable, portable, scriptable, small, and testable.

Avoid abstraction for abstraction's sake. Do not build a framework. Do not create generic plugin systems without a concrete requirement. The architecture should allow future backup engines, but do not implement an engine abstraction with five unused implementations.

Kopia is the engine. The profile model is the product.

---

# 47. Final instruction to the implementing LLM

Before writing substantial code:

1. Inspect the current repository and identify existing structure.
2. Verify the pinned Kopia version's CLI behaviour rather than trusting this document — it was accurate against Kopia master at the time of writing and Kopia has no API stability guarantee.
3. Verify current Rust crate APIs rather than relying on assumptions.
4. Work through the five open assumptions in §38 and record the answers.
5. Write an implementation plan.
6. Implement incrementally, running tests after each subsystem.
7. Keep security-sensitive operations isolated.
8. Do not invent cryptography. Do not reimplement Kopia.
9. Prefer a thin, excellent CLI over a large feature set.
10. Keep OS-specific logic behind clear interfaces.
11. Make the profile model portable across operating systems.
12. Treat restore as a first-class operation, not an afterthought.
13. When a platform behaviour is uncertain, test it on the platform rather than reasoning about it — every factual error corrected in this revision came from assuming rather than checking.

The finished product should feel like:

```text
Kopia
+
cross-platform profile intelligence
+
safe restore
+
YubiKey-backed key protection
+
excellent CLI UX
```

That is the product.
