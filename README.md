# moss

Cross-platform user-profile backup and restore, on top of [Kopia](https://kopia.io).

moss discovers your profile on macOS, Linux or Windows, shows you what it would back up before it
does, backs it up with Kopia, and restores it safely onto another machine or operating system.
Kopia does the storage, encryption, deduplication and retention. moss does everything Kopia does
not know about: which directories make up a profile, what is sensitive, what is a cache, where
`~/Movies` becomes `~/Videos`, and how to put files back without being tricked into writing
outside your home directory.

> "Remembering your digital environment, not merely your files."

## Why not build another backup engine?

Because Kopia already solves that problem. It is content-addressable, deduplicating, encrypted at
rest, supports local and S3-compatible storage, and handles retention and maintenance. There is no
Rust binding and no stable library API, so moss shells out to the `kopia` CLI, pins the tested
version range, and parses its JSON defensively. moss never implements a repository format,
chunker, or cryptographic primitive of its own.

The product is the layer above the engine: profile discovery, portability, safety and the CLI.

## Supported platforms

| OS | Profile discovery | Credential store | Restore containment |
|---|---|---|---|
| macOS | Apple's user template directories; `~/Library` allowlist; TCC-aware | Keychain | component-by-component `openat` with `O_NOFOLLOW` |
| Linux | XDG user directories (localised names resolved) and base directories | Secret Service | `openat2` with `RESOLVE_IN_ROOT` and `RESOLVE_NO_SYMLINKS` |
| Windows | `SHGetKnownFolderPath` known folders (never hardcoded paths) | Credential Manager | `NtCreateFile` opens relative to the verified parent handle |

Kopia 0.23.0 to 0.23.x is the tested engine range. `moss doctor` reports the installed version;
`--skip-version-check` proceeds outside the range at your own risk.

## Install

Homebrew (macOS and Linux). The formula declares Kopia as a dependency, so this installs both:

```bash
brew install planesailingio/tools/moss
```

GitHub releases: one archive per target (`moss_<version>_<target>.tar.gz`, `.zip` on Windows) with
a `.sha256` sidecar, for `x86_64-apple-darwin`, `aarch64-apple-darwin`,
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` and `x86_64-pc-windows-msvc`. Install Kopia
separately from <https://kopia.io/docs/installation/>.

From source (Rust 1.89 or newer):

```bash
cargo install --path .
```

## Quick start

On the first machine:

```bash
moss init --repository /Volumes/Backups/profile   # or s3://bucket/prefix, see below
moss doctor        # Kopia, repository, credential store, Full Disk Access, scan index
moss inspect       # what will be backed up, excluded, and skipped, with sizes
moss backup
```

`init` generates a 256-bit repository password, stores it in the OS credential store, discovers
your profile and writes the source list to `config.yaml`, then prints a **recovery sheet**. The
first backup refuses to run until you confirm you have stored the sheet.

On another machine, of any supported OS:

```bash
moss init --repository /Volumes/Backups/profile   # same location; prompts for the recovery code
moss snapshots
moss restore latest
```

The 24-word recovery code is the only thing you need. No file is copied from the first machine.

## Repositories

moss supports one repository per configuration: a local filesystem path or an S3-compatible bucket.

```bash
moss init --repository /mnt/backups/rhys
moss init --repository s3://bucket/rhys
moss init --repository s3://bucket/rhys --endpoint https://s3.eu-west-1.wasabisys.com --region eu-west-1
```

For S3, `init` takes the access key and secret from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
(and `AWS_SESSION_TOKEN`) in its environment, or prompts for them; leave the prompt empty to use an
IAM or instance role. The keys are passed to Kopia once, in the child environment, and Kopia
persists them in its own config file under moss's state directory (mode 0600). See
[SECURITY.md](SECURITY.md).

To find an endpoint without reading vendor documentation:

```bash
moss init list-backup-endpoints
moss init list-backup-endpoints --name wasabi
```

The table is static and in-tree (AWS, Wasabi, Cloudflare R2, Backblaze B2, DigitalOcean Spaces,
Scaleway, Hetzner, Akamai/Linode, Storj, Vultr, MinIO). moss never fetches anything at runtime.

An `http://` endpoint (a local MinIO, say) makes moss pass `--disable-tls` to Kopia.

## The recovery sheet

```text
RECOVERY SHEET — store this offline, away from this machine

  Repository:  s3://bucket/rhys
  Endpoint:    https://s3.example.com
  Created:     2026-09-04
  Profile:     rhys
  moss:        0.1.0     Kopia: 0.23.1

  Recovery code (24 words, in this order):
     1. abandon     2. ability     3. able        4. about
     ...
    21. action     22. actor      23. actress    24. actual

  Without this code, and without access to this machine's
  keychain, the repository CANNOT be recovered. There is no
  reset, no vendor, and no backdoor.
```

The 24 words *are* the repository password, rendered as a BIP39 mnemonic. `moss recovery show`
prints the sheet again (it reads the credential store). `moss init --print` prints it without the
acknowledgement prompt. Under `--non-interactive`, `init` requires `--recovery-acknowledged`,
which means the caller has taken responsibility for storing it.

## What gets backed up

`moss inspect` shows the selection by source and category, sensitive-file counts (by path and
name only; contents are never read), excluded caches and build artefacts, anything that could not
be read (with the reason), and recorded filename collisions. It works offline and never touches
the repository unless `--estimate` is given.

Defaults are conservative: standard user directories, dotfiles such as `~/.ssh`, `~/.aws`,
`~/.gnupg`, `~/.kube`, `~/.docker`, `~/.gitconfig` and shell configuration, `~/.config`,
`~/Library/Preferences` and known tool state such as k9s (`~/Library/Application Support/k9s`
on macOS, `~/.config/k9s` elsewhere; one `k9s` id, so a restore lands in the right place). Caches, `node_modules/`, `target/`, virtualenvs, cloud-drive roots,
Docker Desktop VM images and moss's and Kopia's own state are excluded by gitignore-style
patterns applied during the walk. `~/Downloads` and macOS `~/Library/Application Support` are
opt-in: `inspect` lists them and `moss include` turns them on. `~/Library/Containers` and
`Group Containers` are opt-in via `backup.include_containers`.

```bash
moss include ~/Projects
moss include ~/Downloads         # opt-in source, by path
moss include "~/Library/Application Support/Sublime Text"   # one app from an opt-in parent
moss exclude 'node_modules/'     # any depth
moss exclude ~/Movies
```

## Cross-platform restore

Every source has a semantic id (`ssh`, `documents`, `video`, ...) that is the same on every OS;
only the path differs. Restore maps ids onto the destination platform and the destination user's
home, so `/Users/rhys/.ssh` from a Mac lands in `/home/revans/.ssh` on Linux, and `~/Movies` lands
in `~/Videos`.

```bash
moss restore latest
moss restore latest --dry-run
moss restore latest --category credentials
moss restore latest --source ssh
moss restore 01M1P83H --from-host macbook
moss restore latest --conflict backup
moss restore latest --to /tmp/inspect-first
```

- The selector is `latest` (default) or a run-id prefix; `--from-host` picks a source machine.
- `--conflict skip|overwrite|backup|interactive`. Default: interactive on a terminal, `skip`
  otherwise. Interactive offers skip, overwrite, backup the existing file, or diff.
- Restore is two-stage: Kopia restores into a moss-owned staging directory, then moss places each
  file with OS containment primitives, so a tampered repository cannot write outside the target.
- Filename collisions recorded at backup time (`Makefile` and `makefile`; NFC and NFD forms of the
  same name) fail loudly on a case- or normalisation-insensitive destination unless
  `--rename-collisions` is given, which renames deterministically (`name.1`, `name.2`).
- A restore journal records each write before it happens. After an interruption, `--resume`
  continues and `--rollback` undoes.
- Nothing restored is executed, and credentials are never imported into `ssh-agent` or
  `gpg-agent`.

### The path report

Configuration files contain absolute paths (`IdentityFile /Users/rhys/.ssh/id_ed25519` in
`~/.ssh/config`; `client-certificate` in `~/.kube/config`; `includeIf` in `~/.gitconfig`; `source`
lines in shell rc files). moss does not rewrite file contents; a wrong rewrite of `~/.kube/config`
is worse than a stale one. Instead, after a cross-platform restore it reports every embedded path
that will not resolve on this machine, by file and line, with the likely new path, so you can fix
them deliberately.

## Scheduling

moss has no daemon. Run it from cron, launchd, systemd timers, Task Scheduler or CI with
`--non-interactive`, which turns every prompt into an exit code instead of a hang:

```cron
15 2 * * *  moss backup --non-interactive --yes --quiet
```

| Exit | Meaning | Scheduler action |
|---|---|---|
| 0 | complete | nothing |
| 9 | partial: some paths were skipped | alert; run `moss inspect --all` to see which |
| 10 | another moss holds the lock | retry later; do not queue |
| 13 | a prompt was needed (recovery sheet, guardrail, conflict) | fix interactively |

The full table is in [docs/exit-codes.md](docs/exit-codes.md).

A scheduled job may be unable to unlock the credential store (locked macOS keychain, Linux job with
no session bus). `moss doctor` reports whether the store is readable without a prompt. The fallback
is `MOSS_REPOSITORY_PASSWORD`, read from a mode-0600 file that the scheduler sources; it takes
precedence over the credential store on every platform and is weaker than the keychain, because it
sits on disk in plaintext.

On macOS, a launchd job does not inherit your terminal's Full Disk Access grant, so a scheduled
backup may capture less than an interactive one. `doctor` warns when it can detect this.

## JSON output

Every information-oriented command accepts `--json` and emits one object with `schema_version: 1`
at the top: `inspect`, `backup`, `snapshots`, `status`, `doctor`, `verify`, `init`, `config show`,
and `init list-backup-endpoints`. Errors under `--json` are also objects, with `exit_code` and
`exit_code_name`. Unlike Kopia's JSON, moss's JSON is a contract: additive changes only within a
major version. See [docs/json-schema.md](docs/json-schema.md).

## Security model in brief

- The repository password is generated by moss, stored only in the OS credential store, and shown
  once as the recovery sheet. There is no `--password` flag; the password reaches Kopia through
  the child process environment only and never through arguments, files, logs or `--verbose`.
- Kopia is always run with `--no-persist-credentials`, so its own base64 password sidecar is never
  written, and with `KOPIA_CHECK_FOR_UPDATES=false`, so nothing phones home. moss has no
  telemetry and no account.
- Restore treats the repository as untrusted: the manifest is validated, every write goes through
  a containment primitive, symlinks are recreated as links and never followed, and restored files
  are never executed.
- Every Kopia invocation gets an explicit environment allowlist, moss's own Kopia config file,
  and file logging disabled unless `--verbose`.

Full detail, including the threat model and how to report a vulnerability, is in
[SECURITY.md](SECURITY.md).

## Known limitations

Each of these can cause silent data loss or a false sense of security, so they are stated here
rather than discovered later.

- **Extended attributes, ACLs and hardlinks are not preserved.** Kopia does not implement xattrs,
  POSIX ACLs, Windows security descriptors, Linux capabilities or SELinux labels; hardlinks are
  restored as separate files. macOS resource forks, Finder flags and quarantine flags are xattrs
  and are lost. `~/Public/Drop Box` relies on an inherited ACL and will not work after a restore.
- **setuid, setgid and sticky bits are dropped on restore.** Kopia applies permission bits only.
- **Case and normalisation collisions are detected but not losslessly restorable** to a
  case-insensitive (APFS, NTFS) or normalisation-insensitive (APFS) filesystem. moss records them
  in the manifest at backup time and refuses at restore unless you opt into renaming.
- **macOS Full Disk Access is required** for parts of the profile (`~/Library/Mail`, Safari,
  Messages, and others). Grant it to your terminal application, not to `moss`. A scheduled run
  may capture less than an interactive one. Anything skipped is listed by `inspect` and `backup`,
  and the run exits 9.
- **The repository password transits the child process environment.** Kopia offers no other
  non-interactive mechanism. On Linux, other processes running as the same user can read it from
  `/proc/<pid>/environ` while Kopia runs.
- **S3 keys are stored in plaintext** by Kopia in its repository config file under moss's state
  directory, protected by file mode 0600 and whatever disk encryption you have. This is the same
  posture as `~/.aws/credentials`. `doctor` checks the mode on every run.

## Commands

| Command | Purpose |
|---|---|
| `init` | Configure a repository, store the password, discover sources, print the recovery sheet. `init list-backup-endpoints` lists S3 vendors. |
| `doctor` | Check Kopia, repository, credential store, recovery acknowledgement, Full Disk Access, state directory, scan index. Non-zero if any check fails. |
| `inspect` | Show the selection with sizes, sensitive counts, exclusions, skipped paths and collisions. `--rescan`, `--measure-excluded`, `--estimate`, `--all`. |
| `backup` | Back up the profile. `--rescan`, `--yes`. Exit 9 if anything was skipped. |
| `snapshots` | List runs with a STATUS column. `--host`, `--latest`. |
| `restore` | Restore a run onto this machine (see above). |
| `status` | Repository, credential source, maintenance owner, latest run per host. |
| `verify` | Verify a run's snapshots (`--files-percent`); `--check-modes` checks credential file modes. |
| `prune` | Report snapshots outside retention; `--delete` (with `--yes`) removes them. |
| `maintenance` | Run Kopia maintenance (`--full`); warns if this machine is not the owner. |
| `config` | `show` the effective configuration, or print its `path`. |
| `include`, `exclude` | Add a path, or a path or gitignore-style pattern, to the configuration. |
| `recovery show` | Print the recovery sheet again. |
| `kopia ...` | Escape hatch: run Kopia against the moss repository with moss's config and credentials. |
| `upload`, `profiles`, `yubikey setup`/`remove` | Reserved for Phase 2; print "not available in this version". |

Global flags: `--config`, `--profile` (`default` only), `--repository`, `--json`, `--quiet`,
`--verbose`, `--dry-run`, `--non-interactive`, `--skip-version-check`.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): module map, data flow, where files live, Kopia process hygiene.
- [SECURITY.md](SECURITY.md): threat model, controls, caveats, reporting.
- [CONTRIBUTING.md](CONTRIBUTING.md): toolchain, tests, fixtures, conventions.
- [CHANGELOG.md](CHANGELOG.md)
- [docs/exit-codes.md](docs/exit-codes.md), [docs/json-schema.md](docs/json-schema.md),
  [docs/assumptions.md](docs/assumptions.md), [docs/kopia-compat.md](docs/kopia-compat.md)
- [spec.md](spec.md): the full specification.

## Licence

MIT. See [LICENSE](LICENSE).
