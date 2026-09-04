# Contributing

## Toolchain

- Rust **1.89 or newer**, edition 2024. `rust-version = "1.89"` is the MSRV (std file locking
  landed there) and CI runs a job at exactly that version.
- Kopia **0.23.x**. Locally, `brew install kopia` is fine. CI installs the pinned version from
  Kopia's GitHub release assets with `scripts/install-kopia.sh`, never from Homebrew, so the pin
  holds when homebrew-core moves ahead.
- `cargo fmt` and `cargo clippy` components.

Read [spec.md](spec.md) before changing behaviour; it is the source of truth and every
requirement carries a section number that the code comments cite.

## The three commands that must pass

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Run all three before opening a pull request. CI runs them on macOS, Linux and Windows.

## Tests

Unit tests live beside the code. Kopia's JSON is parsed from captured fixtures in
`tests/fixtures/kopia/<version>/`, so those tests run without Kopia installed.

`tests/cli_e2e.rs` drives the real binary against a real Kopia and a scratch filesystem
repository. It is **gated on `kopia` being on `PATH`**: each test calls `which::which("kopia")`
and returns early (printing "kopia not on PATH; skipping") when it is absent. Nothing fails
silently; if you expect the integration tests to run, check that `kopia --version` works in the
shell that runs `cargo test`.

The e2e harness redirects everything with environment variables so it never touches your real
profile or credential store: `HOME` to a temporary directory, `MOSS_HOME` for config, state and
cache, `MOSS_HOSTNAME`, `MOSS_REPOSITORY_PASSWORD` with `--credential-store env`, and `NO_COLOR`.
Use the same pattern for any new test that spawns the binary. `MOSS_KOPIA=<path>` overrides the
`PATH` lookup if you need to test against a specific Kopia build.

## Kopia fixtures and the version pin

The tested range is one constant pair in `src/backup/kopia.rs`:

```rust
pub const KOPIA_MIN: (u64, u64, u64) = (0, 23, 0);
pub const KOPIA_MAX_MINOR: (u64, u64) = (0, 23);
```

To move to a new Kopia version:

1. Install it and run `scripts/capture-kopia-fixtures.sh`, which creates a scratch repository and
   captures `snapshot create --json` (clean, with ignored errors, with fatal errors),
   `snapshot list --json`, `repository status --json` and `maintenance info --json` into
   `tests/fixtures/kopia/<version>/`. Scrub paths, host and user before committing, and check
   that `repository status` output contains no credentials.
2. Diff the new directory against the previous one. Any renamed or removed field that `src/backup/json.rs`
   reads is a breaking change for moss; fields it does not read are noise.
3. Review `json.rs` and its tests against the diff. Keep `#[serde(default)]` everywhere and never
   add `deny_unknown_fields`.
4. Widen `KOPIA_MAX_MINOR` (and `KOPIA_MIN` if the old version is dropped), update the fixture
   path in the tests, and re-verify the behaviours listed in [docs/assumptions.md](docs/assumptions.md).
5. Record the change and the diff summary in [docs/kopia-compat.md](docs/kopia-compat.md) and
   [CHANGELOG.md](CHANGELOG.md).

## Code conventions

From spec §46: prefer boring, explicit code. No frameworks, no plugin systems, no engine
abstraction with unused implementations. Kopia is the engine; the profile model is the product.

- **Secrets live in `Secret`** (`src/security/secret.rs`). Never hold a password, key or token in
  a plain `String`; never call `expose()` in a logging or formatting context. `Debug` and
  `Display` on `Secret` print `[redacted]` so a stray `{:?}` cannot leak.
- **There is no `--password` flag**, on any command, ever. A unit test in `src/cli/mod.rs` walks
  the whole clap tree and fails if one appears.
- **Every Kopia invocation goes through `KopiaContext::command`.** Do not spawn Kopia anywhere
  else, and do not pass secrets as flags; the environment allowlist and `KOPIA_PASSWORD` are the
  only channel.
- **User-facing errors follow spec §37**: say what happened and what to do next, in plain English,
  and never surface a raw Kopia message without translation. Add a `MossError` variant with a
  `#[error(...)]` message rather than formatting ad hoc strings; attach raw Kopia stderr as
  `detail` so it appears only under `--verbose`. Exit codes are mapped in one place,
  `MossError::exit_code`, and Kopia's own exit code is never propagated.
- **JSON output is a contract.** Every `--json` report goes through `Console::json_report`, which
  prefixes `schema_version`. Within a major version, add fields; never rename, remove or change
  the type of one. Kopia's JSON, by contrast, is parsed defensively and trusted for nothing.
- **OS-specific code stays behind the adapter.** `cfg(target_os = …)` belongs in `src/platform/`
  and `src/profile/{macos,linux,windows}.rs`. Elsewhere, ask the `PlatformAdapter`. Family gates
  (`cfg(unix)`, `cfg(windows)`) are acceptable where a std API differs.
- **Restore is security-sensitive.** Changes under `src/restore/contain/`, `src/credentials/` and
  `src/backup/kopia.rs` need a second reviewer. Validate and open in one operation; never
  re-resolve a path string after checking it.
- **Do not invent paths.** Every default path in a platform adapter is verified present on that
  OS, cited to a platform authority, or explicitly marked unvalidated (spec §8).
- **Configuration holds no secrets** and uses `deny_unknown_fields`, so a typo is an error rather
  than a silently ignored key.
- British English in documentation and messages; no marketing tone.

## Commits and pull requests

- Commit messages: a short imperative summary line, a blank line, then a body that says what
  changed and why, citing spec sections where relevant.
- Commits authored with an AI assistant carry a `Co-Authored-By:` trailer naming the model, for
  example `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Human co-authors use the
  same trailer with their own name and email.
- Do not modify `spec.md` in the same commit as code unless the code change is what the spec
  change describes. Renumbering spec sections requires updating every `§n` reference;
  `grep -o '§[0-9]*' spec.md | sort -u` against the heading list is the check.
- Pull requests should say which of the three commands you ran and whether the e2e tests ran or
  were skipped.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Email rather than a public issue for anything that could expose a
repository or credentials.
