# Assumptions and verified Kopia facts

Spec §38 lists things that were researched but could not be confirmed from documentation. Each is
a task, not a fact; this file records the answer as it is found. Kopia has no API stability
guarantee, so every entry names the version it was checked against.

## The six items from spec §38

| # | Assumption | Status | Evidence and consequence |
|---|---|---|---|
| 1 | A `kopia repository sync-to` destination is directly usable as a normal repository (§21). | **Open.** | The source copies the format blob verbatim, including `uniqueID`, which implies the same password opens it and `repository connect` works. The docs do not say so. `moss upload` (Phase 2) rests entirely on this; it ships only after an integration test syncs a local repository to MinIO, connects to the destination independently, and restores from it. |
| 2 | Kopia's default cache-path derivation needs to be discovered so moss can exclude it. | **Closed** at spec revision 3. | moss passes `--cache-directory=<cache>/kopia` on create/connect and `--config-file` on every call, so the Kopia state moss creates lives under moss's own directories and is excluded by construction. `repository status --json` has no cache-directory field (verified 0.23.1), and it is the one command whose output is never logged, so discovery would have been the wrong approach anyway. |
| 3 | The setuid/setgid restore bug (kopia#544) has been fixed. | **Closed**, from source: still dropped. | `snapshot/restore/local_fs_output.go` applies `Mode() & ModBits & ^modclear`, permission bits only. kopia#544 and kopia#3884 remain open; the hardlink PR kopia#4460 is unmerged. Documented in README and SECURITY.md. An empirical test at the pinned version is **pending** so a future Kopia change is noticed. |
| 4 | `COM0` and `LPT0` are reserved device names on Windows (§12). | **Open**; sanitised defensively. | Microsoft documents `COM1`–`COM9`, `LPT1`–`LPT9` and the superscript variants; `COM0`/`LPT0` are not in the list. `scan/collisions.rs` treats them as reserved regardless, so a file named `com0.txt` is recorded as a `windows_illegal` collision. The cost of a false positive is one report line; the cost of a false negative is a failed restore. |
| 5 | ext4 is case- and normalisation-sensitive, so a Linux tree can hold pairs that collide on APFS (§12). | **Dischargeable in CI** on `ubuntu-latest`. | The cross-platform restore job (macOS backs up, Ubuntu and Windows restore) exercises this alongside the collision fixtures. No local Linux host is needed. `scan/collisions.rs::probe_insensitive` is the runtime check on the destination. |
| 6 | Kopia creates `repository.config` with mode 0600 on Unix (and what it does on Windows). | **Answered for macOS**, 2026-09-04. | Kopia 0.23.1 creates the config file `-rw-------` (0600) on macOS; `ls -la` on `<state>/kopia/` after `moss init` showed `-rw-------` for `<id>.config` and its `.mlock` sibling. moss re-tightens to 0600 after every create/connect anyway (`paths::make_private_file`), the e2e test asserts it, and `doctor` checks it on every run. Windows behaviour is unverified; moss's tightening is a no-op there and the file relies on the profile directory's ACL. |

## Kopia facts verified on 2026-09-04 against 0.23.1

These were checked by running the CLI, not by reading the docs. Each shaped the implementation.

| Fact | Consequence in moss |
|---|---|
| `--tags` splits each value on the **first colon** and **rejects duplicate keys**. A key containing a colon (`moss:run`) is therefore impossible. | Tag keys are `moss-run`, `moss-profile`, `moss-source`, `moss-os`, `moss-schema` (`backup/tags.rs`). Values have colons and whitespace replaced with `_`. `snapshot list --json` returns them as `tag:moss-run` etc. |
| `policy set --clear-ignore` combined with `--add-ignore` **in one call clears after adding**, leaving no rules. | `repository.rs::set_source_policy` makes two calls: `--clear-ignore` alone, then `--ignore-file-errors=true --ignore-dir-errors=true --ignore-unknown-types=true --add-ignore=…`. |
| gitignore-style ignore rules, including `**` and leading-`/` anchors, work in Kopia policies. | moss's exclusion rules are translated per source into `--add-ignore` entries (`rules::kopia_ignore_rules_for`), so the upload excludes exactly what the scan excluded; the e2e test asserts `node_modules` never reaches the repository. |
| `snapshot create --json` has **no `stats` block**; the counts are under `rootEntry.summ` (`size`, `files`, `symlinks`, `dirs`, `numFailed`, `numIgnoredErrors`, `errors[]`). `snapshot list --json` does carry `stats`. | `json.rs` reads `rootEntry.summ` first and falls back to `stats`. `numFailed` absent is an error, never zero; `numIgnoredErrors` is `omitempty` and absent means zero. The fixture `snapshot-create-clean.json` asserts `stats` is `None`. |
| Fatal errors make `snapshot create` **exit 1 but still emit the manifest JSON** (the snapshot has already been saved). Ignored errors exit 0. | `repository.rs::snapshot_create` parses stdout regardless of exit status and fails only if no manifest was produced. Completeness comes from the counts, never the exit code. Fixture: `snapshot-create-fatal.json`. |
| `repository status --json` has fields `configFile`, `uniqueIDHex`, `clientOptions{hostname,username}`, and a `storage.config` block that includes the storage location. No cache-directory field. | Parsed for `uniqueIDHex` (shown truncated by `status`) and discarded. Never logged. |
| `maintenance info --json` has `owner`, `quick`, `full`, `schedule{nextFullMaintenance,nextQuickMaintenance}`. | `status` surfaces the owner and next full maintenance; `maintenance` warns if this machine is not the owner. |

## Still to verify

- Item 3's empirical setuid test at the pinned version.
- Item 6 on Windows.
- Item 1 end to end against MinIO (gates `moss upload`).
- `snapshot restore` behaviour with `--write-sparse-files` on a genuinely sparse source such as
  `Docker.raw` (excluded by default, so low priority).
