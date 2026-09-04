# JSON output

Every information-oriented command accepts `--json`. The output is one pretty-printed JSON object
on stdout with `schema_version` as its first key. Human progress and informational lines are
suppressed under `--json`; warnings and error messages still go to stderr.

**The contract:** `schema_version` is `1`. Within a major version of moss, fields are added, never
renamed, removed or changed in type. Consumers must ignore unknown fields. This is the opposite of
Kopia's `--json`, which moss parses defensively and does not expose.

Sizes are bytes. Timestamps are RFC 3339 in UTC. Enum values are `snake_case` unless noted.
Examples below were captured from moss 0.1.0 against Kopia 0.23.1; long paths are shortened.

## Errors

When a command fails under `--json`, the error object is printed to stdout and the same message to
stderr, and the process exits with `exit_code`.

```json
{
  "schema_version": 1,
  "error": "Unable to reach the repository.\n\nRepository: /nonexistent/xyz\n\nCheck:\n  - ...",
  "exit_code": 3,
  "exit_code_name": "repository unavailable"
}
```

`exit_code_name` is the description from [exit-codes.md](exit-codes.md). `error` is the
user-facing message; do not parse it.

## `inspect --json`

```json
{
  "schema_version": 1,
  "profile": { "user": "rhys", "os": "macOS", "home": "/Users/rhys", "identity": "rhys" },
  "included": [
    { "id": "ssh", "path": "/Users/rhys/.ssh", "home_relative": "~/.ssh",
      "category": "credentials", "sensitive": true,
      "size": 36, "files": 1, "dirs": 1, "skipped": 0 }
  ],
  "included_by_category": { "Credentials": 36, "Personal data": 6 },
  "opt_in": [ { "id": "containers", "path": "~/Library/Containers", "reason": "..." } ],
  "sensitive": { "SSH": 1 },
  "excluded": { "build_artifact": { "entries": 1, "size": 0, "measured": false } },
  "skipped": [ { "path": "~/Library/Mail", "reason": "permission_denied", "errno": "EPERM" } ],
  "collisions": [ { "kind": "case", "paths": ["~/src/Makefile", "~/src/makefile"] } ],
  "guardrails": [ { "message": "..." } ],
  "estimate": { "raw_bytes": 60, "files": 3, "repository_snapshots": 4 },
  "scan_index_age_seconds": null,
  "rescanned": true
}
```

| Field | Notes |
|---|---|
| `profile.os` | display name: `macOS`, `Linux`, `Windows` |
| `included[].category` | `personal_data`, `configuration`, `credentials`, `development`, `application_state`, `system_integration`, `cache`, `generated`, `unknown` |
| `included_by_category`, `sensitive` | keyed by display name (`Personal data`, `SSH`); values are bytes and file counts respectively |
| `excluded` | keyed by kind: `cache`, `build_artifact`, `temporary`, `cloud_drive`, `own_state`, `user_rule`. `size` is meaningful only when `measured` is true (`--measure-excluded`) |
| `skipped[]`, `collisions[]` | same objects as in the manifest, below |
| `estimate.repository_snapshots` | present only with `--estimate` |
| `scan_index_age_seconds` | `null` when there was no index before this run |

## `backup --json`

```json
{
  "schema_version": 1,
  "run_id": "01M1P83HGD231TW51JN97Q7WAV",
  "complete": true,
  "snapshots": [
    { "source": "ssh", "snapshot_id": "0d22ca2a9d77462b06f7ddb1bb1c5820",
      "fatal_errors": 0, "ignored_errors": 0, "size": 36, "files": 1 }
  ],
  "skipped": [],
  "collisions": 0,
  "total_size": 60,
  "total_files": 3,
  "manifest_path": "/Users/rhys/Library/Application Support/moss/manifests/01M1P83H.../moss-manifest.json",
  "unexpected_errors": 0
}
```

`complete` is `false` (and the exit code 9) when `skipped` is non-empty or any snapshot reported
errors. `unexpected_errors` counts errors Kopia reported that the scan did not predict; their paths
are folded into `skipped` with reason `backup_error`. `collisions` is a count here; the full list
is in the manifest.

With `--dry-run`, the shape is instead `{ "schema_version", "dry_run": true, "run_id",
"repository", "manifest": <manifest object>, "excluded": <as inspect> }` and nothing is written to
the repository.

## `snapshots --json`

```json
{
  "schema_version": 1,
  "runs": [
    {
      "id": "01M1P83HGD231TW51JN97Q7WAV",
      "started": "2026-09-04T13:00:40.710582Z",
      "host": "macbook", "user": "rhys", "os": "macos", "profile": "rhys",
      "size": 60, "files": 3,
      "sources": ["git", "ssh", "documents"],
      "snapshot_ids": ["37fd...", "0d22...", "f169..."],
      "manifest_snapshot_id": "d741...",
      "fatal_errors": 0, "ignored_errors": 0,
      "status": "complete"
    }
  ]
}
```

Runs are newest first. `status` is `complete`, `partial (n skipped)` or
`incomplete (no manifest)`; test `fatal_errors + ignored_errors == 0 && manifest_snapshot_id != null`
rather than parsing the string. `os` is the tag value (`macos`, `linux`, `windows`). `size` and
`files` exclude the manifest snapshot. `--host` and `--latest` filter the array.

## `status --json`

```json
{
  "schema_version": 1,
  "repository": "s3://bucket/rhys",
  "repository_id": "3ecc2316a07cdece",
  "kopia_unique_id": "a8ab853d...",
  "credentials": "keyring",
  "maintenance_owner": "rhys@macbook",
  "next_full_maintenance": "2026-09-05T13:00:39.509215Z",
  "runs": 1,
  "latest_by_host": [
    { "host": "macbook", "os": "macos", "user": "rhys", "run": "01M1P83H...",
      "started": "2026-09-04T13:00:40.710582Z", "status": "complete" }
  ]
}
```

`credentials` is `keyring` or `environment`. `maintenance_owner` and `next_full_maintenance` are
`null` if `kopia maintenance info` failed.

## `doctor --json`

```json
{
  "schema_version": 1,
  "ok": true,
  "checks": [
    { "section": "Kopia", "name": "version", "status": "ok",
      "detail": "0.23.1  (tested: 0.23.0 – 0.23.x)" },
    { "section": "Platform", "name": "full disk access", "status": "fail",
      "detail": "NOT granted (~/Library/Mail is EPERM)",
      "help": "~/Library/Mail and other protected paths will be skipped.\n..." }
  ]
}
```

`status` is `ok`, `warn`, `fail` or `skip`. `ok` is true when no check is `fail`; the exit code is
0 or 1 accordingly. `help` is present only when there is advice. Sections today are `Kopia`,
`Repository`, `Platform`, `YubiKey`, `Scan index`; check names are stable identifiers within a
section (`found`, `version`, `credentials`, `credential store`, `reachable`, `kopia config`,
`recovery`, `full disk access`, `session`, `state directory`, `status`, `fresh`/`stale`/`absent`).

## `init --json`

```json
{
  "schema_version": 1,
  "repository": "s3://bucket/rhys",
  "repository_id": "3ecc2316a07cdece",
  "identity": "rhys",
  "sources": 3,
  "recovery_acknowledged": true,
  "config": "/Users/rhys/Library/Application Support/moss/config.yaml"
}
```

Note: when `init` shows the recovery sheet (first run, or `--print`), the sheet is printed as
plain text on stdout **before** the JSON object, because the sheet is deliberately never encoded
as JSON. Consumers should take the last JSON document on stdout, or run `init` once interactively
and use `--json` on subsequent commands. `init list-backup-endpoints --json` returns
`{ "schema_version": 1, "endpoints": [ { "name", "vendor", "pattern", "example", "regions", "notes" } ] }`.

## Other commands

| Command | Shape |
|---|---|
| `verify --json` | `{ "run", "snapshots_verified", "files_percent", "mode_problems": [string] }`; exit 8 if `mode_problems` is non-empty |
| `prune --json` | `{ "deleted": bool, "kopia_output": string }` |
| `maintenance --json` | `{ "full": bool, "owner": string, "kopia_output": string }` |
| `config show --json` | the configuration file as JSON, same keys as the YAML, plus `schema_version` |
| `yubikey detect --json` | `{ "detected": n, "configured": false, "available": false }` in v1 |
| `recovery show --json` | refused with exit 2; the sheet is plain text only |

## The manifest

Written to `<state>/manifests/<run>/moss-manifest.json` and snapshotted with the run as source
`manifest`, so it inherits repository encryption and integrity. Restore fetches it first and
validates `schema_version` (must be ≤ 1), `run_id` and `sources` before reading anything else;
every path in it is still treated as untrusted. It never contains secret contents; paths are
home-relative (`~/.ssh`) unless outside the home directory.

```json
{
  "schema_version": 1,
  "run_id": "01M1P83HGD231TW51JN97Q7WAV",
  "profile": "default",
  "profile_identity": "rhys",
  "source_os": "macos",
  "source_host": "macbook",
  "source_user": "rhys",
  "source_home": "/Users/rhys",
  "tool_version": "0.1.0",
  "kopia_version": "0.23.1",
  "created_at": "2026-09-04T13:00:39.347776Z",
  "categories": ["configuration", "credentials", "personal_data"],
  "sources": [
    { "id": "ssh", "category": "credentials", "portable": "Portable", "path": "~/.ssh",
      "sensitive": true, "size": 36, "files": 1,
      "snapshot_id": "0d22ca2a9d77462b06f7ddb1bb1c5820",
      "fatal_errors": 0, "ignored_errors": 0 }
  ],
  "skipped": [
    { "path": "~/Library/Mail", "reason": "permission_denied", "errno": "EPERM" }
  ],
  "collisions": [
    { "kind": "case", "paths": ["~/src/Makefile", "~/src/makefile"] },
    { "kind": "normalization", "paths": ["~/café.txt", "~/café.txt"] },
    { "kind": "windows_illegal", "path": "~/notes:draft.md", "problem": "contains ':'" },
    { "kind": "path_too_long", "path": "~/a/b/...", "length": 271 }
  ],
  "sensitive_counts": [ { "kind": "ssh_private_key", "files": 1 } ],
  "totals": { "size": 60, "files": 3, "dirs": 3, "excluded_size": 0 }
}
```

| Field | Values |
|---|---|
| `source_os` | `macos`, `linux`, `windows` |
| `source_home` | absolute; kept so restore can recognise embedded paths from the source machine |
| `sources[].id` | a built-in semantic id (`user_home`, `documents`, `desktop`, `downloads`, `pictures`, `video`, `music`, `public`, `aws`, `ssh`, `gnupg`, `kubernetes`, `docker`, `git`, `shell`, and others such as `config`, `app_support`), or `custom:<home-relative path>` for user includes |
| `sources[].portable` | PascalCase: `Portable`, `PortableWithPathTranslation`, `PlatformSpecific`, `MachineSpecific`, `Unknown` |
| `sources[].snapshot_id` | absent until Kopia has run (dry-run manifests have none) |
| `skipped[].reason` | `permission_denied` (EPERM: TCC, SIP, Data Vault), `access_denied` (EACCES: mode bits or ACL), `not_found`, `io_error`, `backup_error` (Kopia reported it, moss's scan did not predict it), `symlink_unsupported` |
| `skipped[].errno`, `skipped[].detail` | optional strings |
| `collisions[].kind` | `case`, `normalization` (both with `paths`), `windows_illegal` (`path`, `problem`), `path_too_long` (`path`, `length`) |
| `sensitive_counts[].kind` | `ssh_private_key`, `aws_credentials`, `gpg_private_key`, `kubernetes_credentials`, `docker_credentials`, `cloud_provider_credentials`, `git_credentials`, `password_manager_export`, `api_token`, `dot_env`, `credential_cache`, `tls_private_key` |

A run is complete when `skipped` is empty and every source has zero `fatal_errors` and
`ignored_errors`.
