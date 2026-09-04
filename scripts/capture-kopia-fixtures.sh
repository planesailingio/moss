#!/usr/bin/env bash
# Capture the Kopia JSON fixtures under tests/fixtures/kopia/<version>/.
#
# moss parses Kopia's `--json` output, which carries no stability guarantee
# (spec §5). The fixtures pin the shapes moss was written against; CI
# re-captures them with the pinned Kopia and diffs the *structure* (see
# scripts/ci/kopia-json-diff.sh) so a Kopia bump that changes a field name
# or drops a key fails loudly instead of silently mis-parsing.
#
# Usage:
#   scripts/capture-kopia-fixtures.sh <outdir>
#
# Produces, in <outdir>:
#   snapshot-create-clean.json           tagged snapshot, no errors
#   snapshot-create-ignored-errors.json  unreadable dir, ignore-*-errors=true
#   snapshot-create-fatal.json           unreadable dir, ignore-*-errors=false
#   snapshot-list.json                   `snapshot list --all --json` (the two
#                                        error snapshots, oldest first)
#   repository-status.json               `repository status --json`
#   maintenance-info.json                `maintenance info --json`
#
# Paths are scrubbed to /tmp/moss-fixture, host to fixture-host and user to
# fixture-user. Tags use `moss-run:01TEST moss-source:test moss-os:macos`:
# Kopia splits a tag on the first colon, so the key must not contain one.
#
# Must run as an unprivileged user: root can read a mode-000 directory, which
# would remove the error shapes the fixtures exist to capture.
set -euo pipefail

OUT="${1:?usage: capture-kopia-fixtures.sh <outdir>}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

if [ "$(id -u)" = "0" ]; then
  echo "capture-kopia-fixtures: refusing to run as root (permission-denied fixtures need an unprivileged user)" >&2
  exit 1
fi
for tool in kopia jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "capture-kopia-fixtures: $tool not found on PATH" >&2; exit 1; }
done

WORK="$(mktemp -d)"
# macOS hands out /var/folders/... which Kopia may report as /private/var/...;
# scrub both spellings.
WORK_REAL="$(cd "$WORK" && pwd -P)"
cleanup() {
  chmod -R u+rwx "$WORK" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

SRC="$WORK/src"
mkdir -p "$WORK/repo" "$WORK/cfg" "$WORK/cache" "$WORK/logs" "$SRC/sub" "$SRC/noperm"
echo hello > "$SRC/a.txt"
echo world > "$SRC/sub/b.txt"
ln -s a.txt "$SRC/link"
echo x > "$SRC/noperm/f"

export KOPIA_PASSWORD=fixture-password
export KOPIA_CHECK_FOR_UPDATES=false
K=(kopia "--config-file=$WORK/cfg/repository.config" "--log-dir=$WORK/logs")

echo "capture-kopia-fixtures: $(kopia --version | head -n1)"

"${K[@]}" repository create filesystem \
  --path="$WORK/repo" \
  --cache-directory="$WORK/cache" \
  --override-hostname=fixture-host \
  --override-username=fixture-user \
  --no-persist-credentials \
  --no-check-for-updates >/dev/null 2>&1

# Scrub volatile identity from a JSON document and pretty-print it.
scrub() {
  sed -e "s|${WORK_REAL}|/tmp/moss-fixture|g" -e "s|${WORK}|/tmp/moss-fixture|g" \
    -e "s|$(hostname)|fixture-host|g" \
    -e "s|$(id -un)|fixture-user|g" \
  | jq .
}

# 1. Unreadable subtree with ignore-*-errors=true: snapshot saved, exit 0,
#    summ.numIgnoredErrors present.
"${K[@]}" policy set "$SRC" --ignore-file-errors=true --ignore-dir-errors=true >/dev/null 2>&1
chmod 000 "$SRC/noperm"
"${K[@]}" snapshot create --json "$SRC" 2>/dev/null \
  | scrub > "$OUT/snapshot-create-ignored-errors.json"

# 2. Same tree with ignore-*-errors=false: Kopia exits 1 but still prints the
#    saved manifest with summ.numFailed=1 (spec §18).
"${K[@]}" policy set "$SRC" --ignore-file-errors=false --ignore-dir-errors=false >/dev/null 2>&1
set +e
"${K[@]}" snapshot create --json "$SRC" 2>/dev/null > "$WORK/fatal.raw"
fatal_exit=$?
set -e
if [ "$fatal_exit" -eq 0 ]; then
  echo "capture-kopia-fixtures: expected the fatal snapshot to exit non-zero (running as root?)" >&2
  exit 1
fi
scrub < "$WORK/fatal.raw" > "$OUT/snapshot-create-fatal.json"

# 3. List the two error snapshots (oldest first) before the clean one exists,
#    so the fixture carries exactly one ignored-error and one fatal entry.
"${K[@]}" snapshot list --all --json 2>/dev/null \
  | scrub > "$OUT/snapshot-list.json"

# 4. Clean, tagged snapshot with the directory readable again.
chmod 755 "$SRC/noperm"
"${K[@]}" snapshot create --json \
  --tags moss-run:01TEST --tags moss-source:test --tags moss-os:macos \
  "$SRC" 2>/dev/null \
  | scrub > "$OUT/snapshot-create-clean.json"

# 5. Repository and maintenance metadata.
"${K[@]}" repository status --json 2>/dev/null \
  | scrub > "$OUT/repository-status.json"
"${K[@]}" maintenance info --json 2>/dev/null \
  | scrub > "$OUT/maintenance-info.json"

for f in snapshot-create-clean snapshot-create-ignored-errors snapshot-create-fatal \
         snapshot-list repository-status maintenance-info; do
  jq -e . "$OUT/$f.json" >/dev/null || { echo "capture-kopia-fixtures: $f.json is not valid JSON" >&2; exit 1; }
done
echo "capture-kopia-fixtures: wrote 6 fixtures to $OUT"
