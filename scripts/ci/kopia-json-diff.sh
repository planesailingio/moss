#!/usr/bin/env bash
# Compare the *shape* of two directories of Kopia JSON fixtures.
#
# Values such as snapshot ids, object ids, timestamps, uids, volume sizes and
# maintenance run times legitimately differ between captures, so a plain
# `diff -r` is always noisy. Instead each document is reduced to the sorted
# list of its JSON paths plus the type of the value at each path
# ("rootEntry.summ.numIgnoredErrors number"). Two captures with the same
# keys, nesting, array lengths and value types compare equal; a renamed,
# added or removed field, or a string that became a number, does not.
#
# Usage:
#   scripts/ci/kopia-json-diff.sh <expected-dir> <actual-dir>
#
# Exits non-zero (with a unified diff of the shapes) when they differ.
set -euo pipefail

EXPECTED="${1:?usage: kopia-json-diff.sh <expected-dir> <actual-dir>}"
ACTUAL="${2:?usage: kopia-json-diff.sh <expected-dir> <actual-dir>}"

command -v jq >/dev/null 2>&1 || { echo "kopia-json-diff: jq not found on PATH" >&2; exit 1; }

shape() {
  jq -r '. as $root
         | [paths]
         | map(. as $p | ($p | map(tostring) | join(".")) + " " + ($root | getpath($p) | type))
         | .[]' "$1" | LC_ALL=C sort
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/expected" "$WORK/actual"

status=0
for side in expected actual; do
  dir="$EXPECTED"; [ "$side" = actual ] && dir="$ACTUAL"
  for f in "$dir"/*.json; do
    [ -e "$f" ] || continue
    shape "$f" > "$WORK/$side/$(basename "$f" .json).shape"
  done
done

if ! diff -ru "$WORK/expected" "$WORK/actual"; then
  status=1
  echo >&2
  echo "kopia-json-diff: JSON shapes differ between $EXPECTED and $ACTUAL" >&2
  echo "kopia-json-diff: if the pinned Kopia changed its output, update the parsers, then" >&2
  echo "kopia-json-diff: re-capture with scripts/capture-kopia-fixtures.sh and commit the result" >&2
else
  echo "kopia-json-diff: shapes match ($(find "$WORK/expected" -name '*.shape' | wc -l | tr -d ' ') documents)"
fi
exit $status
