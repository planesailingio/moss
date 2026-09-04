#!/usr/bin/env bash
# Backup half of the cross-platform restore job (spec §39): build a fixture
# home, point moss at it, initialise a filesystem repository and back the
# home up. The repository and MOSS_HOME are tarred into one artifact that
# cross-platform-restore.sh consumes on another OS.
#
# CLI contract this script is written against (Milestone 3/4):
#   MOSS_HOME=<dir> MOSS_REPOSITORY_PASSWORD=<pw> \
#     moss init --repository <path> --credential-store env --identity ci \
#               --non-interactive --recovery-acknowledged
#   moss backup --non-interactive --json
#   moss snapshots --json
#
# Usage: scripts/ci/cross-platform-backup.sh   (from the repository root)
# Env:   XPLAT_ROOT, XPLAT_ARTIFACT, MOSS_BIN, MOSS_REPOSITORY_PASSWORD
set -euo pipefail

# shellcheck source=scripts/ci/xplat-common.sh
. "$(dirname "$0")/xplat-common.sh"

FIXTURE_HOME="$XPLAT_ROOT/home"
MOSS_HOME_DIR="$XPLAT_ROOT/moss-home"
REPO="$XPLAT_ROOT/repo"

rm -rf "$XPLAT_ROOT"
mkdir -p "$FIXTURE_HOME/.ssh" "$FIXTURE_HOME/Documents" "$MOSS_HOME_DIR"

# --- Fixture home: the sources discovery must find (.ssh, .gitconfig, Documents)
printf '%s\n' "$SSH_KEY_CONTENT" > "$FIXTURE_HOME/.ssh/id_ed25519"
printf '%s\n' "$SSH_CONFIG_CONTENT" > "$FIXTURE_HOME/.ssh/config"
printf '%s\n' "$GITCONFIG_CONTENT" > "$FIXTURE_HOME/.gitconfig"
printf '%s\n' "$NOTES_CONTENT" > "$FIXTURE_HOME/Documents/notes.txt"
chmod 700 "$FIXTURE_HOME/.ssh"
chmod 600 "$FIXTURE_HOME/.ssh/id_ed25519"
chmod 644 "$FIXTURE_HOME/.ssh/config"

echo "xplat-backup: fixture home at $FIXTURE_HOME"
find "$FIXTURE_HOME" -type f | sort

# --- Point moss at the fixture home; keep its own state out of it.
HOME="$(native_path "$FIXTURE_HOME")"
USERPROFILE="$HOME"
MOSS_HOME="$(native_path "$MOSS_HOME_DIR")"
export HOME USERPROFILE MOSS_HOME

run_moss --version

run_moss init \
  --repository "$(native_path "$REPO")" \
  --credential-store env \
  --identity ci \
  --non-interactive \
  --recovery-acknowledged

run_moss backup --non-interactive --json | tee "$XPLAT_ROOT/backup.json"
echo
run_moss snapshots --json | tee "$XPLAT_ROOT/snapshots.json"
echo

if command -v jq >/dev/null 2>&1; then
  jq -e . "$XPLAT_ROOT/backup.json" >/dev/null || { echo "xplat-backup: backup --json did not emit valid JSON" >&2; exit 1; }
  jq -e . "$XPLAT_ROOT/snapshots.json" >/dev/null || { echo "xplat-backup: snapshots --json did not emit valid JSON" >&2; exit 1; }
fi
[ -d "$REPO" ] && [ -n "$(ls -A "$REPO")" ] || { echo "xplat-backup: repository directory is empty" >&2; exit 1; }

# --- Artifact: repository plus MOSS_HOME (config/state, for inspection).
# The restore side re-runs `moss init` against the extracted repository (the
# §6 "repository already exists" path) rather than reusing this config,
# because the repository path inside it is specific to this runner.
tar -C "$XPLAT_ROOT" -czf "$XPLAT_ARTIFACT" repo moss-home
echo "xplat-backup: wrote $XPLAT_ARTIFACT ($(du -h "$XPLAT_ARTIFACT" | awk '{print $1}'))"
