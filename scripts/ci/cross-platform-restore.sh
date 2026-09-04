#!/usr/bin/env bash
# Restore half of the cross-platform restore job (spec §39): take the
# artifact produced on another OS by cross-platform-backup.sh, connect to the
# repository inside it, restore the latest run into a scratch directory with
# `--to`, and assert that every fixture file landed where it should with the
# right bytes and (on Unix) the right mode.
#
# CLI contract this script is written against (Milestone 4):
#   MOSS_HOME=<dir> MOSS_REPOSITORY_PASSWORD=<pw> \
#     moss init --repository <path> --credential-store env --identity ci \
#               --non-interactive --recovery-acknowledged
#       (repository already exists -> §6 bootstrap path, password from env)
#   moss snapshots --json
#   moss restore latest --to <dir> --conflict overwrite --non-interactive --json
#
# Usage: scripts/ci/cross-platform-restore.sh [artifact.tar.gz]
# Env:   XPLAT_ROOT, XPLAT_ARTIFACT, MOSS_BIN, MOSS_REPOSITORY_PASSWORD
set -euo pipefail

# shellcheck source=scripts/ci/xplat-common.sh
. "$(dirname "$0")/xplat-common.sh"

ARTIFACT="${1:-$XPLAT_ARTIFACT}"
[ -f "$ARTIFACT" ] || { echo "xplat-restore: artifact not found: $ARTIFACT" >&2; exit 1; }

IN="$XPLAT_ROOT/in"
SCRATCH_HOME="$XPLAT_ROOT/home-restore"
MOSS_HOME_DIR="$XPLAT_ROOT/moss-home-restore"
TO="$XPLAT_ROOT/restored"

rm -rf "$IN" "$SCRATCH_HOME" "$MOSS_HOME_DIR" "$TO"
mkdir -p "$IN" "$SCRATCH_HOME" "$MOSS_HOME_DIR" "$TO"
tar -C "$IN" -xzf "$ARTIFACT"
REPO="$IN/repo"
[ -d "$REPO" ] || { echo "xplat-restore: artifact has no repo/ directory" >&2; exit 1; }
echo "xplat-restore: repository extracted to $REPO"

# A fresh, empty home: nothing the restore could be confused by, and the
# assertions below prove placement came from the repository, not from here.
HOME="$(native_path "$SCRATCH_HOME")"
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

run_moss snapshots --json | tee "$XPLAT_ROOT/snapshots-restore.json"
echo

run_moss restore latest \
  --to "$(native_path "$TO")" \
  --conflict overwrite \
  --non-interactive \
  --json | tee "$XPLAT_ROOT/restore.json"
echo

# --- Assertions ------------------------------------------------------------
echo "xplat-restore: restored tree under $TO"
find "$TO" -type f | sort

failures=0
fail() { echo "xplat-restore: FAIL: $*" >&2; failures=$((failures + 1)); }

# Placement: `--to <dir>` mirrors the home layout under <dir>, so the
# semantic sources land at their home-relative paths on every OS (§15).
expect_file() {
  local rel="$1" expected="$2" path="$TO/$1"
  if [ ! -f "$path" ]; then
    fail "missing $rel"
    return
  fi
  # Normalise CRLF in case the Windows side ever translates text files.
  local actual
  actual="$(tr -d '\r' < "$path")"
  if [ "$actual" != "$expected" ]; then
    fail "content mismatch in $rel"
    echo "--- expected" >&2; printf '%s\n' "$expected" >&2
    echo "--- actual" >&2; printf '%s\n' "$actual" >&2
  else
    echo "xplat-restore: ok  $rel"
  fi
}

expect_file .ssh/id_ed25519 "$SSH_KEY_CONTENT"
expect_file .ssh/config "$SSH_CONFIG_CONTENT"
expect_file .gitconfig "$GITCONFIG_CONTENT"
expect_file Documents/notes.txt "$NOTES_CONTENT"

# Modes: the private key must come back 0600 on Unix (§16, §21). Windows has
# no POSIX bits; ACL handling is asserted by moss's own tests.
if ! is_windows; then
  if [ -f "$TO/.ssh/id_ed25519" ]; then
    mode="$(file_mode "$TO/.ssh/id_ed25519")"
    if [ "$mode" = "600" ]; then
      echo "xplat-restore: ok  .ssh/id_ed25519 mode 0600"
    else
      fail ".ssh/id_ed25519 mode is $mode, expected 600"
    fi
  fi
  if [ -d "$TO/.ssh" ]; then
    mode="$(file_mode "$TO/.ssh")"
    case "$mode" in
      700) echo "xplat-restore: ok  .ssh mode 0700" ;;
      *) fail ".ssh mode is $mode, expected 700" ;;
    esac
  fi
fi

if [ "$failures" -ne 0 ]; then
  echo "xplat-restore: $failures assertion(s) failed" >&2
  exit 1
fi
echo "xplat-restore: all assertions passed"
