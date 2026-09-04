#!/usr/bin/env bash
# Shared definitions for the cross-platform restore job (spec §39, plan
# Step 10/12). Sourced by cross-platform-backup.sh and
# cross-platform-restore.sh; not meant to be run directly.
#
# Layout under XPLAT_ROOT (default $RUNNER_TEMP/moss-xplat):
#   home/          fixture $HOME that the backup side discovers and backs up
#   moss-home/     MOSS_HOME used on the backup side (config/state/cache)
#   repo/          Kopia filesystem repository created by `moss init`
#   moss-xplat.tar.gz   artifact: repo/ + moss-home/, handed to the restore side

XPLAT_ROOT="${XPLAT_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/moss-xplat}"
# Git Bash on Windows hands us RUNNER_TEMP as D:\a\_temp; use a POSIX spelling
# inside the scripts and convert back with native_path() when talking to moss.
if command -v cygpath >/dev/null 2>&1; then
  XPLAT_ROOT="$(cygpath -u "$XPLAT_ROOT")"
fi
XPLAT_ARTIFACT="${XPLAT_ARTIFACT:-$XPLAT_ROOT/moss-xplat.tar.gz}"
export MOSS_REPOSITORY_PASSWORD="${MOSS_REPOSITORY_PASSWORD:-ci-fixture-password-not-secret}"

# Fixture content. The restore side checks bytes, not just presence.
# shellcheck disable=SC2034  # consumed by the sourcing scripts
SSH_KEY_CONTENT='-----BEGIN OPENSSH PRIVATE KEY-----
moss-ci-fixture-not-a-real-key
-----END OPENSSH PRIVATE KEY-----'
# shellcheck disable=SC2034
SSH_CONFIG_CONTENT='Host ci-fixture
  HostName example.invalid
  User moss'
# shellcheck disable=SC2034
GITCONFIG_CONTENT='[user]
	name = moss ci
	email = ci@example.invalid'
# shellcheck disable=SC2034
NOTES_CONTENT='moss cross-platform fixture: Documents/notes.txt'

# Resolve the moss binary built by the workflow (cargo build --release).
moss_bin() {
  if [ -n "${MOSS_BIN:-}" ]; then
    echo "$MOSS_BIN"
  elif [ -x target/release/moss.exe ]; then
    echo "$(pwd)/target/release/moss.exe"
  elif [ -x target/release/moss ]; then
    echo "$(pwd)/target/release/moss"
  else
    echo "xplat: moss binary not found; build with 'cargo build --release' or set MOSS_BIN" >&2
    return 1
  fi
}

# Path as the native executable expects it. Git Bash converts POSIX paths in
# *arguments* automatically but not in environment variables, so anything we
# export (HOME, USERPROFILE, MOSS_HOME) goes through here.
native_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    echo "$1"
  fi
}

is_windows() {
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*|Windows_NT) return 0 ;;
    *) return 1 ;;
  esac
}

# Octal permission bits of a file, portable across GNU and BSD stat.
file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

# Run moss with its output captured to a log and echoed, failing loudly.
run_moss() {
  local bin
  bin="$(moss_bin)" || return 1
  echo "+ moss $*"
  "$bin" "$@"
}
