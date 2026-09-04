#!/usr/bin/env bash
# Install the pinned Kopia release from its GitHub release assets.
#
# CI must never `brew install kopia` (or apt/choco): package managers float to
# the newest version and would silently defeat the pin that the JSON fixtures
# under tests/fixtures/kopia/<version>/ are captured against (spec §5).
#
# Usage:
#   scripts/install-kopia.sh                       # installs to $HOME/.local/bin
#   INSTALL_DIR=/some/dir scripts/install-kopia.sh # installs there instead
#
# Inside GitHub Actions (GITHUB_PATH set) the default destination is
# $RUNNER_TEMP/kopia and the directory is appended to GITHUB_PATH so later
# steps find `kopia` on PATH. Works with bash on Linux, macOS and Windows
# (Git Bash / MSYS on the windows-latest runner).
#
# Override KOPIA_VERSION to install a different pin, e.g. when bumping.
set -euo pipefail

KOPIA_VERSION="${KOPIA_VERSION:-0.23.1}"
BASE="https://github.com/kopia/kopia/releases/download/v${KOPIA_VERSION}"

# --- Detect OS and architecture -> release asset name --------------------
uname_s="$(uname -s)"
uname_m="$(uname -m)"

case "$uname_s" in
  Linux)  os="linux" ;;
  Darwin) os="macOS" ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT) os="windows" ;;
  *) echo "install-kopia: unsupported OS '$uname_s'" >&2; exit 1 ;;
esac

case "$uname_m" in
  x86_64|amd64)  arch="x64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "install-kopia: unsupported architecture '$uname_m'" >&2; exit 1 ;;
esac

if [ "$os" = "windows" ]; then
  if [ "$arch" != "x64" ]; then
    echo "install-kopia: Kopia publishes no Windows $arch build" >&2
    exit 1
  fi
  asset="kopia-${KOPIA_VERSION}-windows-x64.zip"
  binary="kopia.exe"
else
  asset="kopia-${KOPIA_VERSION}-${os}-${arch}.tar.gz"
  binary="kopia"
fi

# --- Destination ---------------------------------------------------------
if [ -n "${INSTALL_DIR:-}" ]; then
  dest="$INSTALL_DIR"
elif [ -n "${GITHUB_PATH:-}" ] && [ -n "${RUNNER_TEMP:-}" ]; then
  dest="${RUNNER_TEMP}/kopia"
else
  dest="${HOME}/.local/bin"
fi
# Git Bash on Windows hands us RUNNER_TEMP as D:\a\_temp; normalise for bash.
if command -v cygpath >/dev/null 2>&1; then
  dest="$(cygpath -u "$dest")"
fi
mkdir -p "$dest"

# Already installed at the right version? Then there is nothing to do.
if [ -x "$dest/$binary" ] && "$dest/$binary" --version 2>/dev/null | grep -q "^${KOPIA_VERSION} "; then
  echo "install-kopia: kopia ${KOPIA_VERSION} already present in $dest"
else
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT

  echo "install-kopia: downloading ${asset}"
  curl -fsSL --retry 3 -o "$work/$asset" "${BASE}/${asset}"
  curl -fsSL --retry 3 -o "$work/checksums.txt" "${BASE}/checksums.txt"

  # --- Verify against the published checksums.txt ------------------------
  expected="$(grep -E "[[:space:]]${asset}\$" "$work/checksums.txt" | awk '{print $1}' | head -n1)"
  if [ -z "$expected" ]; then
    echo "install-kopia: ${asset} not listed in checksums.txt" >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$work/$asset" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$work/$asset" | awk '{print $1}')"
  fi
  if [ "$expected" != "$actual" ]; then
    echo "install-kopia: checksum mismatch for ${asset}" >&2
    echo "  expected ${expected}" >&2
    echo "  actual   ${actual}" >&2
    exit 1
  fi
  echo "install-kopia: checksum verified (${actual})"

  # --- Extract -------------------------------------------------------------
  # Archives contain a single top-level directory named after the asset.
  mkdir -p "$work/x"
  case "$asset" in
    *.tar.gz)
      tar -xzf "$work/$asset" -C "$work/x"
      ;;
    *.zip)
      if command -v unzip >/dev/null 2>&1; then
        unzip -q "$work/$asset" -d "$work/x"
      elif command -v 7z >/dev/null 2>&1; then
        7z x -bso0 -bsp0 -o"$work/x" "$work/$asset"
      elif command -v powershell.exe >/dev/null 2>&1; then
        powershell.exe -NoProfile -Command \
          "Expand-Archive -Path '$(cygpath -w "$work/$asset")' -DestinationPath '$(cygpath -w "$work/x")'"
      else
        echo "install-kopia: no unzip, 7z or powershell available to extract ${asset}" >&2
        exit 1
      fi
      ;;
  esac

  found="$(find "$work/x" -type f -name "$binary" | head -n1)"
  if [ -z "$found" ]; then
    echo "install-kopia: ${binary} not found inside ${asset}" >&2
    exit 1
  fi
  install -m 0755 "$found" "$dest/$binary"
  echo "install-kopia: installed to $dest/$binary"
fi

# --- Expose and verify ---------------------------------------------------
if [ -n "${GITHUB_PATH:-}" ]; then
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$dest" >> "$GITHUB_PATH"
  else
    echo "$dest" >> "$GITHUB_PATH"
  fi
fi

installed="$("$dest/$binary" --version | head -n1)"
echo "install-kopia: $installed"
case "$installed" in
  "${KOPIA_VERSION} "*|"${KOPIA_VERSION}") ;;
  *)
    echo "install-kopia: expected version ${KOPIA_VERSION}, got '${installed}'" >&2
    exit 1
    ;;
esac
