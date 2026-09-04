# Releasing moss

Releases are cut from a `vX.Y.Z` tag on `main`. The `Release` workflow
(`.github/workflows/release.yml`) builds the archives, publishes a GitHub
release and, for final versions, pushes the Homebrew formula to
`planesailingio/homebrew-tools` (spec §45, implementation plan Step 12).

## Cutting a release

1. Bump `version` in `Cargo.toml` and run `cargo build` so `Cargo.lock`
   follows.
2. Move the `Unreleased` entries in `CHANGELOG.md` under a new `X.Y.Z`
   heading with the date.
3. If the pinned Kopia changed, `KOPIA_VERSION` in `ci.yml`,
   `scripts/install-kopia.sh`, `tests/fixtures/kopia/<version>/` and the
   `KOPIA_MAX` range in `doctor` must all move in the same release.
4. Commit, make sure CI is green on `main`, then tag and push:

   ```sh
   git tag -a vX.Y.Z -m "moss X.Y.Z"
   git push origin vX.Y.Z
   ```

Tags containing `-` (`v0.2.0-rc1`) are published as prereleases and skip the
tap.

## What the workflow does

- `build` — one job per target (`x86_64-apple-darwin`, `aarch64-apple-darwin`,
  `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
  `x86_64-pc-windows-msvc`). Each produces
  `moss_<version>_<target>.tar.gz` (`.zip` on Windows) containing
  `<name>/bin/moss`, `README.md` and `LICENSE`, plus a `.sha256` sidecar.
- `release` — collects the archives and creates the GitHub release with
  `softprops/action-gh-release`; `prerelease` is set when the tag contains
  `-`.
- `tap` — `needs: release`, skipped for prereleases. Runs
  `MOSS_TAP_CONFIRM=1 scripts/update-tap.sh <version>`, which downloads the
  four Unix `.sha256` sidecars from the release, renders `Formula/moss.rb`
  (binary-only, `depends_on "kopia"`), clones the tap, commits
  `moss <version>` and pushes.

### The `HOMEBREW_TOOLS_TOKEN` secret

The `tap` job pushes to a different repository, which the default
`GITHUB_TOKEN` cannot do. Create a fine-grained personal access token with:

- Repository access: only `planesailingio/homebrew-tools`
- Permissions: Contents — read and write

and store it as the repository secret `HOMEBREW_TOOLS_TOKEN` on
`planesailingio/moss`. The script clones and pushes over
`https://x-access-token:${GH_TOKEN}@github.com/planesailingio/homebrew-tools.git`.

## Dry run before the first real release

1. Push a prerelease tag, e.g. `v0.0.1-rc1`. Confirm the release shows five
   archives with five sidecars, is marked as a prerelease, and the `tap` job
   was skipped.
2. Render the formula locally without pushing (answer `N` at the prompt):

   ```sh
   scripts/update-tap.sh 0.0.1-rc1
   ```

   Inspect `./Formula/moss.rb` (the directory is git-ignored).
3. Install and test it on this machine:

   ```sh
   brew install --formula ./Formula/moss.rb
   brew test moss
   moss doctor
   brew uninstall moss
   ```

   `brew install` must pull in `kopia` as a dependency and `brew test` runs
   `moss --version` and `moss doctor --json`.
4. Tag `v0.1.0`. After the workflow finishes, on a clean machine:

   ```sh
   brew install planesailingio/tools/moss
   moss doctor
   ```

   `doctor` should report Kopia found and inside the supported range.

## If the tap push fails

The release itself is already published; re-run only the `tap` job from the
Actions UI once the cause (usually the token) is fixed, or run
`scripts/update-tap.sh <version>` locally and confirm the push.
