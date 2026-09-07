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

### The tap GitHub App

The `tap` job pushes to a different repository, which the default
`GITHUB_TOKEN` cannot do: it is scoped to the repository the workflow runs
in, and no setting extends it. The job instead mints a one-hour installation
token for a GitHub App owned by the `planesailingio` org, using
`actions/create-github-app-token`, and passes it to the script as `GH_TOKEN`.
The script clones and pushes over
`https://x-access-token:${GH_TOKEN}@github.com/planesailingio/homebrew-tools.git`.

One-time setup, all in the GitHub UI:

1. Org Settings → Developer settings → GitHub Apps → New GitHub App. Untick
   Webhook. Repository permissions: Contents — read and write, nothing else
   (Metadata read is added automatically). Install only on this account.
2. On the new app's page, note the App ID (or client ID; either works) and
   Generate a private key, which downloads a `.pem` file. The client secret
   is for the OAuth login flow and is not used here.
3. Install app → Only select repositories → `planesailingio/homebrew-tools`.
   Check it took: Org Settings → GitHub Apps should list the app, and its
   Configure page must show `homebrew-tools` under repository access. Creating
   the app does not install it, and without this step every tap push fails
   with `Not Found` on the installation lookup.
4. Org Settings → Secrets and variables → Actions. Create the variable
   `TAP_APP_ID` (the App ID) and the secret `TAP_APP_PRIVATE_KEY` (the full
   `.pem` contents, including the BEGIN and END lines). Set both to
   "Selected repositories" and include every repository that pushes to the
   tap: `moss` and `twig`.

Commits pushed this way are authored by the app's bot user. Rotate by
generating a new private key on the app page and replacing the org secret.

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

The release itself is already published, so only the tap needs another go.
Once the cause is fixed, either:

- Actions → Release → Run workflow, enter the version without the leading
  `v` (for example `0.7.1`). `build` and `release` are skipped and only `tap`
  runs. This works for any published version, including tags pushed before
  the app existed.
- Or "Re-run failed jobs" on the original run.
- Or run `scripts/update-tap.sh <version>` locally and confirm the push.

The script is idempotent: if the tap already carries that version it reports
"nothing to push" and exits 0.

Failure signatures from the "Mint tap app token" step:

- `Not Found - .../apps#get-a-repository-installation-for-the-authenticated-app`
  — the app authenticated but is not installed on `homebrew-tools`. Setup
  step 3 above.
- A JWT, signature or `Bad credentials` error — `TAP_APP_ID` and
  `TAP_APP_PRIVATE_KEY` do not belong to the same app. Steps 2 and 4.
- A missing-input error — the variable or secret is not shared with this
  repository. Step 4.
