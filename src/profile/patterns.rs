//! Default exclusion patterns (spec §10). Patterns, not paths: `node_modules/`
//! is matched at any depth during the walk.

/// Directory-name patterns matched at any depth (gitignore syntax).
pub const BUILD_AND_DEPENDENCY_DIRS: [&str; 14] = [
    "node_modules/",
    "target/",
    ".venv/",
    "venv/",
    "__pycache__/",
    "vendor/",
    ".gradle/",
    "build/",
    "dist/",
    ".next/",
    ".nuxt/",
    ".terraform/",
    ".cache/",
    "DerivedData/",
];

/// Home-relative cache locations, largest first as measured (spec §10).
/// Each is anchored to the home directory (leading `/` in gitignore terms).
pub const KNOWN_CACHE_DIRS: [&str; 16] = [
    "/.cache/",
    "/.npm/_cacache/",
    "/.nuget/packages/",
    "/go/pkg/mod/",
    "/Library/Caches/",
    "/Library/pnpm/",
    "/.gradle/caches/",
    "/.cargo/registry/",
    "/.cargo/git/",
    "/.rustup/toolchains/",
    "/.m2/repository/",
    "/Library/Developer/Xcode/DerivedData/",
    "/Library/Developer/CoreSimulator/",
    "/.local/share/Trash/",
    "/.docker/desktop/",
    "/Library/Containers/com.docker.docker/",
];

/// Temporary and disposable files anywhere.
pub const TEMP_PATTERNS: [&str; 6] = [
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    "*.tmp",
    "*.swp",
    "*~",
];

/// Cloud-drive roots (spec §8): already replicated, often placeholder files.
pub const CLOUD_DRIVE_DIRS: [&str; 8] = [
    "/Library/Mobile Documents/",
    "/Library/CloudStorage/",
    "/Dropbox/",
    "/OneDrive/",
    "/OneDrive - */",
    "/Nextcloud/",
    "/Box/",
    "/Google Drive/",
];

/// `~/.config` and `~/.local/share` subtrees that are cache-like (spec §10 table).
pub const CONFIG_CACHE_PATTERNS: [&str; 4] = [
    "/.config/**/Cache/",
    "/.config/**/cache/",
    "/.config/**/CachedData/",
    "/.config/**/GPUCache/",
];

/// Docker Desktop VM images: match on the containing directory, not the file
/// (`Docker.raw`, `Docker.qcow2`, and the Apple Virtualization layout).
pub const DOCKER_VM_PATTERNS: [&str; 2] = [
    "/Library/Containers/com.docker.docker/Data/vms/",
    "/.docker/desktop/vms/",
];

/// Which category an excluded path is reported under in `inspect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionKind {
    Cache,
    BuildArtifact,
    Temporary,
    CloudDrive,
    OwnState,
    UserRule,
}

impl ExclusionKind {
    pub fn display_name(self) -> &'static str {
        match self {
            ExclusionKind::Cache => "Caches",
            ExclusionKind::BuildArtifact => "Build artifacts",
            ExclusionKind::Temporary => "Temporary files",
            ExclusionKind::CloudDrive => "Cloud drives",
            ExclusionKind::OwnState => "Backup tool state",
            ExclusionKind::UserRule => "User exclusions",
        }
    }
}

/// All default patterns with their reporting kind.
pub fn defaults() -> Vec<(&'static str, ExclusionKind)> {
    let mut v = Vec::new();
    v.extend(
        BUILD_AND_DEPENDENCY_DIRS
            .iter()
            .map(|p| (*p, ExclusionKind::BuildArtifact)),
    );
    v.extend(KNOWN_CACHE_DIRS.iter().map(|p| (*p, ExclusionKind::Cache)));
    v.extend(
        CONFIG_CACHE_PATTERNS
            .iter()
            .map(|p| (*p, ExclusionKind::Cache)),
    );
    v.extend(
        DOCKER_VM_PATTERNS
            .iter()
            .map(|p| (*p, ExclusionKind::Cache)),
    );
    v.extend(TEMP_PATTERNS.iter().map(|p| (*p, ExclusionKind::Temporary)));
    v.extend(
        CLOUD_DRIVE_DIRS
            .iter()
            .map(|p| (*p, ExclusionKind::CloudDrive)),
    );
    v
}
