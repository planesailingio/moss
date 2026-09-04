//! The profile manifest that travels with every run (spec §27).
//!
//! Written to `<state>/manifests/<run>.json` and snapshotted as its own Kopia
//! source so it inherits repository encryption and integrity. Paths are
//! home-relative for privacy; the manifest never contains secret contents.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{MossError, Result};
use crate::platform::Platform;
use crate::profile::model::{Portability, ProfileCategory, SemanticId};

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const MANIFEST_FILE_NAME: &str = "moss-manifest.json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub run_id: String,
    pub profile: String,
    pub profile_identity: String,
    pub source_os: Platform,
    pub source_host: String,
    pub source_user: String,
    /// Home directory on the source machine, needed to translate embedded
    /// absolute paths on restore (spec §15).
    pub source_home: String,
    pub tool_version: String,
    pub kopia_version: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub categories: Vec<ProfileCategory>,
    pub sources: Vec<ManifestSource>,
    #[serde(default)]
    pub skipped: Vec<Skipped>,
    #[serde(default)]
    pub collisions: Vec<Collision>,
    #[serde(default)]
    pub sensitive_counts: Vec<SensitiveCount>,
    #[serde(default)]
    pub totals: Totals,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestSource {
    pub id: SemanticId,
    pub category: ProfileCategory,
    pub portable: Portability,
    /// Home-relative path on the source (`~/.ssh`), or absolute if outside home.
    pub path: String,
    pub sensitive: bool,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub files: u64,
    /// Filled after `snapshot create` succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    #[serde(default)]
    pub fatal_errors: u64,
    #[serde(default)]
    pub ignored_errors: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    pub path: String,
    pub reason: SkipReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errno: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// EPERM: TCC / SIP / Data Vault on macOS.
    PermissionDenied,
    /// EACCES: mode bits or ACL.
    AccessDenied,
    NotFound,
    IoError,
    /// Kopia reported an error moss's scan did not predict.
    BackupError,
    SymlinkUnsupported,
}

impl SkipReason {
    pub fn display(self) -> &'static str {
        match self {
            SkipReason::PermissionDenied => "permission denied (Full Disk Access)",
            SkipReason::AccessDenied => "access denied (file permissions)",
            SkipReason::NotFound => "vanished during scan",
            SkipReason::IoError => "I/O error",
            SkipReason::BackupError => "backup error",
            SkipReason::SymlinkUnsupported => "symlink not supported here",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Collision {
    Case { paths: Vec<String> },
    Normalization { paths: Vec<String> },
    WindowsIllegal { path: String, problem: String },
    PathTooLong { path: String, length: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensitiveCount {
    pub kind: crate::profile::sensitive::SensitiveKind,
    pub files: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    pub size: u64,
    pub files: u64,
    pub dirs: u64,
    pub excluded_size: u64,
}

impl Manifest {
    pub fn is_complete(&self) -> bool {
        self.skipped.is_empty()
            && self
                .sources
                .iter()
                .all(|s| s.fatal_errors == 0 && s.ignored_errors == 0)
    }

    pub fn write(&self, dir: &Path) -> Result<PathBuf> {
        crate::config::paths::create_private_dir(dir)?;
        let path = dir.join(MANIFEST_FILE_NAME);
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        crate::config::paths::make_private_file(&path)?;
        Ok(path)
    }

    pub fn read(path: &Path) -> Result<Manifest> {
        let text = std::fs::read_to_string(path)?;
        Manifest::parse(&text)
    }

    /// Parse and validate. The manifest is attacker-influenceable (spec §4):
    /// schema is checked here, paths are checked by restore containment.
    pub fn parse(text: &str) -> Result<Manifest> {
        let m: Manifest = serde_json::from_str(text).map_err(|e| {
            MossError::Integrity(format!("The snapshot manifest is not readable: {e}"))
        })?;
        if m.schema_version > MANIFEST_SCHEMA_VERSION {
            return Err(MossError::Integrity(format!(
                "The snapshot manifest uses schema {} but this moss understands {}. Upgrade moss.",
                m.schema_version, MANIFEST_SCHEMA_VERSION
            )));
        }
        if m.run_id.is_empty() || m.sources.is_empty() {
            return Err(MossError::Integrity(
                "The snapshot manifest is empty.".into(),
            ));
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn sample() -> Manifest {
        Manifest {
            schema_version: 1,
            run_id: "01TEST".into(),
            profile: "default".into(),
            profile_identity: "rhys".into(),
            source_os: Platform::MacOs,
            source_host: "macbook".into(),
            source_user: "rhys".into(),
            source_home: "/Users/rhys".into(),
            tool_version: "0.1.0".into(),
            kopia_version: "0.23.1".into(),
            created_at: chrono::Utc::now(),
            categories: vec![ProfileCategory::Credentials],
            sources: vec![ManifestSource {
                id: SemanticId::new("ssh"),
                category: ProfileCategory::Credentials,
                portable: Portability::Portable,
                path: "~/.ssh".into(),
                sensitive: true,
                size: 10,
                files: 5,
                snapshot_id: Some("abc".into()),
                fatal_errors: 0,
                ignored_errors: 0,
            }],
            skipped: vec![Skipped {
                path: "~/Library/Mail".into(),
                reason: SkipReason::PermissionDenied,
                errno: Some("EPERM".into()),
                detail: None,
            }],
            collisions: vec![Collision::Case {
                paths: vec!["src/Makefile".into(), "src/makefile".into()],
            }],
            sensitive_counts: vec![],
            totals: Totals::default(),
        }
    }

    #[test]
    fn round_trip_and_schema_check() {
        let tmp = tempfile::tempdir().unwrap();
        let m = sample();
        let p = m.write(tmp.path()).unwrap();
        let back = Manifest::read(&p).unwrap();
        assert_eq!(back, m);
        assert!(!back.is_complete());
        let json = std::fs::read_to_string(&p).unwrap();
        assert!(json.contains("\"kind\": \"case\""));
        assert!(json.contains("\"reason\": \"permission_denied\""));
        let newer = json.replace("\"schema_version\": 1", "\"schema_version\": 9");
        assert_eq!(Manifest::parse(&newer).unwrap_err().exit_code().code(), 8);
    }
}
