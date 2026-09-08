//! What a scan could not read and what it found colliding: produced by
//! `scan`, classified by `platform::tcc`, recorded by the backup manifest.

use serde::{Deserialize, Serialize};

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
