//! The YAML configuration (spec §24). No secrets live here.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::model::{ProfileCategory, ProfileSource};

pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Every section defaults as a whole: a missing field takes the value from
/// `Default`, stated once per type below.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub profile: ProfileSection,
    pub repository: Option<RepositoryConfig>,
    pub backup: BackupSection,
    pub restore: RestoreSection,
    pub safety: SafetySection,
    pub limits: LimitsSection,
    pub yubikey: YubiKeySection,
    /// User-added sources (`moss include`).
    pub include: Vec<PathRule>,
    /// User exclusions: gitignore-style patterns or paths (`moss exclude`).
    pub exclude: Vec<PathRule>,
    /// Discovered sources, written at `init` (spec §8 "Discovery output").
    pub sources: Vec<ProfileSource>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            schema_version: CONFIG_SCHEMA_VERSION,
            profile: ProfileSection::default(),
            repository: None,
            backup: BackupSection::default(),
            restore: RestoreSection::default(),
            safety: SafetySection::default(),
            limits: LimitsSection::default(),
            yubikey: YubiKeySection::default(),
            include: Vec::new(),
            exclude: Vec::new(),
            sources: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSection {
    #[serde(default = "default_profile_name")]
    pub name: String,
    /// Stable, user-chosen identity independent of username and hostname (spec §22).
    #[serde(default)]
    pub identity: String,
}

fn default_profile_name() -> String {
    "default".into()
}

impl Default for ProfileSection {
    fn default() -> Self {
        ProfileSection {
            name: default_profile_name(),
            identity: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RepositoryType {
    Filesystem,
    S3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CredentialStoreKind {
    #[default]
    Keyring,
    Env,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryConfig {
    #[serde(rename = "type")]
    pub kind: RepositoryType,
    /// Stable id used to namespace keychain entries and the state directory.
    #[serde(default)]
    pub id: String,
    /// Filesystem path (type = filesystem).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub credential_store: CredentialStoreKind,
    /// When the user acknowledged the recovery sheet (spec §6 gate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Optional local copy for the offline workflow (spec §21, Phase 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<LocalRepositoryConfig>,
}

impl RepositoryConfig {
    pub fn display_url(&self) -> String {
        match self.kind {
            RepositoryType::Filesystem => self
                .path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            RepositoryType::S3 => {
                let bucket = self.bucket.clone().unwrap_or_default();
                match self.prefix.as_deref().filter(|p| !p.is_empty()) {
                    Some(prefix) => format!("s3://{bucket}/{}", prefix.trim_end_matches('/')),
                    None => format!("s3://{bucket}"),
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default)]
    pub disable: bool,
    #[serde(default)]
    pub disable_verification: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_ca_pem_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRepositoryConfig {
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupSection {
    pub include_sensitive: bool,
    pub follow_symlinks: bool,
    /// Opt-in for macOS `~/Library/Containers` and `Group Containers` (spec §8).
    pub include_containers: bool,
}

impl Default for BackupSection {
    fn default() -> Self {
        BackupSection {
            include_sensitive: true,
            follow_symlinks: false,
            include_containers: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ConflictPolicy {
    Skip,
    Overwrite,
    Backup,
    #[default]
    Interactive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RestoreSection {
    #[serde(default)]
    pub conflict: ConflictPolicy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafetySection {
    pub warn_on_sensitive: bool,
    pub allow_sensitive: bool,
}

impl Default for SafetySection {
    fn default() -> Self {
        SafetySection {
            warn_on_sensitive: true,
            allow_sensitive: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsSection {
    pub max_source_size_gb: u64,
    pub max_total_size_gb: u64,
    pub max_file_count: u64,
}

impl Default for LimitsSection {
    fn default() -> Self {
        LimitsSection {
            max_source_size_gb: 10,
            max_total_size_gb: 100,
            max_file_count: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct YubiKeySection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
}

/// A user include/exclude entry. `path` is a path (may start with `~`) or, for
/// excludes, a gitignore-style pattern such as `node_modules/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRule {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<ProfileCategory>,
}

impl PathRule {
    pub fn new(path: impl Into<String>) -> Self {
        PathRule {
            path: path.into(),
            category: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_example_parses() {
        let yaml = r#"
profile:
  name: default
  identity: rhys

repository:
  type: s3
  bucket: my-moss
  prefix: rhys
  endpoint: https://s3.example.com
  region: auto
  credential_store: keyring
  recovery_acknowledged_at: 2026-09-02T09:14:00Z

  local:
    path: /Volumes/Backups/profile

backup:
  include_sensitive: true
  follow_symlinks: false

restore:
  conflict: backup

safety:
  warn_on_sensitive: true
  allow_sensitive: true

limits:
  max_source_size_gb: 10
  max_total_size_gb: 100
  max_file_count: 1000000

yubikey:
  enabled: true
  recipient: age1...

include:
  - path: ~/Projects

exclude:
  - path: ~/Movies
"#;
        let c: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(c.profile.identity, "rhys");
        let repo = c.repository.unwrap();
        assert_eq!(repo.kind, RepositoryType::S3);
        assert_eq!(repo.display_url(), "s3://my-moss/rhys");
        assert_eq!(repo.credential_store, CredentialStoreKind::Keyring);
        assert!(repo.recovery_acknowledged_at.is_some());
        assert_eq!(c.restore.conflict, ConflictPolicy::Backup);
        assert_eq!(c.include[0].path, "~/Projects");
        assert_eq!(c.limits.max_file_count, 1_000_000);
    }

    #[test]
    fn defaults_are_safe() {
        let c = Config::default();
        assert!(c.safety.warn_on_sensitive);
        assert!(!c.backup.follow_symlinks);
        assert!(!c.backup.include_containers);
        assert_eq!(c.restore.conflict, ConflictPolicy::Interactive);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = serde_yaml_ng::from_str::<Config>("password: hunter2\n").unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn round_trips() {
        let c = Config {
            repository: Some(RepositoryConfig {
                kind: RepositoryType::Filesystem,
                id: "abc".into(),
                path: Some(PathBuf::from("/tmp/repo")),
                bucket: None,
                prefix: None,
                endpoint: None,
                region: None,
                tls: None,
                credential_store: CredentialStoreKind::Env,
                recovery_acknowledged_at: None,
                created_at: None,
                local: None,
            }),
            ..Config::default()
        };
        let yaml = serde_yaml_ng::to_string(&c).unwrap();
        let back: Config = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(back, c);
    }
}
