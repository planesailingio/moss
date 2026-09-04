//! The semantic profile model (spec §9, §15).
//!
//! A profile is not a `Vec<PathBuf>`. Each source has a stable semantic id that
//! is the same on every operating system; only the path differs.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::platform::Platform;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileCategory {
    PersonalData,
    Configuration,
    Credentials,
    Development,
    ApplicationState,
    SystemIntegration,
    Cache,
    Generated,
    Unknown,
}

impl ProfileCategory {
    pub fn display_name(self) -> &'static str {
        match self {
            ProfileCategory::PersonalData => "Personal data",
            ProfileCategory::Configuration => "Configuration",
            ProfileCategory::Credentials => "Credentials",
            ProfileCategory::Development => "Development",
            ProfileCategory::ApplicationState => "Application state",
            ProfileCategory::SystemIntegration => "System integration",
            ProfileCategory::Cache => "Caches",
            ProfileCategory::Generated => "Build artifacts",
            ProfileCategory::Unknown => "Unknown",
        }
    }

    pub fn parse(s: &str) -> Option<ProfileCategory> {
        Some(match s.to_ascii_lowercase().replace('-', "_").as_str() {
            "personal_data" | "personal" => ProfileCategory::PersonalData,
            "configuration" | "config" => ProfileCategory::Configuration,
            "credentials" | "creds" => ProfileCategory::Credentials,
            "development" | "dev" => ProfileCategory::Development,
            "application_state" | "app_state" | "application" => ProfileCategory::ApplicationState,
            "system_integration" | "system" => ProfileCategory::SystemIntegration,
            "cache" | "caches" => ProfileCategory::Cache,
            "generated" => ProfileCategory::Generated,
            "unknown" => ProfileCategory::Unknown,
            _ => return None,
        })
    }

    pub const ALL: [ProfileCategory; 9] = [
        ProfileCategory::PersonalData,
        ProfileCategory::Configuration,
        ProfileCategory::Credentials,
        ProfileCategory::Development,
        ProfileCategory::ApplicationState,
        ProfileCategory::SystemIntegration,
        ProfileCategory::Cache,
        ProfileCategory::Generated,
        ProfileCategory::Unknown,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Portability {
    Portable,
    PortableWithPathTranslation,
    PlatformSpecific,
    MachineSpecific,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Inclusion {
    Include,
    Exclude,
    /// Present on the system, known to moss, but only backed up when the user asks.
    OptIn,
}

/// The stable, cross-platform key for a source (spec §15).
///
/// Built-in ids are plain words (`ssh`, `video`); user includes are
/// `custom:<home-relative path with forward slashes>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SemanticId(String);

impl SemanticId {
    pub fn new(id: impl Into<String>) -> Self {
        SemanticId(id.into())
    }

    pub fn custom(home_relative: &Path) -> Self {
        let rel = home_relative
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        SemanticId(format!("custom:{rel}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_custom(&self) -> bool {
        self.0.starts_with("custom:")
    }

    /// For `custom:` ids, the home-relative path.
    pub fn custom_relative(&self) -> Option<PathBuf> {
        self.0
            .strip_prefix("custom:")
            .map(|rel| rel.split('/').collect::<PathBuf>())
    }

    /// Built-in ids in spec §15 order.
    pub const BUILTIN: [&'static str; 15] = [
        "user_home",
        "documents",
        "desktop",
        "downloads",
        "pictures",
        "video",
        "music",
        "public",
        "aws",
        "ssh",
        "gnupg",
        "kubernetes",
        "docker",
        "git",
        "shell",
    ];
}

impl fmt::Display for SemanticId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for SemanticId {
    fn from(s: &str) -> Self {
        SemanticId(s.to_string())
    }
}

/// One discovered source (spec §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSource {
    pub id: SemanticId,
    pub path: PathBuf,
    pub category: ProfileCategory,
    pub platform: Platform,
    pub reason: String,
    pub default_action: Inclusion,
    pub sensitive: bool,
    pub portable: Portability,
}

impl ProfileSource {
    /// Path relative to the home directory with forward slashes, for manifests
    /// (spec §27 privacy: prefer home-relative paths).
    pub fn home_relative(&self, home: &Path) -> String {
        home_relative(&self.path, home)
    }
}

pub fn home_relative(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rel) if rel.as_os_str().is_empty() => "~".to_string(),
        Ok(rel) => format!(
            "~/{}",
            rel.components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
        ),
        Err(_) => path.to_string_lossy().into_owned(),
    }
}

/// Expand a leading `~` against `home`.
pub fn expand_tilde(input: &str, home: &Path) -> PathBuf {
    if input == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = input
        .strip_prefix("~/")
        .or_else(|| input.strip_prefix("~\\"))
    {
        return home.join(rest);
    }
    PathBuf::from(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_ids_round_trip() {
        let id = SemanticId::custom(Path::new("Projects/moss"));
        assert_eq!(id.as_str(), "custom:Projects/moss");
        assert!(id.is_custom());
        assert_eq!(
            id.custom_relative().unwrap(),
            PathBuf::from("Projects").join("moss")
        );
        assert!(SemanticId::new("ssh").custom_relative().is_none());
    }

    #[test]
    fn home_relative_paths() {
        let home = Path::new("/Users/rhys");
        assert_eq!(home_relative(Path::new("/Users/rhys/.ssh"), home), "~/.ssh");
        assert_eq!(home_relative(home, home), "~");
        assert_eq!(home_relative(Path::new("/etc/x"), home), "/etc/x");
    }

    #[test]
    fn tilde_expansion() {
        let home = Path::new("/home/x");
        assert_eq!(expand_tilde("~", home), PathBuf::from("/home/x"));
        assert_eq!(expand_tilde("~/a/b", home), PathBuf::from("/home/x/a/b"));
        assert_eq!(expand_tilde("/abs", home), PathBuf::from("/abs"));
    }

    #[test]
    fn category_parse_and_serde() {
        assert_eq!(
            ProfileCategory::parse("credentials"),
            Some(ProfileCategory::Credentials)
        );
        assert_eq!(
            ProfileCategory::parse("personal"),
            Some(ProfileCategory::PersonalData)
        );
        let json = serde_json::to_string(&ProfileCategory::ApplicationState).unwrap();
        assert_eq!(json, "\"application_state\"");
        let p: Portability = serde_json::from_str("\"PortableWithPathTranslation\"").unwrap();
        assert_eq!(p, Portability::PortableWithPathTranslation);
    }
}
