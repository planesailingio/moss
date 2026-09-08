//! The operating systems moss knows about. `Platform::current()` lives in
//! `platform/` so `cfg(target_os)` stays confined there.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    #[serde(rename = "macos")]
    MacOs,
    Linux,
    Windows,
}

impl Platform {
    pub const ALL: [Platform; 3] = [Platform::MacOs, Platform::Linux, Platform::Windows];

    pub fn display_name(self) -> &'static str {
        match self {
            Platform::MacOs => "macOS",
            Platform::Linux => "Linux",
            Platform::Windows => "Windows",
        }
    }

    pub fn tag_value(self) -> &'static str {
        match self {
            Platform::MacOs => "macos",
            Platform::Linux => "linux",
            Platform::Windows => "windows",
        }
    }

    pub fn parse(s: &str) -> Option<Platform> {
        match s.to_ascii_lowercase().as_str() {
            "macos" | "darwin" | "mac" => Some(Platform::MacOs),
            "linux" => Some(Platform::Linux),
            "windows" | "win" => Some(Platform::Windows),
            _ => None,
        }
    }

    /// Whether the platform's default home filesystem folds case.
    pub fn default_fs_case_insensitive(self) -> bool {
        !matches!(self, Platform::Linux)
    }
}
