//! Operating-system identity and the adapter boundary.
//!
//! `cfg(target_os)` is confined to this module and `profile/{macos,linux,windows}.rs`
//! (spec §2). Everything else asks the [`PlatformAdapter`].

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::profile::model::SemanticId;

pub mod tcc;

/// The operating systems moss knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    #[serde(rename = "macos")]
    MacOs,
    Linux,
    Windows,
}

impl Platform {
    pub const fn current() -> Platform {
        #[cfg(target_os = "macos")]
        {
            Platform::MacOs
        }
        #[cfg(target_os = "linux")]
        {
            Platform::Linux
        }
        #[cfg(target_os = "windows")]
        {
            Platform::Windows
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            Platform::Linux
        }
    }

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

/// Facts about the running machine.
#[derive(Debug, Clone)]
pub struct HostInfo {
    pub platform: Platform,
    pub hostname: String,
    pub username: String,
    pub home: PathBuf,
}

/// A known user directory: the semantic id and where this platform keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownDir {
    pub id: SemanticId,
    pub path: PathBuf,
}

/// The per-OS boundary. Implementations live in `profile/{macos,linux,windows}.rs`.
pub trait PlatformAdapter: Send + Sync {
    fn platform(&self) -> Platform;

    /// The current user's home directory.
    fn home(&self) -> PathBuf;

    /// The platform's standard user directories (Documents, the video folder, …)
    /// resolved through the platform's own mechanism — user template on macOS,
    /// XDG on Linux, known folders on Windows. Only directories that exist are
    /// returned; nothing is invented (spec §8).
    fn known_dirs(&self) -> Vec<KnownDir>;

    /// Where this platform expects a semantic id to live, whether or not it
    /// currently exists. Used by restore to map a source onto the destination.
    fn destination_for(&self, id: &SemanticId) -> Option<PathBuf>;

    /// The user's own Kopia config and cache directories, to exclude (spec §10).
    fn user_kopia_dirs(&self) -> Vec<PathBuf>;
}

/// The adapter for the OS moss is running on.
pub fn current_adapter() -> Box<dyn PlatformAdapter> {
    #[cfg(target_os = "macos")]
    {
        Box::new(crate::profile::macos::MacOsAdapter::detect())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(crate::profile::linux::LinuxAdapter::detect())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(crate::profile::windows::WindowsAdapter::detect())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Box::new(crate::profile::linux::LinuxAdapter::detect())
    }
}

pub fn host_info(adapter: &dyn PlatformAdapter) -> HostInfo {
    HostInfo {
        platform: adapter.platform(),
        hostname: hostname(),
        username: username(),
        home: adapter.home(),
    }
}

pub fn hostname() -> String {
    std::env::var("MOSS_HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown-host".to_string())
}

pub fn username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-user".to_string())
}

/// Home directory, honouring `HOME` / `USERPROFILE` first so tests can redirect it.
pub fn home_dir() -> PathBuf {
    if let Ok(h) = std::env::var("HOME")
        && !h.is_empty()
    {
        return PathBuf::from(h);
    }
    if let Ok(h) = std::env::var("USERPROFILE")
        && !h.is_empty()
    {
        return PathBuf::from(h);
    }
    directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/"))
}
