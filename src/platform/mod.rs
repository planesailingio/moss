//! Operating-system identity and the adapter boundary.
//!
//! `cfg(target_os)` is confined to this module tree (spec §2): `Platform::current`,
//! `current_adapter`, `tcc.rs`, and the three adapters. Everything else asks the
//! [`PlatformAdapter`] to resolve a [`Location`].

use std::path::{Path, PathBuf};

pub mod linux;
pub mod location;
pub mod macos;
pub mod tcc;
pub mod windows;
pub mod xdg;

pub use crate::model::Platform;
pub use location::{Location, UserDir};

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
        compile_error!("moss supports macOS, Linux and Windows only");
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

/// The per-OS boundary. Implementations live in `platform/{macos,linux,windows}.rs`.
/// Adapters resolve their bases once at construction; every method is cheap.
pub trait PlatformAdapter: Send + Sync {
    fn platform(&self) -> Platform;

    /// The current user's home directory.
    fn home(&self) -> &Path;

    /// Absolute path for a table location on this machine, whether or not it
    /// exists. `None` only for a base this OS does not have (`AppData` on
    /// Unix, `DataHome` on Windows).
    fn resolve(&self, loc: Location) -> Option<PathBuf>;

    /// The user's own Kopia config and cache directories, to exclude (spec §10).
    fn user_kopia_dirs(&self) -> Vec<PathBuf>;
}

/// The adapter for the OS moss is running on.
pub fn current_adapter() -> Box<dyn PlatformAdapter> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsAdapter::detect())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxAdapter::detect())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsAdapter::detect())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    compile_error!("moss supports macOS, Linux and Windows only");
}

pub fn host_info(adapter: &dyn PlatformAdapter) -> HostInfo {
    HostInfo {
        platform: adapter.platform(),
        hostname: hostname(),
        username: username(),
        home: adapter.home().to_path_buf(),
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
