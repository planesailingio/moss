//! Windows platform adapter (spec §8). Known folders via `SHGetKnownFolderPath`;
//! nothing is hardcoded because Folder Redirection and OneDrive move them.
//! `%APPDATA%` and `%LOCALAPPDATA%` are read once, at construction.

use std::path::{Path, PathBuf};

use crate::platform::location::under;
use crate::platform::{Location, Platform, PlatformAdapter, UserDir};

pub struct WindowsAdapter {
    home: PathBuf,
    appdata: PathBuf,
    local_appdata: PathBuf,
    /// Known folders the shell resolved; anything missing falls back to the
    /// English name under home.
    resolved: Vec<(UserDir, PathBuf)>,
}

impl WindowsAdapter {
    pub fn detect() -> WindowsAdapter {
        let home = crate::platform::home_dir();
        WindowsAdapter::with(home, resolve_known_folders())
    }

    pub fn with(home: PathBuf, resolved: Vec<(UserDir, PathBuf)>) -> WindowsAdapter {
        WindowsAdapter {
            appdata: appdata(&home),
            local_appdata: local_appdata(&home),
            home,
            resolved,
        }
    }
}

#[cfg(target_os = "windows")]
fn resolve_known_folders() -> Vec<(UserDir, PathBuf)> {
    use known_folders::{KnownFolder, get_known_folder_path};
    fn folder(d: UserDir) -> KnownFolder {
        match d {
            UserDir::Desktop => KnownFolder::Desktop,
            UserDir::Documents => KnownFolder::Documents,
            UserDir::Downloads => KnownFolder::Downloads,
            UserDir::Pictures => KnownFolder::Pictures,
            UserDir::Video => KnownFolder::Videos,
            UserDir::Music => KnownFolder::Music,
            UserDir::Public => KnownFolder::Public,
        }
    }
    UserDir::ALL
        .into_iter()
        .filter_map(|d| {
            // Each FOLDERID is individually fallible (E_INVALIDARG on old systems).
            get_known_folder_path(folder(d)).map(|p| (d, p))
        })
        .collect()
}

#[cfg(not(target_os = "windows"))]
fn resolve_known_folders() -> Vec<(UserDir, PathBuf)> {
    Vec::new()
}

pub fn appdata(home: &Path) -> PathBuf {
    std::env::var_os("APPDATA")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("AppData").join("Roaming"))
}

pub fn local_appdata(home: &Path) -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("AppData").join("Local"))
}

impl PlatformAdapter for WindowsAdapter {
    fn platform(&self) -> Platform {
        Platform::Windows
    }

    fn home(&self) -> &Path {
        &self.home
    }

    fn resolve(&self, loc: Location) -> Option<PathBuf> {
        Some(match loc {
            Location::Home => self.home.clone(),
            Location::HomeRel(rel) => under(self.home.clone(), rel),
            Location::ConfigHome(rel) => under(self.home.join(".config"), rel),
            Location::DataHome(_) | Location::StateHome(_) => return None,
            Location::AppData(rel) => under(self.appdata.clone(), rel),
            Location::LocalAppData(rel) => under(self.local_appdata.clone(), rel),
            Location::UserDir(d) => self
                .resolved
                .iter()
                .find(|(k, _)| *k == d)
                .map(|(_, p)| p.clone())
                .unwrap_or_else(|| self.home.join(d.english_name())),
        })
    }

    fn user_kopia_dirs(&self) -> Vec<PathBuf> {
        vec![self.appdata.join("kopia"), self.local_appdata.join("kopia")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_is_videos_and_redirection_wins() {
        let home = PathBuf::from("C:\\Users\\rhys");
        let a = WindowsAdapter::with(
            home.clone(),
            vec![(UserDir::Documents, PathBuf::from("D:\\OneDrive\\Documents"))],
        );
        assert_eq!(
            a.resolve(Location::UserDir(UserDir::Documents)).unwrap(),
            PathBuf::from("D:\\OneDrive\\Documents")
        );
        assert_eq!(
            a.resolve(Location::UserDir(UserDir::Video)).unwrap(),
            home.join("Videos")
        );
        assert_eq!(
            a.resolve(Location::LocalAppData("k9s")).unwrap(),
            local_appdata(&home).join("k9s")
        );
        assert_eq!(
            a.resolve(Location::AppData("gnupg")).unwrap(),
            appdata(&home).join("gnupg")
        );
        assert_eq!(a.resolve(Location::DataHome("")), None);
    }
}
