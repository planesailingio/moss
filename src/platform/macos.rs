//! macOS platform adapter (spec §8).
//!
//! The standard directories come from Apple's user template at
//! `/System/Library/User Template/Non_localized/` (`UserDir::macos_name`).
//! It is `~/Movies`; there is no `~/Videos` on macOS.

use std::path::{Path, PathBuf};

use crate::platform::location::under;
use crate::platform::{Location, Platform, PlatformAdapter};

pub struct MacOsAdapter {
    home: PathBuf,
}

impl MacOsAdapter {
    pub fn detect() -> MacOsAdapter {
        MacOsAdapter {
            home: crate::platform::home_dir(),
        }
    }

    pub fn with_home(home: PathBuf) -> MacOsAdapter {
        MacOsAdapter { home }
    }
}

impl PlatformAdapter for MacOsAdapter {
    fn platform(&self) -> Platform {
        Platform::MacOs
    }

    fn home(&self) -> &Path {
        &self.home
    }

    fn resolve(&self, loc: Location) -> Option<PathBuf> {
        let home = self.home.clone();
        Some(match loc {
            Location::Home => home,
            Location::HomeRel(rel) => under(home, rel),
            Location::ConfigHome(rel) => under(home.join(".config"), rel),
            Location::DataHome(rel) => under(home.join(".local").join("share"), rel),
            Location::StateHome(rel) => under(home.join(".local").join("state"), rel),
            Location::AppData(_) | Location::LocalAppData(_) => return None,
            Location::UserDir(d) => home.join(d.macos_name()),
        })
    }

    fn user_kopia_dirs(&self) -> Vec<PathBuf> {
        vec![
            self.home.join("Library/Application Support/kopia"),
            self.home.join("Library/Caches/kopia"),
            self.home.join("Library/Logs/kopia"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::UserDir;

    #[test]
    fn video_is_movies() {
        let a = MacOsAdapter::with_home(PathBuf::from("/Users/rhys"));
        assert_eq!(
            a.resolve(Location::UserDir(UserDir::Video)).unwrap(),
            PathBuf::from("/Users/rhys/Movies")
        );
        assert_eq!(
            a.resolve(Location::HomeRel(".ssh")).unwrap(),
            PathBuf::from("/Users/rhys/.ssh")
        );
        assert_eq!(
            a.resolve(Location::ConfigHome("")).unwrap(),
            PathBuf::from("/Users/rhys/.config")
        );
        assert_eq!(a.resolve(Location::AppData("x")), None);
    }
}
