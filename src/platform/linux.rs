//! Linux platform adapter (spec §8). XDG names are localized and the XDG base
//! directories are overridable; both are resolved once, at construction.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::platform::location::under;
use crate::platform::xdg;
use crate::platform::{Location, Platform, PlatformAdapter, UserDir};

pub struct LinuxAdapter {
    home: PathBuf,
    config_home: PathBuf,
    data_home: PathBuf,
    state_home: PathBuf,
    cache_home: PathBuf,
    /// Every `UserDir`, resolved in spec order (user file, defaults file,
    /// English); always complete.
    user_dirs: BTreeMap<UserDir, PathBuf>,
}

impl LinuxAdapter {
    /// The real machine: `$XDG_*` honoured, `/etc/xdg` consulted.
    pub fn detect() -> LinuxAdapter {
        let home = crate::platform::home_dir();
        let config_home = xdg::config_home(&home);
        let user_dirs = xdg::resolve_all(&home, &config_home, Path::new("/etc/xdg"));
        LinuxAdapter {
            data_home: xdg::data_home(&home),
            state_home: xdg::state_home(&home),
            cache_home: xdg::cache_home(&home),
            config_home,
            user_dirs,
            home,
        }
    }

    /// A hermetic adapter for tests: XDG bases are the home-relative defaults
    /// regardless of the environment; `etc_xdg` points at a fixture directory.
    pub fn with_home(home: PathBuf, etc_xdg: PathBuf) -> LinuxAdapter {
        let config_home = home.join(".config");
        let user_dirs = xdg::resolve_all(&home, &config_home, &etc_xdg);
        LinuxAdapter {
            data_home: home.join(".local").join("share"),
            state_home: home.join(".local").join("state"),
            cache_home: home.join(".cache"),
            config_home,
            user_dirs,
            home,
        }
    }
}

impl PlatformAdapter for LinuxAdapter {
    fn platform(&self) -> Platform {
        Platform::Linux
    }

    fn home(&self) -> &Path {
        &self.home
    }

    fn resolve(&self, loc: Location) -> Option<PathBuf> {
        Some(match loc {
            Location::Home => self.home.clone(),
            Location::HomeRel(rel) => under(self.home.clone(), rel),
            Location::ConfigHome(rel) => under(self.config_home.clone(), rel),
            Location::DataHome(rel) => under(self.data_home.clone(), rel),
            Location::StateHome(rel) => under(self.state_home.clone(), rel),
            Location::AppData(_) | Location::LocalAppData(_) => return None,
            Location::UserDir(d) => self.user_dirs.get(&d)?.clone(),
        })
    }

    fn user_kopia_dirs(&self) -> Vec<PathBuf> {
        vec![
            self.config_home.join("kopia"),
            self.cache_home.join("kopia"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_is_videos_and_localized() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(home.join(".config")).unwrap();
        std::fs::write(
            home.join(".config/user-dirs.dirs"),
            "XDG_VIDEOS_DIR=\"$HOME/Vidéos\"\n",
        )
        .unwrap();
        let a = LinuxAdapter::with_home(home.clone(), tmp.path().join("no-etc"));
        assert_eq!(
            a.resolve(Location::UserDir(UserDir::Video)).unwrap(),
            home.join("Vidéos"),
            "user-dirs.dirs wins"
        );
        assert_eq!(
            a.resolve(Location::UserDir(UserDir::Documents)).unwrap(),
            home.join("Documents"),
            "English default when nothing else says"
        );
        assert_eq!(
            a.resolve(Location::HomeRel(".ssh")).unwrap(),
            home.join(".ssh")
        );
        assert_eq!(
            a.resolve(Location::ConfigHome("k9s")).unwrap(),
            home.join(".config/k9s"),
            "macOS Application Support/k9s lands in XDG config on Linux"
        );
        assert_eq!(
            a.resolve(Location::DataHome("")).unwrap(),
            home.join(".local/share")
        );
        assert_eq!(a.resolve(Location::LocalAppData("k9s")), None);
    }
}
