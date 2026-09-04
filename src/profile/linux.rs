//! Linux platform adapter (spec §8). XDG names are localized; resolve them.

use std::path::{Path, PathBuf};

use crate::platform::{KnownDir, Platform, PlatformAdapter};
use crate::profile::model::SemanticId;
use crate::profile::xdg;

pub struct LinuxAdapter {
    home: PathBuf,
    etc_xdg: PathBuf,
}

pub const XDG_TO_ID: [(&str, &str); 7] = [
    ("DESKTOP", "desktop"),
    ("DOCUMENTS", "documents"),
    ("DOWNLOAD", "downloads"),
    ("VIDEOS", "video"),
    ("MUSIC", "music"),
    ("PICTURES", "pictures"),
    ("PUBLICSHARE", "public"),
];

impl LinuxAdapter {
    pub fn detect() -> LinuxAdapter {
        LinuxAdapter {
            home: crate::platform::home_dir(),
            etc_xdg: PathBuf::from("/etc/xdg"),
        }
    }

    pub fn with_home(home: PathBuf, etc_xdg: PathBuf) -> LinuxAdapter {
        LinuxAdapter { home, etc_xdg }
    }

    fn resolved(&self) -> std::collections::BTreeMap<String, PathBuf> {
        xdg::resolve_all(&self.home, &xdg::config_home(&self.home), &self.etc_xdg)
    }
}

pub fn destination_for(
    home: &Path,
    resolved: &std::collections::BTreeMap<String, PathBuf>,
    id: &SemanticId,
) -> Option<PathBuf> {
    if let Some(rel) = id.custom_relative() {
        return Some(home.join(rel));
    }
    Some(match id.as_str() {
        "user_home" => home.to_path_buf(),
        "aws" => home.join(".aws"),
        "ssh" => home.join(".ssh"),
        "gnupg" => home.join(".gnupg"),
        "kubernetes" => home.join(".kube"),
        "docker" => home.join(".docker"),
        "git" => home.join(".gitconfig"),
        "shell" => home.to_path_buf(),
        "config" => xdg::config_home(home),
        "app_support" => xdg::data_home(home),
        other => {
            let key = XDG_TO_ID.iter().find(|(_, i)| *i == other)?.0;
            resolved.get(key).cloned()?
        }
    })
}

impl PlatformAdapter for LinuxAdapter {
    fn platform(&self) -> Platform {
        Platform::Linux
    }

    fn home(&self) -> PathBuf {
        self.home.clone()
    }

    fn known_dirs(&self) -> Vec<KnownDir> {
        let resolved = self.resolved();
        XDG_TO_ID
            .iter()
            .filter_map(|(key, id)| {
                resolved.get(*key).map(|p| KnownDir {
                    id: SemanticId::new(*id),
                    path: p.clone(),
                })
            })
            .filter(|k| k.path.is_dir() && k.path != self.home)
            .collect()
    }

    fn destination_for(&self, id: &SemanticId) -> Option<PathBuf> {
        destination_for(&self.home, &self.resolved(), id)
    }

    fn user_kopia_dirs(&self) -> Vec<PathBuf> {
        vec![
            xdg::config_home(&self.home).join("kopia"),
            xdg::cache_home(&self.home).join("kopia"),
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
        std::fs::create_dir_all(home.join("Vidéos")).unwrap();
        std::fs::create_dir_all(home.join("Documents")).unwrap();
        // Route XDG_CONFIG_HOME to our fixture without touching the real env:
        let a = LinuxAdapter::with_home(home.clone(), tmp.path().join("no-etc"));
        // config_home() reads the env; in tests HOME-relative default applies
        // unless XDG_CONFIG_HOME is set globally, so guard:
        if std::env::var_os("XDG_CONFIG_HOME").is_none() {
            let k = a.known_dirs();
            let video = k.iter().find(|k| k.id.as_str() == "video").unwrap();
            assert_eq!(video.path, home.join("Vidéos"));
            assert_eq!(
                a.destination_for(&SemanticId::new("video")).unwrap(),
                home.join("Vidéos")
            );
        }
        assert_eq!(
            a.destination_for(&SemanticId::new("ssh")).unwrap(),
            home.join(".ssh")
        );
    }
}
