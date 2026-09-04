//! macOS platform adapter (spec §8).
//!
//! The eight standard directories come from Apple's user template at
//! `/System/Library/User Template/Non_localized/`. It is `~/Movies`; there is
//! no `~/Videos` on macOS.

use std::path::{Path, PathBuf};

use crate::platform::{KnownDir, Platform, PlatformAdapter};
use crate::profile::model::SemanticId;

pub struct MacOsAdapter {
    home: PathBuf,
}

/// (semantic id, on-disk name). Verified against the user template on
/// macOS 26.5.1.
pub const TEMPLATE_DIRS: [(&str, &str); 7] = [
    ("desktop", "Desktop"),
    ("documents", "Documents"),
    ("downloads", "Downloads"),
    ("video", "Movies"),
    ("music", "Music"),
    ("pictures", "Pictures"),
    ("public", "Public"),
];

/// Cloud-drive roots that are never included (spec §8).
pub const CLOUD_DRIVE_DIRS: [&str; 6] = [
    "Library/Mobile Documents",
    "Library/CloudStorage",
    "Dropbox",
    "OneDrive",
    "Nextcloud",
    "Box",
];

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

pub fn destination_for(home: &Path, id: &SemanticId) -> Option<PathBuf> {
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
        "config" => home.join(".config"),
        "app_support" => home.join("Library/Application Support"),
        "preferences" => home.join("Library/Preferences"),
        other => {
            let name = TEMPLATE_DIRS.iter().find(|(i, _)| *i == other)?.1;
            home.join(name)
        }
    })
}

impl PlatformAdapter for MacOsAdapter {
    fn platform(&self) -> Platform {
        Platform::MacOs
    }

    fn home(&self) -> PathBuf {
        self.home.clone()
    }

    fn known_dirs(&self) -> Vec<KnownDir> {
        TEMPLATE_DIRS
            .iter()
            .map(|(id, name)| KnownDir {
                id: SemanticId::new(*id),
                path: self.home.join(name),
            })
            .filter(|k| k.path.is_dir())
            .collect()
    }

    fn destination_for(&self, id: &SemanticId) -> Option<PathBuf> {
        destination_for(&self.home, id)
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

    #[test]
    fn video_is_movies() {
        let home = Path::new("/Users/rhys");
        assert_eq!(
            destination_for(home, &SemanticId::new("video")).unwrap(),
            PathBuf::from("/Users/rhys/Movies")
        );
        assert_eq!(
            destination_for(home, &SemanticId::new("ssh")).unwrap(),
            PathBuf::from("/Users/rhys/.ssh")
        );
        assert_eq!(destination_for(home, &SemanticId::new("nope")), None);
        assert_eq!(
            destination_for(home, &SemanticId::custom(Path::new("Projects"))).unwrap(),
            PathBuf::from("/Users/rhys/Projects")
        );
    }

    #[test]
    fn known_dirs_only_existing() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("Movies")).unwrap();
        let a = MacOsAdapter::with_home(tmp.path().to_path_buf());
        let k = a.known_dirs();
        assert_eq!(k.len(), 1);
        assert_eq!(k[0].id.as_str(), "video");
    }
}
