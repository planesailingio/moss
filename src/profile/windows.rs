//! Windows platform adapter (spec §8). Known folders via `SHGetKnownFolderPath`;
//! nothing is hardcoded because Folder Redirection and OneDrive move them.

use std::path::{Path, PathBuf};

use crate::platform::{KnownDir, Platform, PlatformAdapter};
use crate::profile::model::SemanticId;

pub struct WindowsAdapter {
    home: PathBuf,
    resolved: Vec<(SemanticId, PathBuf)>,
}

impl WindowsAdapter {
    pub fn detect() -> WindowsAdapter {
        let home = crate::platform::home_dir();
        WindowsAdapter {
            resolved: resolve_known_folders(),
            home,
        }
    }

    pub fn with(home: PathBuf, resolved: Vec<(SemanticId, PathBuf)>) -> WindowsAdapter {
        WindowsAdapter { home, resolved }
    }
}

#[cfg(target_os = "windows")]
fn resolve_known_folders() -> Vec<(SemanticId, PathBuf)> {
    use known_folders::{KnownFolder, get_known_folder_path};
    let wanted: [(&str, KnownFolder); 7] = [
        ("desktop", KnownFolder::Desktop),
        ("documents", KnownFolder::Documents),
        ("downloads", KnownFolder::Downloads),
        ("pictures", KnownFolder::Pictures),
        ("video", KnownFolder::Videos),
        ("music", KnownFolder::Music),
        ("public", KnownFolder::Public),
    ];
    wanted
        .iter()
        .filter_map(|(id, folder)| {
            // Each FOLDERID is individually fallible (E_INVALIDARG on old systems).
            get_known_folder_path(*folder).map(|p| (SemanticId::new(*id), p))
        })
        .collect()
}

#[cfg(not(target_os = "windows"))]
fn resolve_known_folders() -> Vec<(SemanticId, PathBuf)> {
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

pub fn destination_for(
    home: &Path,
    resolved: &[(SemanticId, PathBuf)],
    id: &SemanticId,
) -> Option<PathBuf> {
    if let Some(rel) = id.custom_relative() {
        return Some(home.join(rel));
    }
    Some(match id.as_str() {
        "user_home" => home.to_path_buf(),
        "aws" => home.join(".aws"),
        "ssh" => home.join(".ssh"),
        "gnupg" => appdata(home).join("gnupg"),
        "kubernetes" => home.join(".kube"),
        "docker" => home.join(".docker"),
        "git" => home.join(".gitconfig"),
        "shell" => home.to_path_buf(),
        "config" => home.join(".config"),
        "app_support" => appdata(home),
        other => {
            if let Some((_, p)) = resolved.iter().find(|(i, _)| i.as_str() == other) {
                return Some(p.clone());
            }
            let default = match other {
                "desktop" => "Desktop",
                "documents" => "Documents",
                "downloads" => "Downloads",
                "pictures" => "Pictures",
                "video" => "Videos",
                "music" => "Music",
                "public" => "Public",
                _ => return None,
            };
            home.join(default)
        }
    })
}

impl PlatformAdapter for WindowsAdapter {
    fn platform(&self) -> Platform {
        Platform::Windows
    }

    fn home(&self) -> PathBuf {
        self.home.clone()
    }

    fn known_dirs(&self) -> Vec<KnownDir> {
        self.resolved
            .iter()
            .map(|(id, path)| KnownDir {
                id: id.clone(),
                path: path.clone(),
            })
            .filter(|k| k.path.is_dir())
            .collect()
    }

    fn destination_for(&self, id: &SemanticId) -> Option<PathBuf> {
        destination_for(&self.home, &self.resolved, id)
    }

    fn user_kopia_dirs(&self) -> Vec<PathBuf> {
        vec![
            appdata(&self.home).join("kopia"),
            local_appdata(&self.home).join("kopia"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_is_videos_and_redirection_wins() {
        let home = Path::new("C:\\Users\\rhys");
        let redirected = vec![(
            SemanticId::new("documents"),
            PathBuf::from("D:\\OneDrive\\Documents"),
        )];
        assert_eq!(
            destination_for(home, &redirected, &SemanticId::new("documents")).unwrap(),
            PathBuf::from("D:\\OneDrive\\Documents")
        );
        assert_eq!(
            destination_for(home, &redirected, &SemanticId::new("video")).unwrap(),
            home.join("Videos")
        );
        assert_eq!(destination_for(home, &[], &SemanticId::new("nope")), None);
    }
}
