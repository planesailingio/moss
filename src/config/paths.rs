//! Where moss keeps things (spec §24, §10).
//!
//! | OS      | config                                   | state                                | cache                       |
//! |---------|------------------------------------------|--------------------------------------|-----------------------------|
//! | macOS   | ~/Library/Application Support/moss       | ~/Library/Application Support/moss   | ~/Library/Caches/moss       |
//! | Linux   | $XDG_CONFIG_HOME/moss                    | $XDG_STATE_HOME/moss                 | $XDG_CACHE_HOME/moss        |
//! | Windows | %APPDATA%\moss                           | %LOCALAPPDATA%\moss                  | %LOCALAPPDATA%\moss\cache   |
//!
//! `directories` appends `\config`, `\data`, `\cache` on Windows; we strip them
//! so the layout is one directory per purpose on every OS.

use std::path::{Path, PathBuf};

use crate::error::{MossError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MossPaths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl MossPaths {
    /// Resolve from the environment. `MOSS_STATE_DIR` and `MOSS_CACHE_DIR`
    /// override the platform defaults (used by tests and schedulers).
    pub fn resolve() -> Result<MossPaths> {
        if let Some(root) = std::env::var_os("MOSS_HOME").filter(|s| !s.is_empty()) {
            let root = PathBuf::from(root);
            return Ok(MossPaths {
                config_dir: root.join("config"),
                state_dir: root.join("state"),
                cache_dir: root.join("cache"),
            });
        }
        let dirs = directories::ProjectDirs::from("", "", "moss")
            .ok_or_else(|| MossError::Config("cannot determine a home directory".into()))?;
        let config_dir = strip_trailing(dirs.config_dir(), "config");
        let state_dir = match dirs.state_dir() {
            Some(s) => s.to_path_buf(),
            None => strip_trailing(dirs.data_local_dir(), "data"),
        };
        let cache_dir = if cfg!(windows) {
            dirs.cache_dir().to_path_buf()
        } else {
            strip_trailing(dirs.cache_dir(), "cache")
        };
        let mut p = MossPaths {
            config_dir,
            state_dir,
            cache_dir,
        };
        if let Some(s) = std::env::var_os("MOSS_STATE_DIR").filter(|s| !s.is_empty()) {
            p.state_dir = PathBuf::from(s);
        }
        if let Some(c) = std::env::var_os("MOSS_CACHE_DIR").filter(|s| !s.is_empty()) {
            p.cache_dir = PathBuf::from(c);
        }
        Ok(p)
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.yaml")
    }

    pub fn lock_file(&self) -> PathBuf {
        self.state_dir.join("lock")
    }

    pub fn scan_index(&self) -> PathBuf {
        self.state_dir.join("index.json")
    }

    pub fn manifests_dir(&self) -> PathBuf {
        self.state_dir.join("manifests")
    }

    pub fn restore_journal(&self) -> PathBuf {
        self.state_dir.join("restore-journal.json")
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.state_dir.join("staging")
    }

    /// Kopia's config file for the given repository id (spec §5).
    pub fn kopia_dir(&self) -> PathBuf {
        self.state_dir.join("kopia")
    }

    pub fn kopia_config(&self, repo_id: &str) -> PathBuf {
        self.kopia_dir().join(format!("{repo_id}.config"))
    }

    pub fn kopia_cache(&self) -> PathBuf {
        self.cache_dir.join("kopia")
    }

    pub fn kopia_logs(&self) -> PathBuf {
        self.state_dir.join("kopia-logs")
    }

    /// Everything moss owns, for exclusion from backups.
    pub fn all_dirs(&self) -> Vec<PathBuf> {
        vec![
            self.config_dir.clone(),
            self.state_dir.clone(),
            self.cache_dir.clone(),
        ]
    }

    /// Create the state and cache directories with restrictive modes.
    pub fn ensure(&self) -> Result<()> {
        for d in [&self.config_dir, &self.state_dir, &self.cache_dir] {
            create_private_dir(d)?;
        }
        Ok(())
    }
}

fn strip_trailing(p: &Path, name: &str) -> PathBuf {
    if cfg!(windows) && p.file_name().and_then(|n| n.to_str()) == Some(name) {
        p.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| p.to_path_buf())
    } else {
        p.to_path_buf()
    }
}

/// `mkdir -p` with mode 0700 on Unix.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Ensure a file is private (0600 on Unix).
pub fn make_private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Report whether a file/dir mode is wider than allowed (Unix only; always ok elsewhere).
pub fn mode_is_private(path: &Path, max_mode: u32) -> std::io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        Ok(mode & !max_mode == 0)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, max_mode);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moss_home_overrides_everything() {
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: tests in this module run single-threaded with respect to this variable.
        unsafe { std::env::set_var("MOSS_HOME", tmp.path()) };
        let p = MossPaths::resolve().unwrap();
        unsafe { std::env::remove_var("MOSS_HOME") };
        assert_eq!(p.config_dir, tmp.path().join("config"));
        assert_eq!(p.state_dir, tmp.path().join("state"));
        assert_eq!(
            p.kopia_config("abc"),
            tmp.path().join("state/kopia/abc.config")
        );
    }

    #[test]
    fn private_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("a/b");
        create_private_dir(&d).unwrap();
        assert!(mode_is_private(&d, 0o700).unwrap());
    }
}
