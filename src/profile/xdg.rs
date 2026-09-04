//! XDG user-directory resolution (spec §8, Linux).
//!
//! 1. `$XDG_CONFIG_HOME/user-dirs.dirs` — `XDG_VIDEOS_DIR="$HOME/Vidéos"`;
//!    a value of exactly `$HOME/` means disabled.
//! 2. `/etc/xdg/user-dirs.defaults` — `VIDEOS=Videos`, relative to home.
//! 3. English defaults.
//!
//! The `dirs` crate does step 1 only, so this is in-tree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const KEYS: [&str; 8] = [
    "DESKTOP",
    "DOWNLOAD",
    "TEMPLATES",
    "PUBLICSHARE",
    "DOCUMENTS",
    "MUSIC",
    "PICTURES",
    "VIDEOS",
];

pub fn english_default(key: &str) -> Option<&'static str> {
    Some(match key {
        "DESKTOP" => "Desktop",
        "DOWNLOAD" => "Downloads",
        "TEMPLATES" => "Templates",
        "PUBLICSHARE" => "Public",
        "DOCUMENTS" => "Documents",
        "MUSIC" => "Music",
        "PICTURES" => "Pictures",
        "VIDEOS" => "Videos",
        _ => return None,
    })
}

/// Parse `user-dirs.dirs` content. Returns key → absolute path; disabled
/// entries (`$HOME/`) are omitted.
pub fn parse_user_dirs(text: &str, home: &Path) -> BTreeMap<String, PathBuf> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let Some(key) = k
            .trim()
            .strip_prefix("XDG_")
            .and_then(|k| k.strip_suffix("_DIR"))
        else {
            continue;
        };
        let v = v.trim().trim_matches('"');
        let path = if let Some(rest) = v.strip_prefix("$HOME/") {
            if rest.is_empty() {
                continue; // disabled
            }
            home.join(rest.trim_end_matches('/'))
        } else if v == "$HOME" {
            continue;
        } else if v.starts_with('/') {
            PathBuf::from(v.trim_end_matches('/'))
        } else {
            home.join(v.trim_end_matches('/'))
        };
        out.insert(key.to_string(), path);
    }
    out
}

/// Parse `/etc/xdg/user-dirs.defaults` content (`VIDEOS=Videos`).
pub fn parse_defaults(text: &str, home: &Path) -> BTreeMap<String, PathBuf> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"');
        if !v.is_empty() {
            out.insert(k.trim().to_string(), home.join(v));
        }
    }
    out
}

/// Full resolution for one key, in spec order. Reads the files under `config_home`
/// and `etc_xdg` so tests can point them at fixtures.
pub fn resolve_all(home: &Path, config_home: &Path, etc_xdg: &Path) -> BTreeMap<String, PathBuf> {
    let user = std::fs::read_to_string(config_home.join("user-dirs.dirs"))
        .map(|t| parse_user_dirs(&t, home))
        .unwrap_or_default();
    let defaults = std::fs::read_to_string(etc_xdg.join("user-dirs.defaults"))
        .map(|t| parse_defaults(&t, home))
        .unwrap_or_default();
    let mut out = BTreeMap::new();
    for key in KEYS {
        let path = user
            .get(key)
            .cloned()
            .or_else(|| defaults.get(key).cloned())
            .or_else(|| english_default(key).map(|d| home.join(d)));
        if let Some(p) = path {
            out.insert(key.to_string(), p);
        }
    }
    out
}

pub fn config_home(home: &Path) -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
}

pub fn data_home(home: &Path) -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"))
}

pub fn cache_home(home: &Path) -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".cache"))
}

pub fn state_home(home: &Path) -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/state"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localized_french_desktop() {
        let home = Path::new("/home/rhys");
        let text = "# comment\nXDG_DESKTOP_DIR=\"$HOME/Bureau\"\nXDG_VIDEOS_DIR=\"$HOME/Vidéos\"\nXDG_TEMPLATES_DIR=\"$HOME/\"\nXDG_MUSIC_DIR=\"/mnt/music/\"\n";
        let m = parse_user_dirs(text, home);
        assert_eq!(m["DESKTOP"], PathBuf::from("/home/rhys/Bureau"));
        assert_eq!(m["VIDEOS"], PathBuf::from("/home/rhys/Vidéos"));
        assert!(!m.contains_key("TEMPLATES"), "disabled entries are omitted");
        assert_eq!(m["MUSIC"], PathBuf::from("/mnt/music"));
    }

    #[test]
    fn resolution_order() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let cfg = home.join(".config");
        let etc = tmp.path().join("etc/xdg");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(
            cfg.join("user-dirs.dirs"),
            "XDG_VIDEOS_DIR=\"$HOME/Vidéos\"\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("user-dirs.defaults"),
            "DOCUMENTS=Dokumente\nVIDEOS=Filme\n",
        )
        .unwrap();
        let m = resolve_all(&home, &cfg, &etc);
        assert_eq!(m["VIDEOS"], home.join("Vidéos"), "user file wins");
        assert_eq!(
            m["DOCUMENTS"],
            home.join("Dokumente"),
            "defaults file second"
        );
        assert_eq!(m["MUSIC"], home.join("Music"), "English last");
        assert_eq!(m.len(), 8);
    }
}
