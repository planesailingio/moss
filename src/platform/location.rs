//! Where a built-in source lives, expressed once and resolved per OS.
//!
//! `Location` is the vocabulary the built-in table (`profile::locations`)
//! speaks; a `PlatformAdapter` turns it into an absolute path for this machine.
//! `UserDir` folds the standard user directories: the XDG key, the English
//! default, the Apple template name and the Windows known folder all hang off
//! one enum so no two lists can drift.

use std::path::PathBuf;

/// The standard user directories every desktop OS has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UserDir {
    Desktop,
    Documents,
    Downloads,
    Pictures,
    Video,
    Music,
    Public,
}

impl UserDir {
    pub const ALL: [UserDir; 7] = [
        UserDir::Desktop,
        UserDir::Documents,
        UserDir::Downloads,
        UserDir::Pictures,
        UserDir::Video,
        UserDir::Music,
        UserDir::Public,
    ];

    /// The semantic id (spec §15): the same on every OS.
    pub const fn id(self) -> &'static str {
        match self {
            UserDir::Desktop => "desktop",
            UserDir::Documents => "documents",
            UserDir::Downloads => "downloads",
            UserDir::Pictures => "pictures",
            UserDir::Video => "video",
            UserDir::Music => "music",
            UserDir::Public => "public",
        }
    }

    pub fn from_id(id: &str) -> Option<UserDir> {
        UserDir::ALL.into_iter().find(|d| d.id() == id)
    }

    /// The `XDG_<KEY>_DIR` key in `user-dirs.dirs` and `user-dirs.defaults`.
    pub const fn xdg_key(self) -> &'static str {
        match self {
            UserDir::Desktop => "DESKTOP",
            UserDir::Documents => "DOCUMENTS",
            UserDir::Downloads => "DOWNLOAD",
            UserDir::Pictures => "PICTURES",
            UserDir::Video => "VIDEOS",
            UserDir::Music => "MUSIC",
            UserDir::Public => "PUBLICSHARE",
        }
    }

    /// The English on-disk name on Linux and Windows.
    pub const fn english_name(self) -> &'static str {
        match self {
            UserDir::Desktop => "Desktop",
            UserDir::Documents => "Documents",
            UserDir::Downloads => "Downloads",
            UserDir::Pictures => "Pictures",
            UserDir::Video => "Videos",
            UserDir::Music => "Music",
            UserDir::Public => "Public",
        }
    }

    /// The name in Apple's user template (spec §8): it is `Movies`, and
    /// there is no `~/Videos` on macOS.
    pub const fn macos_name(self) -> &'static str {
        match self {
            UserDir::Video => "Movies",
            other => other.english_name(),
        }
    }
}

/// A place a source lives, relative to a per-OS base. Suffixes use forward
/// slashes; `""` means the base directory itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    /// The home directory itself.
    Home,
    /// Relative to home (`.ssh`, `Library/Preferences`).
    HomeRel(&'static str),
    /// `$XDG_CONFIG_HOME` on Linux; `~/.config` elsewhere.
    ConfigHome(&'static str),
    /// `$XDG_DATA_HOME` / `~/.local/share` (Linux only).
    DataHome(&'static str),
    /// `$XDG_STATE_HOME` / `~/.local/state` (Linux only).
    StateHome(&'static str),
    /// `%APPDATA%` (Windows only).
    AppData(&'static str),
    /// `%LOCALAPPDATA%` (Windows only).
    LocalAppData(&'static str),
    /// A standard user directory, resolved by the platform's own mechanism.
    UserDir(UserDir),
}

/// `base` for an empty suffix (no trailing separator), else `base` joined
/// component-wise so the result compares equal to `home.join("a").join("b")`.
pub(crate) fn under(base: PathBuf, rel: &str) -> PathBuf {
    if rel.is_empty() {
        return base;
    }
    let mut p = base;
    for c in rel.split('/').filter(|c| !c.is_empty()) {
        p.push(c);
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_has_no_trailing_separator_for_empty_suffix() {
        let base = PathBuf::from("/h/.config");
        assert_eq!(under(base.clone(), ""), base);
        assert_eq!(under(base.clone(), "k9s"), base.join("k9s"));
        assert_eq!(
            under(PathBuf::from("/h"), "Library/Application Support/k9s"),
            PathBuf::from("/h")
                .join("Library")
                .join("Application Support")
                .join("k9s")
        );
    }

    #[test]
    fn user_dir_names_are_consistent() {
        for d in UserDir::ALL {
            assert_eq!(UserDir::from_id(d.id()), Some(d));
            assert!(d.xdg_key().chars().all(|c| c.is_ascii_uppercase()));
        }
        assert_eq!(UserDir::Video.macos_name(), "Movies");
        assert_eq!(UserDir::Video.english_name(), "Videos");
        assert_eq!(UserDir::Downloads.xdg_key(), "DOWNLOAD");
    }
}
