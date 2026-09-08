//! The one table of built-in sources (spec §8, §15).
//!
//! Every fact moss knows about a built-in source is a field of one row here:
//! its semantic id, category, portability, default action, sensitivity, the
//! reason shown in `inspect`, and where it lives on each OS as a
//! [`Location`]. Discovery reads the table on this machine; restore reads it
//! to map an id from another machine onto this one; nothing else lists ids.
//!
//! Two rows may share an id when a tool keeps state in two places (`k9s`);
//! only one of them is the restore destination (`Role::Source`), the other is
//! `Role::DiscoverOnly`. `Role::RestoreOnly` rows (`user_home`, `shell`) are
//! spec §15 destinations that are never discovered as sources.

use std::path::{Path, PathBuf};

use crate::model::{Inclusion, Platform, Portability, ProfileCategory, SemanticId};
use crate::platform::{Location, PlatformAdapter, UserDir};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Discovered when present; the restore destination for its id.
    Source,
    /// Discovered when present; never a destination (a second location of an
    /// id that already has a `Source` row).
    DiscoverOnly,
    /// Never discovered; destination only.
    RestoreOnly,
}

#[derive(Debug, Clone, Copy)]
pub struct Builtin {
    pub id: &'static str,
    pub category: ProfileCategory,
    pub portable: Portability,
    pub action: Inclusion,
    pub sensitive: bool,
    pub reason: &'static str,
    pub role: Role,
    /// Discovery probes this row only on this platform (`None` = wherever it
    /// has a location). Restore ignores it: `app_support` is discovered on
    /// macOS only but restorable everywhere.
    pub only: Option<Platform>,
    pub macos: Option<Location>,
    pub linux: Option<Location>,
    pub windows: Option<Location>,
}

impl Builtin {
    pub fn location(&self, platform: Platform) -> Option<Location> {
        match platform {
            Platform::MacOs => self.macos,
            Platform::Linux => self.linux,
            Platform::Windows => self.windows,
        }
    }

    /// Whether discovery considers this row on `platform`.
    pub fn discovered_on(&self, platform: Platform) -> bool {
        self.role != Role::RestoreOnly
            && self.only.is_none_or(|p| p == platform)
            && self.location(platform).is_some()
    }
}

use Inclusion::{Include, OptIn};
use Location::{AppData, ConfigHome, DataHome, Home, HomeRel, LocalAppData, StateHome};
use Portability::{
    MachineSpecific, PlatformSpecific, Portable, PortableWithPathTranslation as Pwpt,
};
use ProfileCategory::{ApplicationState, Configuration, Credentials, Development, PersonalData};

/// A row that lives at the same home-relative path on every OS.
const fn everywhere(
    id: &'static str,
    rel: &'static str,
    category: ProfileCategory,
    portable: Portability,
    sensitive: bool,
    reason: &'static str,
) -> Builtin {
    Builtin {
        id,
        category,
        portable,
        action: Include,
        sensitive,
        reason,
        role: Role::Source,
        only: None,
        macos: Some(HomeRel(rel)),
        linux: Some(HomeRel(rel)),
        windows: Some(HomeRel(rel)),
    }
}

/// A macOS-only `~/Library` row.
const fn library(
    id: &'static str,
    rel: &'static str,
    category: ProfileCategory,
    action: Inclusion,
    reason: &'static str,
) -> Builtin {
    Builtin {
        id,
        category,
        portable: PlatformSpecific,
        action,
        sensitive: false,
        reason,
        role: Role::Source,
        only: Some(Platform::MacOs),
        macos: Some(HomeRel(rel)),
        linux: None,
        windows: None,
    }
}

const fn user_dir(d: UserDir, action: Inclusion, reason: &'static str) -> Builtin {
    Builtin {
        id: d.id(),
        category: PersonalData,
        portable: Pwpt,
        action,
        sensitive: false,
        reason,
        role: Role::Source,
        only: None,
        macos: Some(Location::UserDir(d)),
        linux: Some(Location::UserDir(d)),
        windows: Some(Location::UserDir(d)),
    }
}

pub const BUILTINS: &[Builtin] = &[
    // Standard user directories (spec §8).
    user_dir(UserDir::Documents, Include, "Standard documents folder"),
    user_dir(UserDir::Desktop, Include, "Desktop"),
    user_dir(
        UserDir::Downloads,
        OptIn,
        "Downloads (transient by default; opt-in)",
    ),
    user_dir(UserDir::Pictures, Include, "Pictures"),
    user_dir(
        UserDir::Video,
        Include,
        "Video folder (Movies on macOS, Videos elsewhere)",
    ),
    user_dir(UserDir::Music, Include, "Music"),
    user_dir(UserDir::Public, Include, "Public folder"),
    // Credentials and tool configuration in home.
    everywhere(
        "ssh",
        ".ssh",
        Credentials,
        Portable,
        true,
        "SSH keys, config and known hosts",
    ),
    everywhere(
        "aws",
        ".aws",
        Credentials,
        Portable,
        true,
        "AWS CLI configuration and credentials",
    ),
    Builtin {
        // GnuPG keeps its home under %APPDATA% on Windows (spec §15).
        windows: Some(AppData("gnupg")),
        ..everywhere(
            "gnupg",
            ".gnupg",
            Credentials,
            Portable,
            true,
            "GnuPG keyrings and trust database",
        )
    },
    Builtin {
        // A Windows user may also have a Unix-style ~/.gnupg (Git for Windows, WSL exports).
        role: Role::DiscoverOnly,
        only: Some(Platform::Windows),
        macos: None,
        linux: None,
        ..everywhere(
            "gnupg",
            ".gnupg",
            Credentials,
            Portable,
            true,
            "GnuPG keyrings and trust database",
        )
    },
    everywhere(
        "kubernetes",
        ".kube",
        Credentials,
        Pwpt,
        true,
        "Kubernetes contexts and credentials",
    ),
    everywhere(
        "docker",
        ".docker",
        Configuration,
        Pwpt,
        true,
        "Docker CLI config and contexts (VM images excluded)",
    ),
    everywhere(
        "git",
        ".gitconfig",
        Configuration,
        Pwpt,
        false,
        "Global Git configuration",
    ),
    everywhere(
        "azure",
        ".azure",
        Credentials,
        Portable,
        true,
        "Azure CLI profile and tokens",
    ),
    everywhere(
        "talos",
        ".talos",
        Credentials,
        Portable,
        false,
        "Talos cluster configuration",
    ),
    everywhere(
        "terraform",
        ".terraform.d",
        Development,
        Portable,
        true,
        "Terraform CLI credentials and plugin cache config",
    ),
    // k9s: Application Support on macOS, XDG config elsewhere, %LOCALAPPDATA% on Windows.
    Builtin {
        id: "k9s",
        category: Development,
        portable: Pwpt,
        action: Include,
        sensitive: false,
        reason: "k9s configuration, skins and plugins",
        role: Role::Source,
        only: None,
        macos: Some(HomeRel("Library/Application Support/k9s")),
        linux: Some(ConfigHome("k9s")),
        windows: Some(LocalAppData("k9s")),
    },
    Builtin {
        // With XDG_CONFIG_HOME set, k9s uses it on macOS too. Nested under
        // `config`, so it only surfaces on its own when `~/.config` is absent.
        role: Role::DiscoverOnly,
        macos: Some(ConfigHome("k9s")),
        linux: Some(ConfigHome("k9s")),
        windows: Some(ConfigHome("k9s")),
        ..everywhere(
            "k9s",
            "",
            Development,
            Pwpt,
            false,
            "k9s configuration, skins and plugins",
        )
    },
    Builtin {
        id: "config",
        category: Configuration,
        portable: Pwpt,
        action: Include,
        sensitive: false,
        reason: "XDG application configuration (caches excluded)",
        role: Role::Source,
        only: None,
        macos: Some(ConfigHome("")),
        linux: Some(ConfigHome("")),
        windows: Some(ConfigHome("")),
    },
    everywhere(
        "claude",
        ".claude",
        ApplicationState,
        Pwpt,
        false,
        "Claude Code settings, memory and projects",
    ),
    everywhere(
        "codex",
        ".codex",
        ApplicationState,
        Pwpt,
        false,
        "Codex CLI state",
    ),
    everywhere(
        "shell_zshrc",
        ".zshrc",
        Configuration,
        Pwpt,
        false,
        "zsh configuration",
    ),
    everywhere(
        "shell_zprofile",
        ".zprofile",
        Configuration,
        Pwpt,
        false,
        "zsh login configuration",
    ),
    everywhere(
        "shell_bashrc",
        ".bashrc",
        Configuration,
        Pwpt,
        false,
        "bash configuration",
    ),
    everywhere(
        "shell_bash_profile",
        ".bash_profile",
        Configuration,
        Pwpt,
        false,
        "bash login configuration",
    ),
    everywhere(
        "shell_profile",
        ".profile",
        Configuration,
        Pwpt,
        false,
        "POSIX shell login configuration",
    ),
    everywhere(
        "shell_bash_history",
        ".bash_history",
        ApplicationState,
        Portable,
        false,
        "bash history",
    ),
    everywhere(
        "shell_zsh_history",
        ".zsh_history",
        ApplicationState,
        Portable,
        false,
        "zsh history",
    ),
    everywhere(
        "npm_config",
        ".npmrc",
        Development,
        Portable,
        false,
        "npm configuration (cache excluded)",
    ),
    // Linux XDG data.
    Builtin {
        id: "local_share",
        category: ApplicationState,
        portable: Pwpt,
        action: Include,
        sensitive: false,
        reason: "XDG application data (Trash excluded)",
        role: Role::Source,
        only: Some(Platform::Linux),
        macos: None,
        linux: Some(DataHome("")),
        windows: None,
    },
    Builtin {
        id: "local_state",
        category: ApplicationState,
        portable: MachineSpecific,
        action: Include,
        sensitive: false,
        reason: "XDG state",
        role: Role::Source,
        only: Some(Platform::Linux),
        macos: None,
        linux: Some(StateHome("")),
        windows: None,
    },
    Builtin {
        id: "mozilla",
        category: ApplicationState,
        portable: PlatformSpecific,
        action: Include,
        sensitive: false,
        reason: "Firefox profiles",
        role: Role::Source,
        only: Some(Platform::Linux),
        macos: None,
        linux: Some(HomeRel(".mozilla")),
        windows: None,
    },
    Builtin {
        id: "flatpak",
        category: ApplicationState,
        portable: PlatformSpecific,
        action: Include,
        sensitive: false,
        reason: "Flatpak application data",
        role: Role::Source,
        only: Some(Platform::Linux),
        macos: None,
        linux: Some(HomeRel(".var")),
        windows: None,
    },
    // macOS ~/Library. `app_support` is discovered on macOS only but maps onto
    // the platform's application-data root on restore.
    Builtin {
        linux: Some(DataHome("")),
        windows: Some(AppData("")),
        ..library(
            "app_support",
            "Library/Application Support",
            ApplicationState,
            OptIn,
            "macOS application support data (large, mostly app-managed state; opt-in)",
        )
    },
    library(
        "preferences",
        "Library/Preferences",
        ApplicationState,
        Include,
        "macOS preference plists",
    ),
    library(
        "containers",
        "Library/Containers",
        ApplicationState,
        OptIn,
        "Sandboxed app containers (TCC-gated per app; opt-in)",
    ),
    library(
        "group_containers",
        "Library/Group Containers",
        ApplicationState,
        OptIn,
        "App group containers (TCC-gated; opt-in)",
    ),
    library(
        "mail",
        "Library/Mail",
        PersonalData,
        OptIn,
        "Apple Mail (requires Full Disk Access)",
    ),
    // Windows AppData.
    Builtin {
        id: "appdata_roaming",
        category: ApplicationState,
        portable: PlatformSpecific,
        action: Include,
        sensitive: false,
        reason: "Roaming application data",
        role: Role::Source,
        only: Some(Platform::Windows),
        macos: None,
        linux: None,
        windows: Some(AppData("")),
    },
    Builtin {
        id: "appdata_local",
        category: ApplicationState,
        portable: MachineSpecific,
        action: OptIn,
        sensitive: false,
        reason: "Local application data (caches excluded)",
        role: Role::Source,
        only: Some(Platform::Windows),
        macos: None,
        linux: None,
        windows: Some(LocalAppData("")),
    },
    // Spec §15 restore-only destinations.
    Builtin {
        id: "user_home",
        category: PersonalData,
        portable: Pwpt,
        action: Include,
        sensitive: false,
        reason: "The home directory itself",
        role: Role::RestoreOnly,
        only: None,
        macos: Some(Home),
        linux: Some(Home),
        windows: Some(Home),
    },
    Builtin {
        id: "shell",
        category: Configuration,
        portable: Pwpt,
        action: Include,
        sensitive: false,
        reason: "Shell configuration files in home",
        role: Role::RestoreOnly,
        only: None,
        macos: Some(Home),
        linux: Some(Home),
        windows: Some(Home),
    },
];

/// The row that restore maps `id` through, if any.
pub fn source_row(id: &str) -> Option<&'static Builtin> {
    BUILTINS
        .iter()
        .find(|b| b.id == id && b.role != Role::DiscoverOnly)
}

/// Where this platform expects a semantic id to live, whether or not it
/// currently exists (spec §15). User includes (`custom:<rel>`) land under home.
pub fn destination_for(adapter: &dyn PlatformAdapter, id: &SemanticId) -> Option<PathBuf> {
    if let Some(rel) = id.custom_relative() {
        return Some(adapter.home().join(rel));
    }
    let row = source_row(id.as_str())?;
    adapter.resolve(row.location(adapter.platform())?)
}

/// Whether a user-included path is one of the sensitive built-in sources
/// (used when an include names a built-in location by path).
pub fn is_sensitive_path(adapter: &dyn PlatformAdapter, path: &Path) -> bool {
    let platform = adapter.platform();
    BUILTINS.iter().any(|b| {
        b.sensitive
            && b.location(platform)
                .and_then(|l| adapter.resolve(l))
                .is_some_and(|p| p == path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::LinuxAdapter;
    use crate::platform::macos::MacOsAdapter;
    use crate::platform::windows::WindowsAdapter;

    fn adapters(home: &Path, etc: &Path) -> Vec<(Platform, Box<dyn PlatformAdapter>)> {
        vec![
            (
                Platform::MacOs,
                Box::new(MacOsAdapter::with_home(home.to_path_buf())),
            ),
            (
                Platform::Linux,
                Box::new(LinuxAdapter::with_home(
                    home.to_path_buf(),
                    etc.to_path_buf(),
                )),
            ),
            (
                Platform::Windows,
                Box::new(WindowsAdapter::with(home.to_path_buf(), vec![])),
            ),
        ]
    }

    /// The bug this table exists to prevent: an id that discovery emits but
    /// restore cannot place.
    #[test]
    fn every_builtin_resolves_on_each_platform_it_applies_to() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        for (platform, adapter) in adapters(&home, &tmp.path().join("no-etc")) {
            for b in BUILTINS {
                let Some(loc) = b.location(platform) else {
                    continue;
                };
                let resolved = adapter
                    .resolve(loc)
                    .unwrap_or_else(|| panic!("{} has no {platform:?} base for {loc:?}", b.id));
                if loc != Home {
                    assert!(
                        resolved.starts_with(&home) || matches!(loc, AppData(_) | LocalAppData(_)),
                        "{} resolves outside home on {platform:?}: {}",
                        b.id,
                        resolved.display()
                    );
                }
                if b.role == Role::Source {
                    assert_eq!(
                        destination_for(adapter.as_ref(), &SemanticId::new(b.id)),
                        Some(resolved),
                        "{} must round-trip through destination_for on {platform:?}",
                        b.id
                    );
                }
            }
        }
    }

    #[test]
    fn exactly_one_source_row_per_id_and_restore_only_rows_map_everywhere() {
        let mut seen = std::collections::BTreeMap::new();
        for b in BUILTINS {
            if b.role != Role::DiscoverOnly {
                *seen.entry(b.id).or_insert(0) += 1;
            }
            if b.role == Role::RestoreOnly {
                for p in Platform::ALL {
                    assert!(b.location(p).is_some(), "{} missing on {p:?}", b.id);
                }
            }
        }
        for (id, n) in seen {
            assert_eq!(n, 1, "{id} has {n} restore rows");
        }
        for b in BUILTINS.iter().filter(|b| b.role == Role::DiscoverOnly) {
            assert!(
                source_row(b.id).is_some(),
                "{}: DiscoverOnly without a Source row",
                b.id
            );
        }
    }

    /// Every path the three old `destination_for` functions produced, pinned.
    #[test]
    fn restore_contract() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let etc = tmp.path().join("no-etc");
        let mac = MacOsAdapter::with_home(home.clone());
        let lin = LinuxAdapter::with_home(home.clone(), etc);
        let win = WindowsAdapter::with(
            home.clone(),
            vec![(UserDir::Documents, PathBuf::from("D:\\OneDrive\\Documents"))],
        );
        let d = |a: &dyn PlatformAdapter, id: &str| destination_for(a, &SemanticId::new(id));
        assert_eq!(d(&mac, "video"), Some(home.join("Movies")));
        assert_eq!(d(&lin, "video"), Some(home.join("Videos")));
        assert_eq!(d(&win, "video"), Some(home.join("Videos")));
        assert_eq!(
            d(&win, "documents"),
            Some(PathBuf::from("D:\\OneDrive\\Documents")),
            "known-folder redirection wins"
        );
        assert_eq!(d(&mac, "ssh"), Some(home.join(".ssh")));
        assert_eq!(
            d(&win, "gnupg"),
            Some(crate::platform::windows::appdata(&home).join("gnupg"))
        );
        assert_eq!(d(&lin, "gnupg"), Some(home.join(".gnupg")));
        assert_eq!(
            d(&mac, "app_support"),
            Some(home.join("Library/Application Support"))
        );
        assert_eq!(d(&lin, "app_support"), Some(home.join(".local/share")));
        assert_eq!(
            d(&win, "app_support"),
            Some(crate::platform::windows::appdata(&home))
        );
        assert_eq!(
            d(&mac, "k9s"),
            Some(home.join("Library/Application Support/k9s"))
        );
        assert_eq!(d(&lin, "k9s"), Some(home.join(".config/k9s")));
        assert_eq!(
            d(&win, "k9s"),
            Some(crate::platform::windows::local_appdata(&home).join("k9s"))
        );
        for a in [&mac as &dyn PlatformAdapter, &lin, &win] {
            assert_eq!(d(a, "config"), Some(home.join(".config")));
            assert_eq!(d(a, "user_home"), Some(home.clone()));
            assert_eq!(d(a, "shell"), Some(home.clone()));
            assert_eq!(d(a, "nope"), None);
            assert_eq!(d(a, "custom:Projects"), Some(home.join("Projects")));
            // Previously unmapped ids that discovery backs up by default.
            for id in [
                "shell_zshrc",
                "npm_config",
                "claude",
                "codex",
                "azure",
                "talos",
            ] {
                assert!(d(a, id).is_some(), "{id} has no destination");
            }
        }
        assert_eq!(d(&lin, "mozilla"), Some(home.join(".mozilla")));
        assert_eq!(
            d(&mac, "preferences"),
            Some(home.join("Library/Preferences"))
        );
        assert_eq!(
            d(&win, "appdata_roaming"),
            Some(crate::platform::windows::appdata(&home))
        );
    }

    #[test]
    fn sensitive_path_matches_sensitive_rows_only() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let mac = MacOsAdapter::with_home(home.clone());
        assert!(is_sensitive_path(&mac, &home.join(".ssh")));
        assert!(!is_sensitive_path(&mac, &home.join("Documents")));
        assert!(!is_sensitive_path(&mac, &home.join(".talos")));
    }
}
