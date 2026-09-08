//! Profile discovery (spec §8): the platform's standard directories, the
//! well-known dotfiles, and the user's includes, as semantic sources.
//!
//! Every path is validated to exist before it becomes a source. Nothing is
//! invented.

use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::platform::{Platform, PlatformAdapter};
use crate::profile::model::{
    Inclusion, Portability, ProfileCategory, ProfileSource, SemanticId, expand_tilde, home_relative,
};
use crate::profile::sensitive::is_sensitive_source;

/// A dotfile or application directory moss knows about. `path` is
/// home-relative with forward slashes.
struct Known {
    id: &'static str,
    path: &'static str,
    category: ProfileCategory,
    portable: Portability,
    reason: &'static str,
    /// `None` = all platforms.
    only: Option<Platform>,
    action: Inclusion,
}

const KNOWN: &[Known] = &[
    Known {
        id: "ssh",
        path: ".ssh",
        category: ProfileCategory::Credentials,
        portable: Portability::Portable,
        reason: "SSH keys, config and known hosts",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "aws",
        path: ".aws",
        category: ProfileCategory::Credentials,
        portable: Portability::Portable,
        reason: "AWS CLI configuration and credentials",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "gnupg",
        path: ".gnupg",
        category: ProfileCategory::Credentials,
        portable: Portability::Portable,
        reason: "GnuPG keyrings and trust database",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "kubernetes",
        path: ".kube",
        category: ProfileCategory::Credentials,
        portable: Portability::PortableWithPathTranslation,
        reason: "Kubernetes contexts and credentials",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "docker",
        path: ".docker",
        category: ProfileCategory::Configuration,
        portable: Portability::PortableWithPathTranslation,
        reason: "Docker CLI config and contexts (VM images excluded)",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "git",
        path: ".gitconfig",
        category: ProfileCategory::Configuration,
        portable: Portability::PortableWithPathTranslation,
        reason: "Global Git configuration",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "azure",
        path: ".azure",
        category: ProfileCategory::Credentials,
        portable: Portability::Portable,
        reason: "Azure CLI profile and tokens",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "talos",
        path: ".talos",
        category: ProfileCategory::Credentials,
        portable: Portability::Portable,
        reason: "Talos cluster configuration",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "terraform",
        path: ".terraform.d",
        category: ProfileCategory::Development,
        portable: Portability::Portable,
        reason: "Terraform CLI credentials and plugin cache config",
        only: None,
        action: Inclusion::Include,
    },
    // k9s keeps config, skins, plugins and hotkeys here. Same id on every
    // platform; the path differs. `~/.config/k9s` is nested under the
    // `config` source, so it only surfaces on its own when `~/.config` is not
    // itself selected; restore still maps `k9s` onto it (spec §15).
    Known {
        id: "k9s",
        path: "Library/Application Support/k9s",
        category: ProfileCategory::Development,
        portable: Portability::PortableWithPathTranslation,
        reason: "k9s configuration, skins and plugins",
        only: Some(Platform::MacOs),
        action: Inclusion::Include,
    },
    Known {
        id: "k9s",
        path: ".config/k9s",
        category: ProfileCategory::Development,
        portable: Portability::PortableWithPathTranslation,
        reason: "k9s configuration, skins and plugins",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "config",
        path: ".config",
        category: ProfileCategory::Configuration,
        portable: Portability::PortableWithPathTranslation,
        reason: "XDG application configuration (caches excluded)",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "claude",
        path: ".claude",
        category: ProfileCategory::ApplicationState,
        portable: Portability::PortableWithPathTranslation,
        reason: "Claude Code settings, memory and projects",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "codex",
        path: ".codex",
        category: ProfileCategory::ApplicationState,
        portable: Portability::PortableWithPathTranslation,
        reason: "Codex CLI state",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "shell_zshrc",
        path: ".zshrc",
        category: ProfileCategory::Configuration,
        portable: Portability::PortableWithPathTranslation,
        reason: "zsh configuration",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "shell_zprofile",
        path: ".zprofile",
        category: ProfileCategory::Configuration,
        portable: Portability::PortableWithPathTranslation,
        reason: "zsh login configuration",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "shell_bashrc",
        path: ".bashrc",
        category: ProfileCategory::Configuration,
        portable: Portability::PortableWithPathTranslation,
        reason: "bash configuration",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "shell_bash_profile",
        path: ".bash_profile",
        category: ProfileCategory::Configuration,
        portable: Portability::PortableWithPathTranslation,
        reason: "bash login configuration",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "shell_profile",
        path: ".profile",
        category: ProfileCategory::Configuration,
        portable: Portability::PortableWithPathTranslation,
        reason: "POSIX shell login configuration",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "shell_bash_history",
        path: ".bash_history",
        category: ProfileCategory::ApplicationState,
        portable: Portability::Portable,
        reason: "bash history",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "shell_zsh_history",
        path: ".zsh_history",
        category: ProfileCategory::ApplicationState,
        portable: Portability::Portable,
        reason: "zsh history",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "npm_config",
        path: ".npmrc",
        category: ProfileCategory::Development,
        portable: Portability::Portable,
        reason: "npm configuration (cache excluded)",
        only: None,
        action: Inclusion::Include,
    },
    Known {
        id: "local_share",
        path: ".local/share",
        category: ProfileCategory::ApplicationState,
        portable: Portability::PortableWithPathTranslation,
        reason: "XDG application data (Trash excluded)",
        only: Some(Platform::Linux),
        action: Inclusion::Include,
    },
    Known {
        id: "local_state",
        path: ".local/state",
        category: ProfileCategory::ApplicationState,
        portable: Portability::MachineSpecific,
        reason: "XDG state",
        only: Some(Platform::Linux),
        action: Inclusion::Include,
    },
    Known {
        id: "mozilla",
        path: ".mozilla",
        category: ProfileCategory::ApplicationState,
        portable: Portability::PlatformSpecific,
        reason: "Firefox profiles",
        only: Some(Platform::Linux),
        action: Inclusion::Include,
    },
    Known {
        id: "flatpak",
        path: ".var",
        category: ProfileCategory::ApplicationState,
        portable: Portability::PlatformSpecific,
        reason: "Flatpak application data",
        only: Some(Platform::Linux),
        action: Inclusion::Include,
    },
    Known {
        id: "app_support",
        path: "Library/Application Support",
        category: ProfileCategory::ApplicationState,
        portable: Portability::PlatformSpecific,
        reason: "macOS application support data (large, mostly app-managed state; opt-in)",
        only: Some(Platform::MacOs),
        action: Inclusion::OptIn,
    },
    Known {
        id: "preferences",
        path: "Library/Preferences",
        category: ProfileCategory::ApplicationState,
        portable: Portability::PlatformSpecific,
        reason: "macOS preference plists",
        only: Some(Platform::MacOs),
        action: Inclusion::Include,
    },
    Known {
        id: "containers",
        path: "Library/Containers",
        category: ProfileCategory::ApplicationState,
        portable: Portability::PlatformSpecific,
        reason: "Sandboxed app containers (TCC-gated per app; opt-in)",
        only: Some(Platform::MacOs),
        action: Inclusion::OptIn,
    },
    Known {
        id: "group_containers",
        path: "Library/Group Containers",
        category: ProfileCategory::ApplicationState,
        portable: Portability::PlatformSpecific,
        reason: "App group containers (TCC-gated; opt-in)",
        only: Some(Platform::MacOs),
        action: Inclusion::OptIn,
    },
    Known {
        id: "mail",
        path: "Library/Mail",
        category: ProfileCategory::PersonalData,
        portable: Portability::PlatformSpecific,
        reason: "Apple Mail (requires Full Disk Access)",
        only: Some(Platform::MacOs),
        action: Inclusion::OptIn,
    },
    Known {
        id: "appdata_roaming",
        path: "AppData/Roaming",
        category: ProfileCategory::ApplicationState,
        portable: Portability::PlatformSpecific,
        reason: "Roaming application data",
        only: Some(Platform::Windows),
        action: Inclusion::Include,
    },
    Known {
        id: "appdata_local",
        path: "AppData/Local",
        category: ProfileCategory::ApplicationState,
        portable: Portability::MachineSpecific,
        reason: "Local application data (caches excluded)",
        only: Some(Platform::Windows),
        action: Inclusion::OptIn,
    },
];

/// Standard user directories that are opt-in rather than included by default.
/// `~/Downloads` is a landing zone for installers and transient files; the
/// user says `moss include ~/Downloads` to back it up.
const OPT_IN_USER_DIRS: &[&str] = &["downloads"];

fn user_dir_category(id: &str) -> (ProfileCategory, &'static str) {
    match id {
        "documents" => (ProfileCategory::PersonalData, "Standard documents folder"),
        "desktop" => (ProfileCategory::PersonalData, "Desktop"),
        "downloads" => (
            ProfileCategory::PersonalData,
            "Downloads (transient by default; opt-in)",
        ),
        "pictures" => (ProfileCategory::PersonalData, "Pictures"),
        "video" => (
            ProfileCategory::PersonalData,
            "Video folder (Movies on macOS, Videos elsewhere)",
        ),
        "music" => (ProfileCategory::PersonalData, "Music"),
        "public" => (ProfileCategory::PersonalData, "Public folder"),
        _ => (ProfileCategory::Unknown, "Standard user directory"),
    }
}

/// Discover sources on this machine.
pub fn discover(adapter: &dyn PlatformAdapter, config: &Config) -> Vec<ProfileSource> {
    let home = adapter.home();
    let platform = adapter.platform();
    let mut out: Vec<ProfileSource> = Vec::new();

    for known in adapter.known_dirs() {
        let (category, reason) = user_dir_category(known.id.as_str());
        let default_action = if OPT_IN_USER_DIRS.contains(&known.id.as_str()) {
            Inclusion::OptIn
        } else {
            Inclusion::Include
        };
        out.push(ProfileSource {
            id: known.id,
            path: known.path,
            category,
            platform,
            reason: reason.to_string(),
            default_action,
            sensitive: false,
            portable: Portability::PortableWithPathTranslation,
        });
    }

    for k in KNOWN {
        if k.only.is_some_and(|p| p != platform) {
            continue;
        }
        let path = home.join(k.path.split('/').collect::<PathBuf>());
        if !path.exists() {
            tracing::debug!(path = %path.display(), "known source absent; skipped");
            continue;
        }
        let mut action = k.action;
        if config.backup.include_containers && matches!(k.id, "containers" | "group_containers") {
            action = Inclusion::Include;
        }
        out.push(ProfileSource {
            id: SemanticId::new(k.id),
            path,
            category: k.category,
            platform,
            reason: k.reason.to_string(),
            default_action: action,
            sensitive: is_sensitive_source(&format!("~/{}", k.path)),
            portable: k.portable,
        });
    }

    // User includes (spec §25): `custom:<home-relative>` ids.
    for rule in &config.include {
        let path = expand_tilde(&rule.path, &home);
        if !path.exists() {
            tracing::warn!(path = %path.display(), "included path does not exist");
            continue;
        }
        if let Some(existing) = out.iter_mut().find(|s| s.path == path) {
            // Including an opt-in source by path turns it on; including a
            // source that is already selected is a no-op.
            if existing.default_action == Inclusion::OptIn {
                existing.default_action = Inclusion::Include;
                existing.reason = format!("{} — included by user", existing.reason);
            }
            continue;
        }
        let id = match path.strip_prefix(&home) {
            Ok(rel) => SemanticId::custom(rel),
            Err(_) => SemanticId::new(format!("custom:{}", path.display())),
        };
        let portable = if path.starts_with(&home) {
            Portability::PortableWithPathTranslation
        } else {
            Portability::MachineSpecific
        };
        out.push(ProfileSource {
            id,
            path: path.clone(),
            category: rule.category.unwrap_or(ProfileCategory::PersonalData),
            platform,
            reason: "Included by user".to_string(),
            default_action: Inclusion::Include,
            sensitive: is_sensitive_source(&home_relative(&path, &home)),
            portable,
        });
    }

    // Drop nested sources: a source inside another *selected* source would be
    // backed up twice, so keep the outer one. A source beneath an opt-in
    // parent (`~/Library/Application Support/k9s`) stands on its own.
    let selected_roots: Vec<PathBuf> = out
        .iter()
        .filter(|s| s.default_action == Inclusion::Include)
        .map(|s| s.path.clone())
        .collect();
    out.retain(|s| {
        !selected_roots
            .iter()
            .any(|outer| outer != &s.path && s.path.starts_with(outer))
    });

    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// The sources that will actually be backed up.
pub fn selected<'a>(sources: &'a [ProfileSource], config: &Config) -> Vec<&'a ProfileSource> {
    sources
        .iter()
        .filter(|s| s.default_action == Inclusion::Include)
        .filter(|s| config.backup.include_sensitive || !s.sensitive)
        .collect()
}

/// Sources that would be nested inside another selected source are skipped in
/// the walk; expose that for `inspect`.
pub fn is_under_home(path: &Path, home: &Path) -> bool {
    path.starts_with(home)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::macos::MacOsAdapter;

    #[test]
    fn discovers_only_existing_paths_with_semantic_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        for d in [
            ".ssh",
            "Documents",
            "Downloads",
            "Movies",
            "Library/Application Support",
            "Library/Containers",
            "Projects",
        ] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        std::fs::write(home.join(".gitconfig"), "[user]\n").unwrap();
        let adapter = MacOsAdapter::with_home(home.clone());
        let mut config = Config::default();
        config
            .include
            .push(crate::config::PathRule::new("~/Projects"));
        let sources = discover(&adapter, &config);
        let ids: Vec<&str> = sources.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"ssh"));
        assert!(ids.contains(&"video"));
        assert!(ids.contains(&"git"));
        assert!(ids.contains(&"custom:Projects"));
        assert!(!ids.contains(&"aws"), "absent paths are not invented");
        let ssh = sources.iter().find(|s| s.id.as_str() == "ssh").unwrap();
        assert!(ssh.sensitive);
        assert_eq!(ssh.category, ProfileCategory::Credentials);
        let containers = sources
            .iter()
            .find(|s| s.id.as_str() == "containers")
            .unwrap();
        assert_eq!(containers.default_action, Inclusion::OptIn);
        for id in ["downloads", "app_support"] {
            let s = sources.iter().find(|s| s.id.as_str() == id).unwrap();
            assert_eq!(s.default_action, Inclusion::OptIn, "{id} is opt-in");
        }
        let sel = selected(&sources, &config);
        for id in ["containers", "downloads", "app_support"] {
            assert!(sel.iter().all(|s| s.id.as_str() != id), "{id} not selected");
        }
    }

    #[test]
    fn including_an_opt_in_source_turns_it_on() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        for d in ["Downloads", "Library/Application Support"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        let adapter = MacOsAdapter::with_home(home.clone());
        let mut config = Config::default();
        config
            .include
            .push(crate::config::PathRule::new("~/Downloads"));
        let sources = discover(&adapter, &config);
        let downloads = sources
            .iter()
            .find(|s| s.id.as_str() == "downloads")
            .unwrap();
        assert_eq!(downloads.default_action, Inclusion::Include);
        assert!(
            !sources.iter().any(|s| s.id.as_str() == "custom:Downloads"),
            "keeps the semantic id rather than adding a custom source"
        );
        let app = sources
            .iter()
            .find(|s| s.id.as_str() == "app_support")
            .unwrap();
        assert_eq!(app.default_action, Inclusion::OptIn);
        let sel = selected(&sources, &config);
        assert!(sel.iter().any(|s| s.id.as_str() == "downloads"));
        assert!(sel.iter().all(|s| s.id.as_str() != "app_support"));
    }

    #[test]
    fn k9s_is_a_default_source_beneath_opt_in_app_support() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        std::fs::create_dir_all(home.join("Library/Application Support/k9s")).unwrap();
        std::fs::create_dir_all(home.join(".config/k9s")).unwrap();
        let adapter = MacOsAdapter::with_home(home.clone());
        let config = Config::default();
        let sources = discover(&adapter, &config);
        let sel: Vec<&str> = selected(&sources, &config)
            .iter()
            .map(|s| s.id.as_str())
            .collect();
        assert_eq!(
            sel,
            vec!["config", "k9s"],
            "App Support k9s stands alone; .config/k9s folds into config"
        );
        let k9s = sources.iter().find(|s| s.id.as_str() == "k9s").unwrap();
        assert_eq!(k9s.path, home.join("Library/Application Support/k9s"));
        assert_eq!(k9s.category, ProfileCategory::Development);
    }

    #[test]
    fn include_beneath_an_opt_in_parent_is_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        std::fs::create_dir_all(home.join("Library/Application Support/Sublime Text")).unwrap();
        let adapter = MacOsAdapter::with_home(home.clone());
        let mut config = Config::default();
        config.include.push(crate::config::PathRule::new(
            "~/Library/Application Support/Sublime Text",
        ));
        let sources = discover(&adapter, &config);
        let ids: Vec<&str> = sources.iter().map(|s| s.id.as_str()).collect();
        assert!(
            ids.contains(&"custom:Library/Application Support/Sublime Text"),
            "{ids:?}"
        );
        assert!(
            ids.contains(&"app_support"),
            "parent stays listed as opt-in"
        );
        let sel: Vec<&str> = selected(&sources, &config)
            .iter()
            .map(|s| s.id.as_str())
            .collect();
        assert_eq!(sel, vec!["custom:Library/Application Support/Sublime Text"]);
    }

    #[test]
    fn nested_includes_are_deduplicated() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        std::fs::create_dir_all(home.join("Documents/work")).unwrap();
        let adapter = MacOsAdapter::with_home(home.clone());
        let mut config = Config::default();
        config
            .include
            .push(crate::config::PathRule::new("~/Documents/work"));
        let sources = discover(&adapter, &config);
        let ids: Vec<&str> = sources.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["documents"]);
    }
}
