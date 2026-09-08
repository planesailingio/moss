//! Profile discovery (spec §8): the built-in table (`locations::BUILTINS`)
//! resolved on this machine, plus the user's includes, as semantic sources.
//!
//! Every path is validated to exist before it becomes a source. Nothing is
//! invented.

use std::path::PathBuf;

use crate::config::Config;
use crate::model::{
    Inclusion, Portability, ProfileCategory, ProfileSource, SemanticId, expand_tilde,
};
use crate::platform::PlatformAdapter;
use crate::profile::locations::{self, BUILTINS};

/// Discover sources on this machine.
pub fn discover(adapter: &dyn PlatformAdapter, config: &Config) -> Vec<ProfileSource> {
    let home = adapter.home().to_path_buf();
    let platform = adapter.platform();
    let mut out: Vec<ProfileSource> = Vec::new();

    for b in BUILTINS.iter().filter(|b| b.discovered_on(platform)) {
        let Some(path) = b.location(platform).and_then(|l| adapter.resolve(l)) else {
            continue;
        };
        // A user directory disabled in `user-dirs.dirs` resolves to home itself.
        if path == home || !path.exists() {
            tracing::debug!(id = b.id, path = %path.display(), "known source absent; skipped");
            continue;
        }
        // Two rows of one id can coincide (both k9s rows when XDG_CONFIG_HOME
        // points at ~/.config); keep the first.
        if out.iter().any(|s| s.id.as_str() == b.id && s.path == path) {
            continue;
        }
        let mut action = b.action;
        if config.backup.include_containers && matches!(b.id, "containers" | "group_containers") {
            action = Inclusion::Include;
        }
        out.push(ProfileSource {
            id: SemanticId::new(b.id),
            path,
            category: b.category,
            platform,
            reason: b.reason.to_string(),
            default_action: action,
            sensitive: b.sensitive,
            portable: b.portable,
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
            sensitive: locations::is_sensitive_path(adapter, &path),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::UserDir;
    use crate::platform::linux::LinuxAdapter;
    use crate::platform::macos::MacOsAdapter;
    use crate::platform::windows::WindowsAdapter;

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

    /// Everything the table can discover, on a home that has all of it. The
    /// expected lists were captured from the hand-written `KNOWN` table this
    /// module replaced, so `config.yaml` written by an older moss keeps
    /// matching what discovery produces (ids and paths are a persisted
    /// contract). Additions are allowed only deliberately; check the diff.
    #[test]
    fn discovery_golden() {
        const DIRS: &[&str] = &[
            "Desktop",
            "Documents",
            "Downloads",
            "Movies",
            "Music",
            "Pictures",
            "Public",
            "Videos",
            ".ssh",
            ".aws",
            ".gnupg",
            ".kube",
            ".docker",
            ".azure",
            ".talos",
            ".terraform.d",
            ".config",
            ".config/k9s",
            ".claude",
            ".codex",
            ".local/share",
            ".local/state",
            ".mozilla",
            ".var",
            "Library/Application Support",
            "Library/Application Support/k9s",
            "Library/Preferences",
            "Library/Containers",
            "Library/Group Containers",
            "Library/Mail",
            "AppData/Roaming",
            "AppData/Local",
        ];
        const FILES: &[&str] = &[
            ".gitconfig",
            ".zshrc",
            ".zprofile",
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".bash_history",
            ".zsh_history",
            ".npmrc",
        ];
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        for d in DIRS {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        for f in FILES {
            std::fs::write(home.join(f), "x").unwrap();
        }
        let cfg = Config::default();
        let ids = |sources: Vec<ProfileSource>| -> Vec<(String, String)> {
            sources
                .iter()
                .map(|s| {
                    (
                        s.id.to_string(),
                        crate::model::home_relative(&s.path, &home),
                    )
                })
                .collect()
        };
        let expect = |rows: &[(&str, &str)]| -> Vec<(String, String)> {
            rows.iter()
                .map(|(i, p)| (i.to_string(), p.to_string()))
                .collect()
        };
        let mac = ids(discover(&MacOsAdapter::with_home(home.clone()), &cfg));
        assert_eq!(mac, expect(MACOS));
        let lin = ids(discover(
            &LinuxAdapter::with_home(home.clone(), tmp.path().join("no-etc")),
            &cfg,
        ));
        assert_eq!(lin, expect(LINUX));
        let known: Vec<(UserDir, PathBuf)> = UserDir::ALL
            .into_iter()
            .map(|d| (d, home.join(d.english_name())))
            .collect();
        let win = ids(discover(&WindowsAdapter::with(home.clone(), known), &cfg));
        assert_eq!(win, expect(WINDOWS));

        const MACOS: &[(&str, &str)] = &[
            ("app_support", "~/Library/Application Support"),
            ("aws", "~/.aws"),
            ("azure", "~/.azure"),
            ("claude", "~/.claude"),
            ("codex", "~/.codex"),
            ("config", "~/.config"),
            ("containers", "~/Library/Containers"),
            ("desktop", "~/Desktop"),
            ("docker", "~/.docker"),
            ("documents", "~/Documents"),
            ("downloads", "~/Downloads"),
            ("git", "~/.gitconfig"),
            ("gnupg", "~/.gnupg"),
            ("group_containers", "~/Library/Group Containers"),
            ("k9s", "~/Library/Application Support/k9s"),
            ("kubernetes", "~/.kube"),
            ("mail", "~/Library/Mail"),
            ("music", "~/Music"),
            ("npm_config", "~/.npmrc"),
            ("pictures", "~/Pictures"),
            ("preferences", "~/Library/Preferences"),
            ("public", "~/Public"),
            ("shell_bash_history", "~/.bash_history"),
            ("shell_bash_profile", "~/.bash_profile"),
            ("shell_bashrc", "~/.bashrc"),
            ("shell_profile", "~/.profile"),
            ("shell_zprofile", "~/.zprofile"),
            ("shell_zsh_history", "~/.zsh_history"),
            ("shell_zshrc", "~/.zshrc"),
            ("ssh", "~/.ssh"),
            ("talos", "~/.talos"),
            ("terraform", "~/.terraform.d"),
            ("video", "~/Movies"),
        ];
        const LINUX: &[(&str, &str)] = &[
            ("aws", "~/.aws"),
            ("azure", "~/.azure"),
            ("claude", "~/.claude"),
            ("codex", "~/.codex"),
            ("config", "~/.config"),
            ("desktop", "~/Desktop"),
            ("docker", "~/.docker"),
            ("documents", "~/Documents"),
            ("downloads", "~/Downloads"),
            ("flatpak", "~/.var"),
            ("git", "~/.gitconfig"),
            ("gnupg", "~/.gnupg"),
            ("kubernetes", "~/.kube"),
            ("local_share", "~/.local/share"),
            ("local_state", "~/.local/state"),
            ("mozilla", "~/.mozilla"),
            ("music", "~/Music"),
            ("npm_config", "~/.npmrc"),
            ("pictures", "~/Pictures"),
            ("public", "~/Public"),
            ("shell_bash_history", "~/.bash_history"),
            ("shell_bash_profile", "~/.bash_profile"),
            ("shell_bashrc", "~/.bashrc"),
            ("shell_profile", "~/.profile"),
            ("shell_zprofile", "~/.zprofile"),
            ("shell_zsh_history", "~/.zsh_history"),
            ("shell_zshrc", "~/.zshrc"),
            ("ssh", "~/.ssh"),
            ("talos", "~/.talos"),
            ("terraform", "~/.terraform.d"),
            ("video", "~/Videos"),
        ];
        const WINDOWS: &[(&str, &str)] = &[
            ("appdata_local", "~/AppData/Local"),
            ("appdata_roaming", "~/AppData/Roaming"),
            ("aws", "~/.aws"),
            ("azure", "~/.azure"),
            ("claude", "~/.claude"),
            ("codex", "~/.codex"),
            ("config", "~/.config"),
            ("desktop", "~/Desktop"),
            ("docker", "~/.docker"),
            ("documents", "~/Documents"),
            ("downloads", "~/Downloads"),
            ("git", "~/.gitconfig"),
            ("gnupg", "~/.gnupg"),
            ("kubernetes", "~/.kube"),
            ("music", "~/Music"),
            ("npm_config", "~/.npmrc"),
            ("pictures", "~/Pictures"),
            ("public", "~/Public"),
            ("shell_bash_history", "~/.bash_history"),
            ("shell_bash_profile", "~/.bash_profile"),
            ("shell_bashrc", "~/.bashrc"),
            ("shell_profile", "~/.profile"),
            ("shell_zprofile", "~/.zprofile"),
            ("shell_zsh_history", "~/.zsh_history"),
            ("shell_zshrc", "~/.zshrc"),
            ("ssh", "~/.ssh"),
            ("talos", "~/.talos"),
            ("terraform", "~/.terraform.d"),
            ("video", "~/Videos"),
        ];
    }
}
