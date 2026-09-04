//! Include/exclude rule evaluation (spec §10, §25).
//!
//! One gitignore-style matcher built from the default patterns, known cache
//! paths, tool-reported cache paths, moss's and Kopia's own state, and the
//! user's `exclude` entries. Evaluated during the walk so excluded directories
//! are never descended.

use std::path::{Path, PathBuf};

use ignore::gitignore::{Gitignore, GitignoreBuilder};

use crate::config::{Config, PathRule};
use crate::error::{MossError, Result};
use crate::profile::model::expand_tilde;
use crate::profile::patterns::{self, ExclusionKind};

pub struct RuleSet {
    home: PathBuf,
    matcher: Gitignore,
    /// Pattern text → reporting kind (the `ignore` crate exposes the matched
    /// glob's original text, not its index).
    kinds: std::collections::HashMap<String, ExclusionKind>,
    /// Absolute paths the user explicitly included; they win over defaults.
    includes: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Include,
    Exclude(ExclusionKind),
}

impl RuleSet {
    pub fn build(
        config: &Config,
        home: &Path,
        extra_excludes: &[(PathBuf, ExclusionKind)],
    ) -> Result<RuleSet> {
        let mut builder = GitignoreBuilder::new(home);
        let mut kinds = std::collections::HashMap::new();
        let mut add =
            |builder: &mut GitignoreBuilder, pattern: &str, kind: ExclusionKind| -> Result<()> {
                builder.add_line(None, pattern).map_err(|e| {
                    MossError::Config(format!("bad exclude pattern {pattern:?}: {e}"))
                })?;
                kinds.insert(pattern.to_string(), kind);
                Ok(())
            };
        for (p, kind) in patterns::defaults() {
            add(&mut builder, p, kind)?;
        }
        for (path, kind) in extra_excludes {
            if let Some(p) = anchored_pattern(path, home) {
                add(&mut builder, &p, *kind)?;
            }
        }
        for rule in &config.exclude {
            let pattern = user_rule_pattern(rule, home);
            add(&mut builder, &pattern, ExclusionKind::UserRule)?;
        }
        let matcher = builder
            .build()
            .map_err(|e| MossError::Config(format!("cannot build exclusion rules: {e}")))?;
        let includes = config
            .include
            .iter()
            .map(|r| expand_tilde(&r.path, home))
            .collect();
        Ok(RuleSet {
            home: home.to_path_buf(),
            matcher,
            kinds,
            includes,
        })
    }

    /// Evaluate one path. `is_dir` matters for trailing-slash patterns.
    pub fn verdict(&self, path: &Path, is_dir: bool) -> Verdict {
        // Explicit user includes override every default rule for the path
        // itself and everything beneath it, but user excludes still apply
        // (user rules beat discovery; excludes narrow includes).
        let explicitly_included = self
            .includes
            .iter()
            .any(|inc| path == inc || path.starts_with(inc));
        match self.matcher.matched_path_or_any_parents(path, is_dir) {
            ignore::Match::Ignore(glob) => {
                let kind = self
                    .kinds
                    .get(glob.original())
                    .copied()
                    .unwrap_or(ExclusionKind::UserRule);
                if explicitly_included
                    && kind != ExclusionKind::UserRule
                    && self.includes.iter().any(|inc| path == inc)
                {
                    // The include target itself was excluded by a default; the
                    // user's intent wins for the root, and children are judged
                    // on their own patterns.
                    return Verdict::Include;
                }
                Verdict::Exclude(kind)
            }
            _ => Verdict::Include,
        }
    }

    pub fn is_excluded(&self, path: &Path, is_dir: bool) -> bool {
        matches!(self.verdict(path, is_dir), Verdict::Exclude(_))
    }

    pub fn home(&self) -> &Path {
        &self.home
    }
}

/// A user rule is either a path (`~/Movies`, `/abs`) or a pattern (`node_modules/`).
fn user_rule_pattern(rule: &PathRule, home: &Path) -> String {
    let raw = rule.path.trim();
    if raw.starts_with("~/") || raw.starts_with('/') || raw.starts_with("~\\") {
        let abs = expand_tilde(raw, home);
        anchored_pattern(&abs, home).unwrap_or_else(|| raw.to_string())
    } else {
        raw.to_string()
    }
}

/// Turn an absolute path under home into an anchored gitignore pattern.
fn anchored_pattern(abs: &Path, home: &Path) -> Option<String> {
    let rel = abs.strip_prefix(home).ok()?;
    let joined = rel
        .components()
        .map(|c| escape_glob(&c.as_os_str().to_string_lossy()))
        .collect::<Vec<_>>()
        .join("/");
    if joined.is_empty() {
        return None;
    }
    Some(format!("/{joined}"))
}

fn escape_glob(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\' | '#' | '!') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(config: Config) -> RuleSet {
        RuleSet::build(&config, Path::new("/home/x"), &[]).unwrap()
    }

    #[test]
    fn node_modules_at_any_depth() {
        let r = rules(Config::default());
        assert!(r.is_excluded(Path::new("/home/x/git/a/b/node_modules"), true));
        assert!(r.is_excluded(
            Path::new("/home/x/git/a/b/node_modules/pkg/index.js"),
            false
        ));
        assert!(!r.is_excluded(Path::new("/home/x/git/a/src/index.js"), false));
    }

    #[test]
    fn known_cache_dirs_are_anchored() {
        let r = rules(Config::default());
        assert!(r.is_excluded(Path::new("/home/x/.npm/_cacache"), true));
        assert!(!r.is_excluded(Path::new("/home/x/.npm/npmrc"), false));
        assert!(
            !r.is_excluded(Path::new("/home/x/projects/.npm/_cacache"), true),
            "anchored: only at home root"
        );
        assert!(r.is_excluded(Path::new("/home/x/.config/Code/Cache/x"), false));
        assert!(!r.is_excluded(Path::new("/home/x/.config/Code/settings.json"), false));
        assert!(r.is_excluded(Path::new("/home/x/.local/share/Trash/f"), false));
    }

    #[test]
    fn user_rules_override_and_narrow() {
        let mut c = Config::default();
        c.include.push(PathRule::new("~/Projects"));
        c.exclude.push(PathRule::new("~/Movies"));
        c.exclude.push(PathRule::new("*.iso"));
        let r = rules(c);
        assert!(r.is_excluded(Path::new("/home/x/Movies"), true));
        assert!(r.is_excluded(Path::new("/home/x/Projects/big.iso"), false));
        assert!(!r.is_excluded(Path::new("/home/x/Projects/src/main.rs"), false));
        // Defaults still apply beneath an include.
        assert!(r.is_excluded(Path::new("/home/x/Projects/web/node_modules"), true));
    }

    #[test]
    fn include_of_default_excluded_root_wins() {
        let mut c = Config::default();
        c.include.push(PathRule::new("~/.cache"));
        let r = rules(c);
        assert_eq!(
            r.verdict(Path::new("/home/x/.cache"), true),
            Verdict::Include
        );
    }

    #[test]
    fn extra_excludes_such_as_own_state() {
        let r = RuleSet::build(
            &Config::default(),
            Path::new("/home/x"),
            &[(
                PathBuf::from("/home/x/.local/state/moss"),
                ExclusionKind::OwnState,
            )],
        )
        .unwrap();
        assert_eq!(
            r.verdict(Path::new("/home/x/.local/state/moss/index.json"), false),
            Verdict::Exclude(ExclusionKind::OwnState)
        );
    }

    #[test]
    fn glob_escaping() {
        assert_eq!(escape_glob("a[1]*"), "a\\[1\\]\\*");
    }
}
