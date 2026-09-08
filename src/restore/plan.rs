//! Where one manifest source lands on this machine (spec §15, §16): a pure
//! decision over the destination the platform table gave us, the destination
//! home, and `--to`. No I/O, so every cell is unit-tested.

use std::path::{Path, PathBuf};

use crate::backup::manifest::ManifestSource;
use crate::model::{ProfileCategory, home_relative};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourcePlan {
    /// Nothing is placed; the report carries the reason.
    Skip { destination: String, reason: String },
    /// Place `dest_rel` beneath the containment root `root`.
    Place {
        root: PathBuf,
        dest_rel: PathBuf,
        /// What the report and the progress line show for this destination.
        display: String,
    },
}

/// Decide the containment root and relative path for `source`.
///
/// - No destination on this platform: skip.
/// - Inside home: root is home (or `--to`), path is home-relative.
/// - Outside home (a redirected known folder, `%APPDATA%`): credentials never
///   leave the profile (spec §16) and `--to` keeps everything under one root,
///   so both skip; anything else is rooted at the destination's parent.
pub fn plan_source(
    source: &ManifestSource,
    dest_abs: Option<&Path>,
    dest_home: &Path,
    root_override: Option<&Path>,
) -> SourcePlan {
    let Some(dest_abs) = dest_abs else {
        return SourcePlan::Skip {
            destination: "-".into(),
            reason: format!("this platform has no location for {}", source.id),
        };
    };
    let (root, dest_rel) = match dest_abs.strip_prefix(dest_home) {
        Ok(rel) => (
            root_override.unwrap_or(dest_home).to_path_buf(),
            rel.to_path_buf(),
        ),
        Err(_) => {
            if source.category == ProfileCategory::Credentials || root_override.is_some() {
                return SourcePlan::Skip {
                    destination: dest_abs.display().to_string(),
                    reason: "destination is outside the home directory".into(),
                };
            }
            let parent = dest_abs
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| dest_abs.to_path_buf());
            let name = dest_abs.file_name().map(PathBuf::from).unwrap_or_default();
            (parent, name)
        }
    };
    let display = if root_override.is_some() {
        root.join(&dest_rel).display().to_string()
    } else {
        home_relative(&root.join(&dest_rel), dest_home)
    };
    SourcePlan::Place {
        root,
        dest_rel,
        display,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restore::test_support::source;

    fn home() -> PathBuf {
        PathBuf::from("/home/x")
    }

    #[test]
    fn inside_home_is_home_relative() {
        let s = source("ssh", ProfileCategory::Credentials, "~/.ssh");
        let plan = plan_source(&s, Some(&home().join(".ssh")), &home(), None);
        assert_eq!(
            plan,
            SourcePlan::Place {
                root: home(),
                dest_rel: PathBuf::from(".ssh"),
                display: "~/.ssh".into(),
            }
        );
    }

    #[test]
    fn to_override_reroots_and_shows_absolute() {
        let s = source("documents", ProfileCategory::PersonalData, "~/Documents");
        let to = PathBuf::from("/tmp/out");
        let plan = plan_source(&s, Some(&home().join("Documents")), &home(), Some(&to));
        assert_eq!(
            plan,
            SourcePlan::Place {
                root: to.clone(),
                dest_rel: PathBuf::from("Documents"),
                display: to.join("Documents").display().to_string(),
            }
        );
    }

    #[test]
    fn no_destination_skips() {
        let s = source("mystery", ProfileCategory::Development, "~/x");
        match plan_source(&s, None, &home(), None) {
            SourcePlan::Skip {
                destination,
                reason,
            } => {
                assert_eq!(destination, "-");
                assert!(reason.contains("mystery"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn outside_home_rules() {
        let outside = PathBuf::from("/data/Documents");
        let docs = source("documents", ProfileCategory::PersonalData, "~/Documents");
        assert_eq!(
            plan_source(&docs, Some(&outside), &home(), None),
            SourcePlan::Place {
                root: PathBuf::from("/data"),
                dest_rel: PathBuf::from("Documents"),
                display: "/data/Documents".into(),
            },
            "personal data follows a redirected folder"
        );
        let creds = source("gnupg", ProfileCategory::Credentials, "~/.gnupg");
        assert!(matches!(
            plan_source(&creds, Some(&PathBuf::from("/data/gnupg")), &home(), None),
            SourcePlan::Skip { .. }
        ));
        assert!(matches!(
            plan_source(&docs, Some(&outside), &home(), Some(Path::new("/tmp/out"))),
            SourcePlan::Skip { .. }
        ));
    }
}
