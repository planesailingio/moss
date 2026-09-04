//! Case, Unicode-normalization and Windows-name collision detection (spec §12).
//!
//! Detected at backup time, per directory, where both members are visible.

use std::collections::HashMap;
use std::path::Path;

use unicode_normalization::UnicodeNormalization;

use crate::backup::manifest::Collision;

pub const WINDOWS_MAX_PATH: usize = 260;

/// Windows reserved device names, matched case-insensitively with any extension.
const RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];
/// Superscript variants Microsoft documents, plus COM0/LPT0 which are
/// unconfirmed but sanitised defensively.
const RESERVED_EXTRA: [&str; 8] = [
    "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³", "COM0", "LPT0",
];

/// Why a name is illegal on Windows, if it is.
pub fn windows_problem(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    if let Some(c) = name.chars().find(|c| {
        matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || (*c as u32) < 0x20
    }) {
        return Some(format!("contains {:?}", c));
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Some("trailing dot or space is stripped by Win32".into());
    }
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str())
        || RESERVED_EXTRA.iter().any(|r| r.eq_ignore_ascii_case(&stem))
    {
        return Some(format!("reserved device name {stem}"));
    }
    None
}

/// Inspect the names of one directory. `rel_dir` is the home-relative
/// directory used in reports (forward slashes, e.g. `~/git/app/src`).
pub fn check_directory(rel_dir: &str, names: &[String]) -> Vec<Collision> {
    let mut out = Vec::new();
    let join = |n: &str| {
        if rel_dir.is_empty() {
            n.to_string()
        } else {
            format!("{rel_dir}/{n}")
        }
    };

    // Case-insensitive collisions.
    let mut by_fold: HashMap<String, Vec<&String>> = HashMap::new();
    for n in names {
        by_fold.entry(n.to_lowercase()).or_default().push(n);
    }
    for group in by_fold.values() {
        if group.len() > 1 {
            let mut paths: Vec<String> = group.iter().map(|n| join(n)).collect();
            paths.sort();
            out.push(Collision::Case { paths });
        }
    }

    // Normalization collisions: distinct byte strings with the same NFC form.
    let mut by_nfc: HashMap<String, Vec<&String>> = HashMap::new();
    for n in names {
        by_nfc
            .entry(n.nfc().collect::<String>())
            .or_default()
            .push(n);
    }
    for group in by_nfc.values() {
        if group.len() > 1 {
            let mut paths: Vec<String> = group.iter().map(|n| join(n)).collect();
            paths.sort();
            // Avoid double-reporting a pair already reported as a case collision
            // (only possible if the names differ solely by case *and* normalization).
            if !out
                .iter()
                .any(|c| matches!(c, Collision::Case { paths: p } if *p == paths))
            {
                out.push(Collision::Normalization { paths });
            }
        }
    }

    for n in names {
        if let Some(problem) = windows_problem(n) {
            out.push(Collision::WindowsIllegal {
                path: join(n),
                problem,
            });
        }
    }
    out
}

/// Path length check against MAX_PATH, counting the destination form
/// (`C:\Users\<user>\` prefix ≈ 16 chars plus the home-relative path).
pub fn check_length(rel_path: &str) -> Option<Collision> {
    let length = rel_path.chars().count() + 16;
    if length > WINDOWS_MAX_PATH {
        Some(Collision::PathTooLong {
            path: rel_path.to_string(),
            length,
        })
    } else {
        None
    }
}

/// Probe whether a directory's filesystem folds case or normalization, by
/// creating two names in it. Used by restore on the destination.
pub fn probe_insensitive(dir: &Path) -> std::io::Result<(bool, bool)> {
    let probe = dir.join(format!(".moss-probe-{}", std::process::id()));
    std::fs::create_dir_all(&probe)?;
    let result = (|| {
        std::fs::write(probe.join("Case"), b"")?;
        let case_insensitive = probe.join("case").exists();
        std::fs::write(probe.join("caf\u{e9}"), b"")?; // NFC
        let norm_insensitive = probe.join("cafe\u{301}").exists(); // NFD
        Ok::<_, std::io::Error>((case_insensitive, norm_insensitive))
    })();
    let _ = std::fs::remove_dir_all(&probe);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_pair() {
        let c = check_directory(
            "~/src",
            &["Makefile".into(), "makefile".into(), "README".into()],
        );
        assert_eq!(
            c,
            vec![Collision::Case {
                paths: vec!["~/src/Makefile".into(), "~/src/makefile".into()]
            }]
        );
    }

    #[test]
    fn normalization_pair() {
        let nfc = "caf\u{e9}.txt".to_string();
        let nfd = "cafe\u{301}.txt".to_string();
        let c = check_directory("~", &[nfc.clone(), nfd.clone()]);
        assert_eq!(c.len(), 1);
        assert!(matches!(&c[0], Collision::Normalization { paths } if paths.len() == 2));
    }

    #[test]
    fn windows_illegal_names() {
        assert!(windows_problem("aux.txt").unwrap().contains("AUX"));
        assert!(windows_problem("notes:draft.md").unwrap().contains(':'));
        assert!(windows_problem("trailing.").is_some());
        assert!(windows_problem("trailing ").is_some());
        assert!(windows_problem("com0").is_some(), "sanitised defensively");
        assert!(windows_problem("normal.txt").is_none());
        assert!(
            windows_problem("\u{7f}x").is_none(),
            "0x7F is not documented as illegal"
        );
        let c = check_directory("~", &["aux.txt".into()]);
        assert!(matches!(&c[0], Collision::WindowsIllegal { .. }));
    }

    #[test]
    fn long_paths() {
        let long = "a/".repeat(130);
        assert!(check_length(&long).is_some());
        assert!(check_length("~/short").is_none());
    }

    #[test]
    fn probe_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let (case, norm) = probe_insensitive(tmp.path()).unwrap();
        if cfg!(target_os = "macos") {
            assert!(case && norm, "APFS is case- and normalization-insensitive");
        }
        assert!(
            !tmp.path()
                .join(format!(".moss-probe-{}", std::process::id()))
                .exists()
        );
    }
}
