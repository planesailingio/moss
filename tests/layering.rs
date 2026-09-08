//! Module layering guard (ARCHITECTURE.md, "Module layering").
//!
//! Each top-level module may reference only the crate modules listed for it.
//! `cli` may use anything. Add an edge here deliberately, never by accident.

use std::collections::BTreeSet;
use std::path::Path;

/// (module, modules it may reference via `crate::<name>`)
const ALLOWED: &[(&str, &[&str])] = &[
    ("model", &[]),
    ("error", &[]),
    ("output", &["error"]),
    ("security", &["error"]),
    ("config", &["error", "model"]),
    ("platform", &["model"]),
    ("profile", &["config", "error", "model", "platform"]),
    // `output::human` is pure formatting; scan must never see `Console`.
    (
        "scan",
        &["config", "error", "model", "output", "platform", "profile"],
    ),
    (
        "backup",
        &[
            "config", "error", "model", "platform", "profile", "scan", "security",
        ],
    ),
    (
        "restore",
        &[
            "backup", "config", "error", "model", "output", "platform", "scan",
        ],
    ),
    ("lock", &["config", "error"]),
    ("credentials", &["config", "error", "security"]),
    ("yubikey", &["error", "security"]),
    ("endpoints", &["output"]),
];

fn sources(module: &str) -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    let file = root.join(format!("{module}.rs"));
    if file.is_file() {
        out.push((
            file.display().to_string(),
            std::fs::read_to_string(&file).unwrap(),
        ));
    }
    let dir = root.join(module);
    if dir.is_dir() {
        let mut stack = vec![dir];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push((
                        p.display().to_string(),
                        std::fs::read_to_string(&p).unwrap(),
                    ));
                }
            }
        }
    }
    assert!(!out.is_empty(), "no sources for module {module}");
    out
}

fn referenced(text: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for (i, _) in text.match_indices("crate::") {
        let rest = &text[i + "crate::".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        // Crate-root items (`crate::VERSION`) are not modules.
        if !name.is_empty() && name.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
            set.insert(name);
        }
    }
    set
}

#[test]
fn modules_only_depend_downward() {
    let mut violations = Vec::new();
    for (module, allowed) in ALLOWED {
        for (file, text) in sources(module) {
            for dep in referenced(&text) {
                if dep == *module || allowed.contains(&dep.as_str()) {
                    continue;
                }
                violations.push(format!("{file}: {module} -> {dep}"));
            }
            if *module == "scan" {
                for (i, _) in text.match_indices("crate::output::") {
                    let rest = &text[i..];
                    if !rest.starts_with("crate::output::human") {
                        violations.push(format!("{file}: scan may use output::human only"));
                    }
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "layering violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn every_top_level_module_is_listed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let listed: BTreeSet<&str> = ALLOWED.iter().map(|(m, _)| *m).collect();
    for e in std::fs::read_dir(&root).unwrap().flatten() {
        let p = e.path();
        let name = p.file_stem().unwrap().to_string_lossy().into_owned();
        if matches!(name.as_str(), "lib" | "main" | "cli") {
            continue;
        }
        assert!(
            listed.contains(name.as_str()),
            "src/{name} is not in the layering table"
        );
    }
}
