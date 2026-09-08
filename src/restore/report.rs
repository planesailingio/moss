//! The restore report (spec §15, §26, §29): human and JSON forms of what was
//! placed, skipped, blocked, and which embedded paths need attention, plus the
//! exit code that follows from it (spec §23).

use serde::Serialize;

use crate::backup::manifest::ManifestSource;
use crate::error::ExitCode;
use crate::model::ProfileCategory;
use crate::output::{Console, human};
use crate::platform::Platform;
use crate::restore::place::Outcome;
use crate::restore::translate::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    /// Every entry placed.
    Restored,
    /// Placed, but some entries were skipped.
    Partial,
    /// Nothing placed, for a reported reason (no destination, category
    /// mismatch, not in the snapshot).
    Skipped,
    /// Blocked by a recorded collision or a fatal error.
    Failed,
    /// Dry run.
    Planned,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ConflictCounts {
    pub skipped: u64,
    pub overwritten: u64,
    pub backed_up: u64,
}

impl ConflictCounts {
    pub fn add(&mut self, other: &ConflictCounts) {
        self.skipped += other.skipped;
        self.overwritten += other.overwritten;
        self.backed_up += other.backed_up;
    }

    pub fn total(&self) -> u64 {
        self.skipped + self.overwritten + self.backed_up
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedEntry {
    pub source: String,
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CollisionFailure {
    pub source: String,
    pub kind: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rename {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceReport {
    pub id: String,
    pub category: ProfileCategory,
    pub destination: String,
    pub status: SourceStatus,
    pub placed: u64,
    pub skipped: u64,
    pub conflicts: ConflictCounts,
    /// Bytes according to the manifest (dry-run disk estimate).
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SourceReport {
    fn base(source: &ManifestSource, destination: impl Into<String>) -> SourceReport {
        SourceReport {
            id: source.id.to_string(),
            category: source.category,
            destination: destination.into(),
            status: SourceStatus::Skipped,
            placed: 0,
            skipped: 0,
            conflicts: ConflictCounts::default(),
            size: source.size,
            reason: None,
        }
    }

    /// Nothing placed, for a reported reason.
    pub fn skipped(
        source: &ManifestSource,
        destination: impl Into<String>,
        reason: impl Into<String>,
    ) -> SourceReport {
        SourceReport {
            reason: Some(reason.into()),
            ..SourceReport::base(source, destination)
        }
    }

    /// Blocked or errored before anything was placed.
    pub fn failed(
        source: &ManifestSource,
        destination: impl Into<String>,
        reason: impl Into<String>,
    ) -> SourceReport {
        SourceReport {
            status: SourceStatus::Failed,
            reason: Some(reason.into()),
            ..SourceReport::base(source, destination)
        }
    }

    /// A dry-run entry: what would be placed.
    pub fn planned(
        source: &ManifestSource,
        destination: impl Into<String>,
        note: Option<String>,
    ) -> SourceReport {
        SourceReport {
            status: SourceStatus::Planned,
            placed: source.files,
            reason: note,
            ..SourceReport::base(source, destination)
        }
    }

    /// The result of placing a staged source.
    pub fn from_outcome(
        source: &ManifestSource,
        destination: impl Into<String>,
        outcome: &Outcome,
    ) -> SourceReport {
        SourceReport {
            status: if outcome.skipped.is_empty() {
                SourceStatus::Restored
            } else {
                SourceStatus::Partial
            },
            placed: outcome.placed,
            skipped: outcome.skipped.len() as u64,
            conflicts: outcome.conflicts.clone(),
            ..SourceReport::base(source, destination)
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Totals {
    pub placed: u64,
    pub skipped: u64,
    pub conflicts: ConflictCounts,
    /// Staging space needed: the manifest sizes of the selected sources.
    pub disk_needed: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestoreReport {
    pub run_id: String,
    pub source_host: String,
    pub source_os: Platform,
    pub destination_os: Platform,
    pub destination_root: String,
    pub dry_run: bool,
    pub resumed: bool,
    pub sources: Vec<SourceReport>,
    pub totals: Totals,
    pub skipped: Vec<SkippedEntry>,
    pub collisions: Vec<CollisionFailure>,
    pub renames: Vec<Rename>,
    pub path_findings: Vec<Finding>,
    /// Set when the journal was left behind (a source failed hard).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staging_kept: Option<String>,
}

impl RestoreReport {
    pub fn new(
        run_id: &str,
        source_host: &str,
        source_os: Platform,
        destination_os: Platform,
        destination_root: &std::path::Path,
        dry_run: bool,
    ) -> RestoreReport {
        RestoreReport {
            run_id: run_id.to_string(),
            source_host: source_host.to_string(),
            source_os,
            destination_os,
            destination_root: destination_root.display().to_string(),
            dry_run,
            resumed: false,
            sources: Vec::new(),
            totals: Totals::default(),
            skipped: Vec::new(),
            collisions: Vec::new(),
            renames: Vec::new(),
            path_findings: Vec::new(),
            journal: None,
            staging_kept: None,
        }
    }

    pub fn push_source(&mut self, s: SourceReport) {
        self.totals.placed += s.placed;
        self.totals.skipped += s.skipped;
        self.totals.conflicts.add(&s.conflicts);
        self.totals.disk_needed += s.size;
        self.sources.push(s);
    }

    /// Spec §23: 5 when a recorded collision blocked a source, 9 when anything
    /// was skipped, 0 otherwise. A dry run is always 0.
    pub fn exit_code(&self) -> ExitCode {
        if self.dry_run {
            return ExitCode::Success;
        }
        if !self.collisions.is_empty() {
            return ExitCode::RestoreConflict;
        }
        let anything_skipped = self.totals.skipped > 0
            || self.sources.iter().any(|s| {
                matches!(
                    s.status,
                    SourceStatus::Skipped | SourceStatus::Failed | SourceStatus::Partial
                )
            });
        if anything_skipped {
            ExitCode::PartialSuccess
        } else {
            ExitCode::Success
        }
    }

    pub fn render_human(&self, console: &Console) -> String {
        let mut out = Vec::new();
        let verb = if self.dry_run {
            "Would restore"
        } else if self.resumed {
            "Resumed restore of"
        } else {
            "Restored"
        };
        out.push(format!(
            "{verb} snapshot {} from {} ({}) onto this {} machine.",
            self.run_id,
            self.source_host,
            self.source_os.display_name(),
            self.destination_os.display_name()
        ));
        out.push(String::new());
        let rows: Vec<Vec<String>> = self
            .sources
            .iter()
            .map(|s| {
                vec![
                    s.id.clone(),
                    s.destination.clone(),
                    source_status_text(s, self.dry_run),
                ]
            })
            .collect();
        out.push(indent(&human::table(
            &["SOURCE", "DESTINATION", "STATUS"],
            &rows,
        )));
        out.push(String::new());
        if self.dry_run {
            out.push(format!(
                "Staging needs up to {} of temporary space in moss's state directory (one source at a time). Nothing was written.",
                human::bytes(self.totals.disk_needed)
            ));
        } else {
            let mut line = format!(
                "Placed {}.",
                human::count(self.totals.placed, "entry", "entries")
            );
            let c = &self.totals.conflicts;
            if c.total() > 0 {
                line.push_str(&format!(
                    " Existing files: {} skipped, {} overwritten, {} backed up.",
                    c.skipped, c.overwritten, c.backed_up
                ));
            }
            out.push(line);
        }
        if !self.skipped.is_empty() {
            out.push(String::new());
            out.push(format!(
                "{} Skipped {}:",
                console.warn_mark(),
                human::count(self.skipped.len() as u64, "entry", "entries")
            ));
            let rows: Vec<Vec<String>> = self
                .skipped
                .iter()
                .take(50)
                .map(|s| vec![s.path.clone(), s.reason.clone()])
                .collect();
            out.push(indent(&human::table(&["PATH", "REASON"], &rows)));
            if self.skipped.len() > 50 {
                out.push(format!(
                    "  … and {} more (see --json)",
                    self.skipped.len() - 50
                ));
            }
        }
        if !self.collisions.is_empty() {
            out.push(String::new());
            out.push(format!(
                "{} {} blocked by name collisions this filesystem cannot keep apart:",
                console.fail_mark(),
                human::count(self.collisions.len() as u64, "source", "sources")
            ));
            for c in &self.collisions {
                out.push(format!("  {} ({}):", c.source, c.kind));
                for p in &c.paths {
                    out.push(format!("    {p}"));
                }
            }
            out.push(String::new());
            out.push(
                "Re-run with --rename-collisions to restore them as name.1, name.2 … (sorted order), or restore onto a case-sensitive volume with --to."
                    .into(),
            );
        }
        if !self.renames.is_empty() {
            out.push(String::new());
            out.push(format!(
                "Renamed {} to avoid collisions:",
                human::count(self.renames.len() as u64, "entry", "entries")
            ));
            for r in &self.renames {
                out.push(format!("  {}  →  {}", r.from, r.to));
            }
        }
        if !self.path_findings.is_empty() {
            let files: std::collections::BTreeSet<&str> =
                self.path_findings.iter().map(|f| f.file.as_str()).collect();
            out.push(String::new());
            out.push(format!(
                "Restored {} with paths that will not resolve on this system:",
                human::count(files.len() as u64, "file", "files")
            ));
            out.push(String::new());
            let width = self
                .path_findings
                .iter()
                .map(|f| format!("{}:{}", f.file, f.line).chars().count())
                .max()
                .unwrap_or(0);
            for f in &self.path_findings {
                let loc = format!("{}:{}", f.file, f.line);
                out.push(format!("  {loc:<width$}    {} {}", f.key, f.path));
                out.push(format!("  {:<width$}    → likely {}", "", f.suggestion));
                out.push(String::new());
            }
            out.push(
                "Review these manually. (`--rewrite-paths` is not available in this version.)"
                    .into(),
            );
        }
        if let Some(j) = &self.journal {
            out.push(String::new());
            out.push(format!(
                "{} The restore did not finish cleanly; the journal was kept at {j}. Re-run `moss restore` to resume or roll back.",
                console.warn_mark()
            ));
        }
        if let Some(s) = &self.staging_kept {
            out.push(format!(
                "Staged files were kept for inspection at {s}; remove that directory when done."
            ));
        }
        out.join("\n")
    }
}

fn source_status_text(s: &SourceReport, dry_run: bool) -> String {
    match s.status {
        SourceStatus::Planned => {
            let mut t = format!("{} to restore", human::bytes(s.size));
            if let Some(r) = &s.reason {
                t.push_str(&format!(" ({r})"));
            }
            t
        }
        SourceStatus::Restored => {
            if dry_run {
                "planned".into()
            } else {
                format!("restored ({})", human::count(s.placed, "entry", "entries"))
            }
        }
        SourceStatus::Partial => format!("partial ({} placed, {} skipped)", s.placed, s.skipped),
        SourceStatus::Skipped => format!(
            "skipped: {}",
            s.reason
                .clone()
                .unwrap_or_else(|| "no reason recorded".into())
        ),
        SourceStatus::Failed => format!(
            "failed: {}",
            s.reason
                .clone()
                .unwrap_or_else(|| "no reason recorded".into())
        ),
    }
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(id: &str, status: SourceStatus, placed: u64, skipped: u64) -> SourceReport {
        SourceReport {
            id: id.into(),
            category: ProfileCategory::Credentials,
            destination: format!("~/.{id}"),
            status,
            placed,
            skipped,
            conflicts: ConflictCounts::default(),
            size: 100,
            reason: None,
        }
    }

    fn report() -> RestoreReport {
        RestoreReport::new(
            "01RUN",
            "macbook",
            Platform::MacOs,
            Platform::Linux,
            std::path::Path::new("/home/rhys"),
            false,
        )
    }

    #[test]
    fn exit_codes_follow_the_spec() {
        let mut r = report();
        r.push_source(source("ssh", SourceStatus::Restored, 4, 0));
        assert_eq!(r.exit_code(), ExitCode::Success);
        r.push_source(source("gnupg", SourceStatus::Partial, 3, 1));
        assert_eq!(r.exit_code(), ExitCode::PartialSuccess);
        r.collisions.push(CollisionFailure {
            source: "documents".into(),
            kind: "case".into(),
            paths: vec!["~/Documents/A".into(), "~/Documents/a".into()],
        });
        assert_eq!(r.exit_code(), ExitCode::RestoreConflict);
        r.dry_run = true;
        assert_eq!(r.exit_code(), ExitCode::Success);
        assert_eq!(r.totals.placed, 7);
        assert_eq!(r.totals.disk_needed, 200);
    }

    #[test]
    fn human_report_has_spec_sections() {
        let mut r = report();
        r.push_source(source("ssh", SourceStatus::Restored, 4, 0));
        r.skipped.push(SkippedEntry {
            source: "ssh".into(),
            path: "~/.ssh/link".into(),
            reason: "symlink not supported here".into(),
        });
        r.path_findings.push(Finding {
            file: "~/.ssh/config".into(),
            line: 12,
            key: "IdentityFile".into(),
            path: "/Users/rhys/.ssh/id_ed25519".into(),
            suggestion: "/home/rhys/.ssh/id_ed25519".into(),
        });
        r.journal = Some("/state/restore-journal.json".into());
        let text = r.render_human(&Console::for_tests());
        assert!(
            text.contains("Restored snapshot 01RUN from macbook (macOS) onto this Linux machine.")
        );
        assert!(text.contains("SOURCE"));
        assert!(text.contains("restored (4 entries)"));
        assert!(
            text.contains("~/.ssh/config:12    IdentityFile /Users/rhys/.ssh/id_ed25519"),
            "{text}"
        );
        assert!(text.contains("→ likely /home/rhys/.ssh/id_ed25519"));
        assert!(text.contains("Restored 1 file with paths that will not resolve"));
        assert!(text.contains("restore-journal.json"));
        let json = crate::output::with_schema(&r);
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["sources"][0]["status"], "restored");
        assert_eq!(json["path_findings"][0]["line"], 12);
    }
}
