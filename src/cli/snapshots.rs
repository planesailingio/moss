//! `moss snapshots` (spec §19): Kopia snapshots grouped into moss runs.

use std::collections::BTreeMap;

use clap::Args;
use serde::Serialize;

use crate::backup::json::SnapshotManifest;
use crate::backup::tags;
use crate::cli::AppContext;
use crate::error::{ExitCode, Result};
use crate::output::human;

#[derive(Debug, Args)]
pub struct SnapshotsArgs {
    /// Only runs from this host.
    #[arg(long)]
    pub host: Option<String>,
    /// Only the most recent run.
    #[arg(long)]
    pub latest: bool,
}

#[derive(Debug, Serialize)]
pub struct RunSummary {
    pub id: String,
    pub started: Option<chrono::DateTime<chrono::Utc>>,
    pub host: String,
    pub user: String,
    pub os: String,
    pub profile: String,
    pub size: u64,
    pub files: u64,
    pub sources: Vec<String>,
    pub snapshot_ids: Vec<String>,
    pub manifest_snapshot_id: Option<String>,
    pub fatal_errors: u64,
    pub ignored_errors: u64,
    pub status: String,
}

/// Group Kopia snapshots by run tag. Snapshots without moss tags are ignored.
pub fn group_runs(snapshots: &[SnapshotManifest]) -> Vec<RunSummary> {
    let mut by_run: BTreeMap<String, Vec<&SnapshotManifest>> = BTreeMap::new();
    for s in snapshots {
        if let Some(run) = s.tag(tags::RUN) {
            by_run.entry(run.to_string()).or_default().push(s);
        }
    }
    let mut runs: Vec<RunSummary> = by_run
        .into_iter()
        .map(|(id, members)| {
            let first = members[0];
            let manifest = members
                .iter()
                .find(|m| m.tag(tags::SOURCE) == Some(tags::MANIFEST_SOURCE));
            let data: Vec<&&SnapshotManifest> = members
                .iter()
                .filter(|m| m.tag(tags::SOURCE) != Some(tags::MANIFEST_SOURCE))
                .collect();
            let fatal: u64 = data.iter().map(|m| m.fatal_errors().unwrap_or(1)).sum();
            let ignored: u64 = data.iter().map(|m| m.ignored_errors()).sum();
            let errors = fatal + ignored;
            RunSummary {
                started: members.iter().filter_map(|m| m.start_time).min(),
                host: first.source.host.clone(),
                user: first.source.user_name.clone(),
                os: first.tag(tags::OS).unwrap_or("?").to_string(),
                profile: first.tag(tags::PROFILE).unwrap_or("").to_string(),
                size: data.iter().map(|m| m.total_size()).sum(),
                files: data.iter().map(|m| m.file_count()).sum(),
                sources: data
                    .iter()
                    .filter_map(|m| m.tag(tags::SOURCE))
                    .map(String::from)
                    .collect(),
                snapshot_ids: data.iter().map(|m| m.id.clone()).collect(),
                manifest_snapshot_id: manifest.map(|m| m.id.clone()),
                fatal_errors: fatal,
                ignored_errors: ignored,
                status: if manifest.is_none() {
                    "incomplete (no manifest)".into()
                } else if errors == 0 {
                    "complete".into()
                } else {
                    format!("partial ({errors} skipped)")
                },
                id,
            }
        })
        .collect();
    runs.sort_by(|a, b| b.started.cmp(&a.started).then_with(|| b.id.cmp(&a.id)));
    runs
}

pub fn run(ctx: &AppContext, args: SnapshotsArgs) -> Result<ExitCode> {
    let console = ctx.console;
    let connected = ctx.connect()?;
    let repo = connected.repository();
    let snapshots = repo.snapshot_list(&[])?;
    let mut runs = group_runs(&snapshots);
    if let Some(h) = &args.host {
        runs.retain(|r| r.host.eq_ignore_ascii_case(h));
    }
    if args.latest {
        runs.truncate(1);
    }
    if console.json {
        console.json_report(&serde_json::json!({ "runs": runs }))?;
        return Ok(ExitCode::Success);
    }
    if runs.is_empty() {
        println!("No snapshots yet. Run `moss backup`.");
        return Ok(ExitCode::Success);
    }
    let rows: Vec<Vec<String>> = runs
        .iter()
        .map(|r| {
            vec![
                r.id.chars().take(10).collect(),
                r.started
                    .map(|t| {
                        t.with_timezone(&chrono::Local)
                            .format("%Y-%m-%d %H:%M")
                            .to_string()
                    })
                    .unwrap_or_else(|| "?".into()),
                r.host.clone(),
                r.os.clone(),
                human::bytes(r.size),
                r.status.clone(),
            ]
        })
        .collect();
    println!(
        "{}",
        human::table(&["ID", "DATE", "HOST", "OS", "SIZE", "STATUS"], &rows)
    );
    Ok(ExitCode::Success)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(id: &str, run: &str, source: &str, failed: Option<u64>, size: u64) -> SnapshotManifest {
        let mut m: SnapshotManifest = serde_json::from_str(&format!(
            r#"{{"id":"{id}","source":{{"host":"mac","userName":"rhys","path":"/x"}},"startTime":"2026-09-04T10:00:00Z","stats":{{"totalSize":{size},"fileCount":2,"errorCount":{}}},"tags":{{"tag:moss-run":"{run}","tag:moss-source":"{source}","tag:moss-os":"macos","tag:moss-profile":"rhys"}}}}"#,
            failed.unwrap_or(0)
        ))
        .unwrap();
        if failed.is_none() {
            m.stats = None;
        }
        m
    }

    #[test]
    fn groups_and_labels_runs() {
        let snaps = vec![
            snap("a", "RUN1", "ssh", Some(0), 10),
            snap("b", "RUN1", "documents", Some(2), 20),
            snap("c", "RUN1", "manifest", Some(0), 1),
            snap("d", "RUN2", "ssh", Some(0), 5),
        ];
        let runs = group_runs(&snaps);
        assert_eq!(runs.len(), 2);
        let r1 = runs.iter().find(|r| r.id == "RUN1").unwrap();
        assert_eq!(r1.size, 30, "manifest excluded from size");
        assert_eq!(r1.status, "partial (2 skipped)");
        assert_eq!(r1.manifest_snapshot_id.as_deref(), Some("c"));
        let r2 = runs.iter().find(|r| r.id == "RUN2").unwrap();
        assert_eq!(r2.status, "incomplete (no manifest)");
    }

    #[test]
    fn missing_error_count_is_not_treated_as_complete() {
        let snaps = vec![
            snap("a", "R", "ssh", None, 1),
            snap("m", "R", "manifest", Some(0), 1),
        ];
        let runs = group_runs(&snaps);
        assert!(runs[0].status.starts_with("partial"));
    }
}
