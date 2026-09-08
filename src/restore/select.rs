//! Snapshot selection (spec §15, §19): Kopia snapshots grouped into moss runs
//! by their `moss-run` tag, newest first, resolved from a selector such as
//! `latest` or a run-id prefix.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::backup::json::SnapshotManifest;
use crate::backup::repository::Repository;
use crate::backup::tags;
use crate::error::{MossError, Result};
use crate::platform::Platform;

/// One `moss backup` run: every Kopia snapshot that shares a `moss-run` tag.
#[derive(Debug, Clone)]
pub struct Run {
    pub id: String,
    pub started: Option<DateTime<Utc>>,
    pub host: String,
    pub user: String,
    pub os: Option<Platform>,
    pub profile: Option<String>,
    /// Data snapshots (the manifest snapshot is kept separately).
    pub members: Vec<SnapshotManifest>,
    pub manifest_snapshot: Option<String>,
    pub fatal_errors: u64,
    pub ignored_errors: u64,
    /// A member reported no error count at all (spec §18: treat as an error).
    pub missing_counts: bool,
    /// A member was marked incomplete by Kopia.
    pub incomplete: bool,
}

impl Run {
    pub fn total_size(&self) -> u64 {
        self.members.iter().map(SnapshotManifest::total_size).sum()
    }

    pub fn file_count(&self) -> u64 {
        self.members.iter().map(SnapshotManifest::file_count).sum()
    }

    /// Semantic source ids present in this run, in tag order.
    pub fn source_ids(&self) -> Vec<String> {
        self.members
            .iter()
            .filter_map(|m| m.tag(tags::SOURCE))
            .map(str::to_string)
            .collect()
    }

    pub fn snapshot_for_source(&self, source_id: &str) -> Option<&SnapshotManifest> {
        let wanted = tags::sanitize(source_id);
        self.members
            .iter()
            .find(|m| m.tag(tags::SOURCE) == Some(wanted.as_str()))
    }

    pub fn snapshot_by_id(&self, snapshot_id: &str) -> Option<&SnapshotManifest> {
        self.members.iter().find(|m| m.id == snapshot_id)
    }

    /// The date column of `moss snapshots`.
    pub fn started_display(&self) -> String {
        self.started
            .map(|t| {
                t.with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M")
                    .to_string()
            })
            .unwrap_or_else(|| "unknown".into())
    }

    /// The `STATUS` column (spec §19), one label set shared by `moss
    /// snapshots`, `moss status`, `moss verify` and `moss restore`:
    ///
    /// | Condition                                   | Label                                |
    /// |---------------------------------------------|--------------------------------------|
    /// | no manifest snapshot in the run             | `incomplete (no manifest)`           |
    /// | Kopia marked a member incomplete            | `incomplete`                         |
    /// | a member reported no error count (spec §18) | `unknown (no error counts reported)` |
    /// | fatal + ignored errors > 0                  | `partial (N skipped)`                |
    /// | otherwise                                   | `complete`                           |
    ///
    /// Checks run top to bottom; the first that applies wins.
    pub fn status_label(&self) -> String {
        if self.manifest_snapshot.is_none() {
            return "incomplete (no manifest)".into();
        }
        if self.incomplete {
            return "incomplete".into();
        }
        if self.missing_counts {
            return "unknown (no error counts reported)".into();
        }
        let skipped = self.fatal_errors + self.ignored_errors;
        if skipped == 0 {
            "complete".into()
        } else {
            format!("partial ({skipped} skipped)")
        }
    }

    /// The serialisable view printed by `moss snapshots --json`.
    pub fn summary(&self) -> RunSummary {
        RunSummary {
            id: self.id.clone(),
            started: self.started,
            host: self.host.clone(),
            user: self.user.clone(),
            os: self
                .os
                .map(|p| p.tag_value().to_string())
                .unwrap_or_else(|| "?".into()),
            profile: self.profile.clone().unwrap_or_default(),
            size: self.total_size(),
            files: self.file_count(),
            sources: self.source_ids(),
            snapshot_ids: self.members.iter().map(|m| m.id.clone()).collect(),
            manifest_snapshot_id: self.manifest_snapshot.clone(),
            fatal_errors: self.fatal_errors,
            ignored_errors: self.ignored_errors,
            status: self.status_label(),
        }
    }
}

/// A [`Run`] flattened for JSON output (`docs/json-schema.md`, `snapshots`).
/// `size`, `files`, `sources` and `snapshot_ids` exclude the manifest snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct RunSummary {
    pub id: String,
    pub started: Option<DateTime<Utc>>,
    pub host: String,
    pub user: String,
    /// The `moss-os` tag value (`macos`, `linux`, `windows`), or `?`.
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

/// Group raw snapshots into runs, newest first. Snapshots without a
/// `moss-run` tag are not moss's and are ignored.
pub fn group_runs(snapshots: Vec<SnapshotManifest>) -> Vec<Run> {
    let mut by_run: BTreeMap<String, Run> = BTreeMap::new();
    for snap in snapshots {
        let Some(run_id) = snap.tag(tags::RUN).map(str::to_string) else {
            continue;
        };
        let run = by_run.entry(run_id.clone()).or_insert_with(|| Run {
            id: run_id,
            started: None,
            host: String::new(),
            user: String::new(),
            os: None,
            profile: None,
            members: Vec::new(),
            manifest_snapshot: None,
            fatal_errors: 0,
            ignored_errors: 0,
            missing_counts: false,
            incomplete: false,
        });
        if run.host.is_empty() {
            run.host = snap.source.host.clone();
        }
        if run.user.is_empty() {
            run.user = snap.source.user_name.clone();
        }
        if run.os.is_none() {
            run.os = snap.tag(tags::OS).and_then(Platform::parse);
        }
        if run.profile.is_none() {
            run.profile = snap.tag(tags::PROFILE).map(str::to_string);
        }
        match (run.started, snap.start_time) {
            (None, Some(t)) => run.started = Some(t),
            (Some(cur), Some(t)) if t < cur => run.started = Some(t),
            _ => {}
        }
        if snap.tag(tags::SOURCE) == Some(tags::MANIFEST_SOURCE) {
            run.manifest_snapshot = Some(snap.id.clone());
            continue;
        }
        match snap.fatal_errors() {
            Some(n) => run.fatal_errors += n,
            None => run.missing_counts = true,
        }
        run.ignored_errors += snap.ignored_errors();
        if snap.incomplete.is_some() {
            run.incomplete = true;
        }
        run.members.push(snap);
    }
    let mut runs: Vec<Run> = by_run.into_values().collect();
    // Newest first; ULIDs sort chronologically so the id breaks ties.
    runs.sort_by(|a, b| b.started.cmp(&a.started).then_with(|| b.id.cmp(&a.id)));
    runs
}

/// Every run in the repository, newest first.
pub fn list_runs(repo: &Repository) -> Result<Vec<Run>> {
    Ok(group_runs(repo.snapshot_list(&[])?))
}

/// Resolve `latest` or a run-id prefix against the runs, optionally limited
/// to one source host.
pub fn select_run<'a>(runs: &'a [Run], selector: &str, from_host: Option<&str>) -> Result<&'a Run> {
    let candidates: Vec<&Run> = runs
        .iter()
        .filter(|r| from_host.is_none_or(|h| r.host.eq_ignore_ascii_case(h)))
        .collect();
    if candidates.is_empty() {
        return Err(MossError::Usage(match from_host {
            Some(h) => format!(
                "No snapshots from host {h:?} were found in the repository.\n\nRun `moss snapshots` to see which hosts have backed up here."
            ),
            None => "The repository has no moss snapshots yet.\n\nRun `moss backup` first.".into(),
        }));
    }
    if selector.is_empty() || selector.eq_ignore_ascii_case("latest") {
        return Ok(candidates[0]);
    }
    let needle = selector.to_ascii_uppercase();
    let matches: Vec<&Run> = candidates
        .iter()
        .copied()
        .filter(|r| r.id.to_ascii_uppercase().starts_with(&needle))
        .collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(MossError::Usage(format!(
            "No snapshot matches {selector:?}.\n\nRun `moss snapshots` to list snapshot ids, or use `latest`."
        ))),
        _ => Err(MossError::Usage(format!(
            "{selector:?} matches {} snapshots: {}.\n\nGive more characters of the id.",
            matches.len(),
            matches
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(
        id: &str,
        run: &str,
        source: &str,
        host: &str,
        start: &str,
        failed: Option<u64>,
    ) -> SnapshotManifest {
        let mut v = serde_json::json!({
            "id": id,
            "source": {"host": host, "userName": "u", "path": format!("/home/u/{source}")},
            "startTime": start,
            "tags": {"tag:moss-run": run, "tag:moss-source": source, "tag:moss-os": "linux", "tag:moss-profile": "p"},
            "rootEntry": {"summ": {"size": 10, "files": 2}}
        });
        if let Some(n) = failed {
            v["rootEntry"]["summ"]["numFailed"] = serde_json::json!(n);
        }
        serde_json::from_value(v).unwrap()
    }

    fn runs() -> Vec<Run> {
        group_runs(vec![
            snap(
                "a1",
                "01OLD",
                "ssh",
                "macbook",
                "2026-08-01T10:00:00Z",
                Some(0),
            ),
            snap(
                "a2",
                "01OLD",
                "manifest",
                "macbook",
                "2026-08-01T10:00:01Z",
                Some(0),
            ),
            snap(
                "b1",
                "01NEW",
                "ssh",
                "macbook",
                "2026-09-01T10:00:00Z",
                Some(0),
            ),
            snap(
                "b2",
                "01NEW",
                "documents",
                "macbook",
                "2026-09-01T10:00:02Z",
                Some(2),
            ),
            snap(
                "b3",
                "01NEW",
                "manifest",
                "macbook",
                "2026-09-01T10:00:03Z",
                Some(0),
            ),
            snap(
                "c1",
                "02LNX",
                "ssh",
                "linuxbox",
                "2026-08-15T10:00:00Z",
                None,
            ),
            serde_json::from_value(serde_json::json!({"id": "zz", "source": {"host": "x"}}))
                .unwrap(),
        ])
    }

    #[test]
    fn groups_newest_first_and_separates_manifest() {
        let runs = runs();
        assert_eq!(
            runs.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["01NEW", "02LNX", "01OLD"]
        );
        let new = &runs[0];
        assert_eq!(new.members.len(), 2);
        assert_eq!(new.manifest_snapshot.as_deref(), Some("b3"));
        assert_eq!(new.fatal_errors, 2);
        assert_eq!(new.os, Some(Platform::Linux));
        assert_eq!(new.host, "macbook");
        assert_eq!(new.source_ids(), vec!["ssh", "documents"]);
        assert_eq!(new.snapshot_for_source("documents").unwrap().id, "b2");
        assert_eq!(new.total_size(), 20);
        assert_eq!(
            new.started.unwrap().to_rfc3339(),
            "2026-09-01T10:00:00+00:00"
        );
        assert_eq!(new.status_label(), "partial (2 skipped)");
        assert_eq!(runs[2].status_label(), "complete");
        assert!(runs[1].missing_counts);
    }

    #[test]
    fn groups_and_labels_runs() {
        let runs = group_runs(vec![
            snap("a", "RUN1", "ssh", "mac", "2026-09-04T10:00:00Z", Some(0)),
            snap(
                "b",
                "RUN1",
                "documents",
                "mac",
                "2026-09-04T10:00:01Z",
                Some(2),
            ),
            snap(
                "c",
                "RUN1",
                "manifest",
                "mac",
                "2026-09-04T10:00:02Z",
                Some(0),
            ),
            snap("d", "RUN2", "ssh", "mac", "2026-09-04T11:00:00Z", Some(0)),
        ]);
        assert_eq!(runs.len(), 2);
        let r1 = runs.iter().find(|r| r.id == "RUN1").unwrap().summary();
        assert_eq!(r1.size, 20, "manifest excluded from size");
        assert_eq!(r1.files, 4);
        assert_eq!(r1.sources, vec!["ssh", "documents"]);
        assert_eq!(r1.snapshot_ids, vec!["a", "b"]);
        assert_eq!(r1.manifest_snapshot_id.as_deref(), Some("c"));
        assert_eq!(r1.fatal_errors, 2);
        assert_eq!(r1.status, "partial (2 skipped)");
        assert_eq!(r1.os, "linux");
        assert_eq!(r1.profile, "p");
        let r2 = runs.iter().find(|r| r.id == "RUN2").unwrap().summary();
        assert_eq!(r2.status, "incomplete (no manifest)");
        assert!(r2.manifest_snapshot_id.is_none());
    }

    #[test]
    fn missing_error_count_is_not_treated_as_complete() {
        let runs = group_runs(vec![
            snap("a", "R", "ssh", "mac", "2026-09-04T10:00:00Z", None),
            snap("m", "R", "manifest", "mac", "2026-09-04T10:00:01Z", Some(0)),
        ]);
        assert_eq!(runs.len(), 1);
        assert!(runs[0].missing_counts);
        assert_eq!(runs[0].status_label(), "unknown (no error counts reported)");
        assert_eq!(runs[0].summary().status, runs[0].status_label());
    }

    #[test]
    fn kopia_incomplete_flag_wins_over_error_counts() {
        let mut broken = snap("a", "R", "ssh", "mac", "2026-09-04T10:00:00Z", Some(3));
        broken.incomplete = Some("canceled".into());
        let runs = group_runs(vec![
            broken,
            snap("m", "R", "manifest", "mac", "2026-09-04T10:00:01Z", Some(0)),
        ]);
        assert!(runs[0].incomplete);
        assert_eq!(runs[0].status_label(), "incomplete");
        // A missing manifest outranks everything else.
        let runs = group_runs(vec![snap(
            "a",
            "R",
            "ssh",
            "mac",
            "2026-09-04T10:00:00Z",
            None,
        )]);
        assert_eq!(runs[0].status_label(), "incomplete (no manifest)");
    }

    #[test]
    fn selectors() {
        let runs = runs();
        assert_eq!(select_run(&runs, "latest", None).unwrap().id, "01NEW");
        assert_eq!(select_run(&runs, "", None).unwrap().id, "01NEW");
        assert_eq!(
            select_run(&runs, "latest", Some("linuxbox")).unwrap().id,
            "02LNX"
        );
        assert_eq!(select_run(&runs, "01old", None).unwrap().id, "01OLD");
        assert_eq!(select_run(&runs, "02", None).unwrap().id, "02LNX");
        let err = select_run(&runs, "01", None).unwrap_err();
        assert!(err.to_string().contains("matches 2 snapshots"), "{err}");
        assert_eq!(err.exit_code().code(), 2);
        assert!(select_run(&runs, "9", None).is_err());
        assert!(select_run(&runs, "latest", Some("nohost")).is_err());
        assert!(select_run(&[], "latest", None).is_err());
    }
}
