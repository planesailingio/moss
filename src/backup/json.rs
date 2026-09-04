//! Defensive views of Kopia's `--json` output (spec §5).
//!
//! Kopia's JSON is `json.Marshal` over internal structs with no stability
//! promise. Every struct here uses `#[serde(default)]`, ignores unknown fields,
//! and never fails on an addition. Fields critical to correctness are
//! `Option` so absence is detectable (spec §18).
//!
//! Field names verified against Kopia 0.23.1; fixtures in
//! `tests/fixtures/kopia/0.23.1/`.

use std::collections::BTreeMap;

use serde::Deserialize;

/// `kopia snapshot create --json` / one element of `snapshot list --json`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SnapshotManifest {
    pub id: String,
    pub source: SourceInfo,
    pub description: String,
    #[serde(rename = "startTime")]
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "endTime")]
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub stats: Option<SnapshotStats>,
    #[serde(rename = "rootEntry")]
    pub root_entry: Option<RootEntry>,
    /// `omitempty`: present only when the snapshot is incomplete (reason string).
    pub incomplete: Option<String>,
    /// Keys arrive as `tag:<key>` (verified 0.23.1).
    pub tags: BTreeMap<String, String>,
}

impl SnapshotManifest {
    /// A moss tag value (`moss-run`, `moss-source`, …), tolerant of Kopia's
    /// `tag:` key prefix.
    pub fn tag(&self, key: &str) -> Option<&str> {
        self.tags
            .get(&format!("tag:{key}"))
            .or_else(|| self.tags.get(key))
            .map(String::as_str)
    }

    /// Fatal error count. `None` when Kopia did not report one — the caller
    /// must treat that as an error, not zero (spec §18).
    pub fn fatal_errors(&self) -> Option<u64> {
        self.root_entry
            .as_ref()
            .and_then(|r| r.summ.as_ref())
            .and_then(|s| s.num_failed)
            .or_else(|| self.stats.as_ref().and_then(|s| s.error_count))
    }

    /// Ignored error count; `omitempty` in Kopia, so absence means zero.
    pub fn ignored_errors(&self) -> u64 {
        self.root_entry
            .as_ref()
            .and_then(|r| r.summ.as_ref())
            .and_then(|s| s.num_ignored_errors)
            .or_else(|| self.stats.as_ref().and_then(|s| s.ignored_error_count))
            .unwrap_or(0)
    }

    /// Logical size of the tree. `rootEntry.summ` describes the whole tree;
    /// `stats` describes this upload (cached files are not recounted), so the
    /// summary is preferred.
    pub fn total_size(&self) -> u64 {
        self.root_entry
            .as_ref()
            .and_then(|r| r.summ.as_ref())
            .and_then(|s| s.size)
            .or_else(|| self.stats.as_ref().and_then(|s| s.total_size))
            .unwrap_or(0)
    }

    pub fn file_count(&self) -> u64 {
        self.root_entry
            .as_ref()
            .and_then(|r| r.summ.as_ref())
            .and_then(|s| s.files)
            .or_else(|| self.stats.as_ref().and_then(|s| s.file_count))
            .unwrap_or(0)
    }

    pub fn error_samples(&self) -> Vec<EntryError> {
        self.root_entry
            .as_ref()
            .and_then(|r| r.summ.as_ref())
            .map(|s| s.errors.clone())
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SourceInfo {
    pub host: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    pub path: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SnapshotStats {
    #[serde(rename = "totalSize")]
    pub total_size: Option<u64>,
    #[serde(rename = "fileCount")]
    pub file_count: Option<u64>,
    #[serde(rename = "dirCount")]
    pub dir_count: Option<u64>,
    #[serde(rename = "errorCount")]
    pub error_count: Option<u64>,
    #[serde(rename = "ignoredErrorCount")]
    pub ignored_error_count: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RootEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub obj: String,
    pub summ: Option<DirectorySummary>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DirectorySummary {
    pub size: Option<u64>,
    pub files: Option<u64>,
    pub symlinks: Option<u64>,
    pub dirs: Option<u64>,
    #[serde(rename = "numFailed")]
    pub num_failed: Option<u64>,
    #[serde(rename = "numIgnoredErrors")]
    pub num_ignored_errors: Option<u64>,
    /// Capped at 10 by Kopia.
    pub errors: Vec<EntryError>,
}

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
#[serde(default)]
pub struct EntryError {
    pub path: String,
    pub error: String,
}

/// `kopia repository status --json`. Never log this (spec §5).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RepositoryStatus {
    #[serde(rename = "configFile")]
    pub config_file: String,
    #[serde(rename = "uniqueIDHex")]
    pub unique_id_hex: String,
    #[serde(rename = "clientOptions")]
    pub client_options: ClientOptions,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ClientOptions {
    pub hostname: String,
    pub username: String,
    pub readonly: bool,
    pub description: String,
}

/// `kopia maintenance info --json`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct MaintenanceInfo {
    pub owner: String,
    pub quick: MaintenanceCycle,
    pub full: MaintenanceCycle,
    pub schedule: MaintenanceSchedule,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct MaintenanceCycle {
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct MaintenanceSchedule {
    #[serde(rename = "nextFullMaintenance")]
    pub next_full: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "nextQuickMaintenance")]
    pub next_quick: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/kopia/0.23.1")
            .join(name);
        std::fs::read_to_string(p).unwrap()
    }

    #[test]
    fn create_clean() {
        let m: SnapshotManifest =
            serde_json::from_str(&fixture("snapshot-create-clean.json")).unwrap();
        assert_eq!(m.fatal_errors(), Some(0));
        assert_eq!(m.ignored_errors(), 0);
        assert_eq!(m.tag("moss-run"), Some("01TEST"));
        assert_eq!(m.tag("moss-source"), Some("test"));
        assert!(
            m.stats.is_none(),
            "create output has no stats block in 0.23.1"
        );
        assert_eq!(m.file_count(), 3);
    }

    #[test]
    fn create_with_ignored_errors_is_exit_zero_but_counted() {
        let m: SnapshotManifest =
            serde_json::from_str(&fixture("snapshot-create-ignored-errors.json")).unwrap();
        assert_eq!(m.fatal_errors(), Some(0));
        assert_eq!(m.ignored_errors(), 1);
        assert_eq!(m.error_samples()[0].path, "noperm");
    }

    #[test]
    fn create_fatal_still_has_manifest() {
        let m: SnapshotManifest =
            serde_json::from_str(&fixture("snapshot-create-fatal.json")).unwrap();
        assert_eq!(m.fatal_errors(), Some(1));
        assert!(!m.id.is_empty());
    }

    #[test]
    fn missing_counts_are_none_not_zero() {
        let m: SnapshotManifest =
            serde_json::from_str(r#"{"id":"x","rootEntry":{"summ":{"size":1}}}"#).unwrap();
        assert_eq!(m.fatal_errors(), None);
        assert_eq!(m.ignored_errors(), 0);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let m: SnapshotManifest = serde_json::from_str(
            r#"{"id":"x","brandNewField":{"a":1},"stats":{"newCounter":5,"errorCount":0}}"#,
        )
        .unwrap();
        assert_eq!(m.fatal_errors(), Some(0));
    }

    #[test]
    fn list_and_status_and_maintenance() {
        let list: Vec<SnapshotManifest> =
            serde_json::from_str(&fixture("snapshot-list.json")).unwrap();
        assert_eq!(list.len(), 2);
        assert!(list[0].start_time.is_some());
        assert_eq!(list[0].source.host, "fixture-host");
        let status: RepositoryStatus =
            serde_json::from_str(&fixture("repository-status.json")).unwrap();
        assert_eq!(status.unique_id_hex.len(), 64);
        let m: MaintenanceInfo = serde_json::from_str(&fixture("maintenance-info.json")).unwrap();
        assert_eq!(m.owner, "fixture-user@fixture-host");
        assert!(m.schedule.next_full.is_some());
    }
}
