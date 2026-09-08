//! The JSON shape of every command that has no domain report type of its own.
//! `schema_version` is prepended by `Console::json_report`; each struct here is
//! pinned by a snapshot test so a field rename is a deliberate, reviewed change
//! (spec §26: additions only within a major version).

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;

use crate::backup::manifest::Manifest;
use crate::profile::patterns::ExclusionKind;
use crate::restore::select::RunSummary;
use crate::scan::walker::ExcludedStats;

/// `moss <anything>` when it fails.
#[derive(Debug, Serialize)]
pub struct ErrorReport {
    pub error: String,
    pub exit_code: i32,
    pub exit_code_name: &'static str,
}

/// `moss backup --dry-run`.
#[derive(Debug, Serialize)]
pub struct DryRunReport<'a> {
    pub dry_run: bool,
    pub run_id: &'a str,
    pub repository: String,
    pub manifest: &'a Manifest,
    pub excluded: &'a BTreeMap<ExclusionKind, ExcludedStats>,
}

/// `moss snapshots`.
#[derive(Debug, Serialize)]
pub struct RunsReport {
    pub runs: Vec<RunSummary>,
}

/// `moss status`.
#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub repository: String,
    pub repository_id: String,
    pub kopia_unique_id: String,
    pub credentials: &'static str,
    pub maintenance_owner: Option<String>,
    pub next_full_maintenance: Option<chrono::DateTime<chrono::Utc>>,
    pub runs: usize,
    pub latest_by_host: Vec<HostLatest>,
}

#[derive(Debug, Serialize)]
pub struct HostLatest {
    pub host: String,
    pub os: String,
    pub user: String,
    pub run: String,
    pub started: Option<chrono::DateTime<chrono::Utc>>,
    pub status: String,
}

impl HostLatest {
    pub fn from_summary(s: &RunSummary) -> HostLatest {
        HostLatest {
            host: s.host.clone(),
            os: s.os.clone(),
            user: s.user.clone(),
            run: s.id.clone(),
            started: s.started,
            status: s.status.clone(),
        }
    }
}

/// `moss verify`.
#[derive(Debug, Serialize)]
pub struct VerifyReport<'a> {
    pub run: &'a str,
    pub snapshots_verified: usize,
    pub files_percent: u8,
    pub mode_problems: &'a [String],
}

/// `moss prune`.
#[derive(Debug, Serialize)]
pub struct PruneReport<'a> {
    pub deleted: bool,
    pub kopia_output: &'a str,
}

/// `moss maintenance`.
#[derive(Debug, Serialize)]
pub struct MaintenanceReport<'a> {
    pub full: bool,
    pub owner: &'a str,
    pub kopia_output: &'a str,
}

/// `moss yubikey detect|status`.
#[derive(Debug, Serialize)]
pub struct YubikeyReport {
    pub detected: usize,
    pub configured: bool,
    pub available: bool,
}

/// `moss restore --rollback`.
#[derive(Debug, Serialize)]
pub struct RollbackReport {
    pub rolled_back: bool,
    pub removed: Vec<String>,
    pub restored_backups: Vec<String>,
    pub failed: Vec<(String, String)>,
}

/// `moss init list-backup-endpoints`.
#[derive(Debug, Serialize)]
pub struct EndpointsReport {
    pub endpoints: &'static [crate::endpoints::Endpoint],
}

/// `moss init`.
#[derive(Debug, Serialize)]
pub struct InitReport {
    pub repository: Option<String>,
    pub repository_id: Option<String>,
    pub identity: String,
    pub sources: usize,
    pub recovery_acknowledged: bool,
    pub config: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::with_schema;

    fn summary() -> RunSummary {
        RunSummary {
            id: "01RUN".into(),
            started: Some(
                chrono::DateTime::parse_from_rfc3339("2026-09-04T10:00:00Z")
                    .unwrap()
                    .into(),
            ),
            host: "mac".into(),
            user: "rhys".into(),
            os: "macos".into(),
            profile: "rhys".into(),
            size: 30,
            files: 4,
            sources: vec!["ssh".into(), "documents".into()],
            snapshot_ids: vec!["a".into(), "b".into()],
            manifest_snapshot_id: Some("c".into()),
            fatal_errors: 0,
            ignored_errors: 0,
            status: "complete".into(),
        }
    }

    #[test]
    fn error_report() {
        insta::assert_json_snapshot!(with_schema(&ErrorReport {
            error: "boom".into(),
            exit_code: 1,
            exit_code_name: "general failure",
        }));
    }

    #[test]
    fn dry_run_report() {
        let mut manifest = crate::restore::test_support::sample_manifest();
        manifest.created_at = chrono::DateTime::parse_from_rfc3339("2026-09-04T10:00:00Z")
            .unwrap()
            .into();
        let mut excluded = BTreeMap::new();
        excluded.insert(
            ExclusionKind::BuildArtifact,
            ExcludedStats {
                entries: 1,
                size: 0,
                measured: false,
            },
        );
        insta::assert_json_snapshot!(with_schema(&DryRunReport {
            dry_run: true,
            run_id: "01RUN",
            repository: "/tmp/repo".into(),
            manifest: &manifest,
            excluded: &excluded,
        }));
    }

    #[test]
    fn runs_and_status_reports() {
        insta::assert_json_snapshot!(
            "runs",
            with_schema(&RunsReport {
                runs: vec![summary()]
            })
        );
        insta::assert_json_snapshot!(
            "status",
            with_schema(&StatusReport {
                repository: "/tmp/repo".into(),
                repository_id: "71c0c64b14b241b7".into(),
                kopia_unique_id: "abcdef".into(),
                credentials: "keyring",
                maintenance_owner: Some("rhys@mac".into()),
                next_full_maintenance: None,
                runs: 1,
                latest_by_host: vec![HostLatest::from_summary(&summary())],
            })
        );
    }

    #[test]
    fn small_reports() {
        insta::assert_json_snapshot!(
            "verify",
            with_schema(&VerifyReport {
                run: "01RUN",
                snapshots_verified: 3,
                files_percent: 10,
                mode_problems: &["~/.ssh/id_ed25519 is mode 0644".to_string()],
            })
        );
        insta::assert_json_snapshot!(
            "prune",
            with_schema(&PruneReport {
                deleted: false,
                kopia_output: "nothing to expire",
            })
        );
        insta::assert_json_snapshot!(
            "maintenance",
            with_schema(&MaintenanceReport {
                full: true,
                owner: "rhys@mac",
                kopia_output: "ok",
            })
        );
        insta::assert_json_snapshot!(
            "yubikey",
            with_schema(&YubikeyReport {
                detected: 0,
                configured: false,
                available: false,
            })
        );
        insta::assert_json_snapshot!(
            "rollback",
            with_schema(&RollbackReport {
                rolled_back: true,
                removed: vec!["/h/.ssh/half".into()],
                restored_backups: vec![],
                failed: vec![],
            })
        );
        insta::assert_json_snapshot!(
            "init",
            with_schema(&InitReport {
                repository: Some("/tmp/repo".into()),
                repository_id: Some("71c0c64b14b241b7".into()),
                identity: "rhys".into(),
                sources: 12,
                recovery_acknowledged: true,
                config: PathBuf::from("/h/config.yaml"),
            })
        );
    }
}
