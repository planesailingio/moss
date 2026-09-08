//! The backup run (spec §18, §19, §21, §27): lock → gate → scan → warn →
//! manifest → one `kopia snapshot create` over every source plus the manifest
//! directory → per-snapshot error counts → exit 0 or 9.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::backup::manifest::{
    Manifest, ManifestSource, SensitiveCount, SkipReason, Skipped, Totals,
};
use crate::backup::repository::Repository;
use crate::backup::tags;
use crate::config::Config;
use crate::error::{MossError, Result};
use crate::model::ProfileSource;
use crate::platform::HostInfo;
use crate::scan::ScanResult;

#[derive(Debug, Serialize)]
pub struct RunOutcome {
    pub run_id: String,
    pub complete: bool,
    pub snapshots: Vec<SnapshotOutcome>,
    pub skipped: Vec<Skipped>,
    pub collisions: usize,
    pub total_size: u64,
    pub total_files: u64,
    pub manifest_path: PathBuf,
    pub unexpected_errors: u64,
}

impl RunOutcome {
    /// Spec §18, §23: 9 when anything was skipped so schedulers notice.
    pub fn exit_code(&self) -> crate::error::ExitCode {
        if self.complete {
            crate::error::ExitCode::Success
        } else {
            crate::error::ExitCode::PartialSuccess
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SnapshotOutcome {
    pub source: String,
    pub snapshot_id: String,
    pub fatal_errors: u64,
    pub ignored_errors: u64,
    pub size: u64,
    pub files: u64,
}

/// Build the manifest from a scan before Kopia runs.
pub fn build_manifest(
    run_id: &str,
    config: &Config,
    host: &HostInfo,
    kopia_version: &str,
    sources: &[&ProfileSource],
    scan: &ScanResult,
) -> Manifest {
    let mut categories: Vec<_> = sources.iter().map(|s| s.category).collect();
    categories.sort_by_key(|c| c.display_name());
    categories.dedup();
    Manifest {
        schema_version: crate::backup::manifest::MANIFEST_SCHEMA_VERSION,
        run_id: run_id.to_string(),
        profile: config.profile.name.clone(),
        profile_identity: config.profile.identity.clone(),
        source_os: host.platform,
        source_host: host.hostname.clone(),
        source_user: host.username.clone(),
        source_home: host.home.display().to_string(),
        tool_version: crate::VERSION.to_string(),
        kopia_version: kopia_version.to_string(),
        created_at: chrono::Utc::now(),
        categories,
        sources: sources
            .iter()
            .map(|s| {
                let stats = scan.sources.iter().find(|st| st.id == s.id);
                ManifestSource {
                    id: s.id.clone(),
                    category: s.category,
                    portable: s.portable,
                    path: s.home_relative(&host.home),
                    sensitive: s.sensitive,
                    size: stats.map(|st| st.size).unwrap_or(0),
                    files: stats.map(|st| st.files).unwrap_or(0),
                    snapshot_id: None,
                    fatal_errors: 0,
                    ignored_errors: 0,
                }
            })
            .collect(),
        skipped: scan.skipped.clone(),
        collisions: scan.collisions.clone(),
        sensitive_counts: scan
            .sensitive
            .iter()
            .map(|(k, v)| SensitiveCount {
                kind: *k,
                files: *v,
            })
            .collect(),
        totals: Totals {
            size: scan.total_size,
            files: scan.total_files,
            dirs: scan.total_dirs,
            excluded_size: scan.excluded.values().map(|e| e.size).sum(),
        },
    }
}

/// Execute the Kopia side of a run. Sources are snapshotted together with
/// the manifest directory in one invocation; all carry the run tags.
pub fn execute(
    repo: &Repository<'_>,
    manifests_dir: &Path,
    mut manifest: Manifest,
    sources: &[&ProfileSource],
    rules: &crate::profile::rules::RuleSet,
) -> Result<RunOutcome> {
    let run_dir = manifests_dir.join(&manifest.run_id);
    let manifest_path = manifest.write(&run_dir)?;

    // Kopia policies: unreadable files are recorded, not fatal (spec §18), and
    // the scan's exclusions apply to the upload too (spec §10).
    for s in sources {
        repo.set_source_policy(&s.path, &rules.kopia_ignore_rules_for(&s.path))?;
    }
    repo.set_source_policy(&run_dir, &[])?;

    let base_tags = tags::run_tags(
        &manifest.run_id,
        &manifest.profile_identity,
        manifest.source_os,
    );
    let mut outcomes = Vec::new();
    let mut unexpected = 0u64;

    // One invocation per source so each snapshot gets its own moss-source tag.
    for s in sources {
        let mut t = base_tags.clone();
        t.push(tags::source_tag(&s.id));
        let manifests = repo.snapshot_create(&[&s.path], &t)?;
        let m = manifests
            .into_iter()
            .next()
            .ok_or_else(|| MossError::Kopia {
                message: format!("Kopia produced no snapshot for {}", s.path.display()),
                detail: String::new(),
            })?;
        let fatal = m.fatal_errors().ok_or_else(|| MossError::Integrity(format!(
            "Kopia's output for {} did not include an error count; refusing to call this snapshot complete.",
            s.path.display()
        )))?;
        let ignored = m.ignored_errors();
        if let Some(ms) = manifest.sources.iter_mut().find(|ms| ms.id == s.id) {
            ms.snapshot_id = Some(m.id.clone());
            ms.fatal_errors = fatal;
            ms.ignored_errors = ignored;
        }
        // Errors the scan did not predict become skipped entries too.
        let predicted = manifest
            .skipped
            .iter()
            .filter(|k| {
                k.path
                    .starts_with(&s.home_relative(Path::new(&manifest.source_home)))
            })
            .count() as u64;
        if fatal + ignored > predicted {
            unexpected += fatal + ignored - predicted;
            for e in m.error_samples() {
                let path = format!(
                    "{}/{}",
                    s.home_relative(Path::new(&manifest.source_home)),
                    e.path
                );
                if !manifest.skipped.iter().any(|k| k.path == path) {
                    manifest.skipped.push(Skipped {
                        path,
                        reason: SkipReason::BackupError,
                        errno: None,
                        detail: Some(e.error),
                    });
                }
            }
        }
        outcomes.push(SnapshotOutcome {
            source: s.id.to_string(),
            snapshot_id: m.id.clone(),
            fatal_errors: fatal,
            ignored_errors: ignored,
            size: m.total_size(),
            files: m.file_count(),
        });
    }

    // Final manifest (with snapshot ids and any unexpected errors) travels with the run.
    manifest.write(&run_dir)?;
    let mut t = base_tags.clone();
    t.push((tags::SOURCE.into(), tags::MANIFEST_SOURCE.into()));
    let mm = repo.snapshot_create(&[&run_dir], &t)?;
    if mm.first().and_then(|m| m.fatal_errors()) != Some(0) {
        return Err(MossError::Integrity(
            "The manifest snapshot did not complete cleanly.".into(),
        ));
    }

    let complete = manifest.is_complete() && unexpected == 0;
    Ok(RunOutcome {
        run_id: manifest.run_id.clone(),
        complete,
        snapshots: outcomes,
        skipped: manifest.skipped.clone(),
        collisions: manifest.collisions.len(),
        total_size: manifest.totals.size,
        total_files: manifest.totals.files,
        manifest_path,
        unexpected_errors: unexpected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::kopia::testing::FixtureRunner;
    use crate::backup::manifest::MANIFEST_SCHEMA_VERSION;
    use crate::config::{RepositoryConfig, RepositoryType};
    use crate::model::{Inclusion, Platform, Portability, ProfileCategory, SemanticId};
    use crate::profile::rules::RuleSet;
    use crate::security::secret::Secret;

    fn source(home: &Path) -> ProfileSource {
        ProfileSource {
            id: SemanticId::new("test"),
            path: home.join("src"),
            category: ProfileCategory::PersonalData,
            platform: Platform::MacOs,
            reason: "test".into(),
            default_action: Inclusion::Include,
            sensitive: false,
            portable: Portability::Portable,
        }
    }

    fn manifest(home: &Path, source: &ProfileSource) -> Manifest {
        Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            run_id: "01TEST".into(),
            profile: "default".into(),
            profile_identity: "tester".into(),
            source_os: Platform::MacOs,
            source_host: "host".into(),
            source_user: "tester".into(),
            source_home: home.display().to_string(),
            tool_version: "0.0.0".into(),
            kopia_version: "0.23.1".into(),
            created_at: chrono::Utc::now(),
            categories: vec![source.category],
            sources: vec![ManifestSource {
                id: source.id.clone(),
                category: source.category,
                portable: source.portable,
                path: source.home_relative(home),
                sensitive: false,
                size: 14,
                files: 3,
                snapshot_id: None,
                fatal_errors: 0,
                ignored_errors: 0,
            }],
            skipped: Vec::new(),
            collisions: Vec::new(),
            sensitive_counts: Vec::new(),
            totals: Totals::default(),
        }
    }

    fn repo_config() -> RepositoryConfig {
        RepositoryConfig {
            kind: RepositoryType::Filesystem,
            id: "x".into(),
            path: Some("/tmp/r".into()),
            bucket: None,
            prefix: None,
            endpoint: None,
            region: None,
            tls: None,
            credential_store: Default::default(),
            recovery_acknowledged_at: None,
            created_at: None,
            local: None,
        }
    }

    /// Run `execute` with the manifest snapshot answered by the clean fixture
    /// and the source snapshot by `source_fixture`.
    fn run_with(
        source_fixture: &str,
        exit: i32,
    ) -> (RunOutcome, Vec<Vec<String>>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(home.join("src")).unwrap();
        let runner = FixtureRunner::new()
            .on_fixture(
                &["snapshot", "create", "moss-source:manifest"],
                "snapshot-create-clean.json",
                0,
            )
            .on_fixture(&["snapshot", "create"], source_fixture, exit);
        let cfg = repo_config();
        let pw = Secret::new("pw");
        let repo = Repository::new(&runner, &cfg, &pw);
        let src = source(&home);
        let rules = RuleSet::build(&Config::default(), &home, &[]).unwrap();
        let outcome = execute(
            &repo,
            &tmp.path().join("manifests"),
            manifest(&home, &src),
            &[&src],
            &rules,
        )
        .unwrap();
        (outcome, runner.calls(), tmp)
    }

    #[test]
    fn clean_run_is_complete() {
        let (outcome, calls, _tmp) = run_with("snapshot-create-clean.json", 0);
        assert!(outcome.complete);
        assert!(outcome.skipped.is_empty());
        assert_eq!(outcome.unexpected_errors, 0);
        assert_eq!(outcome.snapshots.len(), 1);
        assert_eq!(
            outcome.snapshots[0].snapshot_id,
            "75b224b4694aac0d843af1e698ee1410"
        );
        assert_eq!(outcome.snapshots[0].files, 3);
        assert!(outcome.manifest_path.is_file());
        // Policies first (clear, then set) for the source and the manifest
        // dir, then one snapshot per source, then the manifest snapshot.
        let verbs: Vec<String> = calls.iter().map(|c| c[..2].join(" ")).collect();
        assert_eq!(
            verbs,
            vec![
                "policy set",
                "policy set",
                "policy set",
                "policy set",
                "snapshot create",
                "snapshot create"
            ]
        );
        assert!(calls[0].contains(&"--clear-ignore".to_string()));
        assert!(calls[1].iter().any(|a| a == "--ignore-file-errors=true"));
        let manifest_call = calls.last().unwrap();
        assert!(manifest_call.contains(&"moss-source:manifest".to_string()));
        assert!(manifest_call.iter().any(|a| a == "moss-run:01TEST"));
    }

    /// Kopia exits 1 on a fatal error but still prints the manifest; the run
    /// is incomplete (exit 9 in the CLI), never an error, and the failing path
    /// is folded into `skipped`.
    #[test]
    fn fatal_error_is_partial_not_failed() {
        let (outcome, _, _tmp) = run_with("snapshot-create-fatal.json", 1);
        assert!(!outcome.complete);
        assert_eq!(outcome.unexpected_errors, 1);
        assert_eq!(outcome.snapshots[0].fatal_errors, 1);
        assert_eq!(outcome.skipped.len(), 1);
        assert_eq!(outcome.skipped[0].path, "~/src/noperm");
        assert_eq!(outcome.skipped[0].reason, SkipReason::BackupError);
        assert!(
            outcome.skipped[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("permission denied")
        );
        // The manifest on disk carries the same skipped entry.
        let written = Manifest::read(&outcome.manifest_path).unwrap();
        assert_eq!(written.skipped.len(), 1);
        assert_eq!(written.sources[0].fatal_errors, 1);
        assert!(written.sources[0].snapshot_id.is_some());
    }

    /// Ignored errors exit 0 in Kopia but still count against completeness.
    #[test]
    fn ignored_errors_are_counted() {
        let (outcome, _, _tmp) = run_with("snapshot-create-ignored-errors.json", 0);
        assert!(!outcome.complete);
        assert_eq!(outcome.snapshots[0].ignored_errors, 1);
        assert_eq!(outcome.skipped.len(), 1);
    }
}
