//! Restore (spec §15–§17): two-stage — Kopia restores into a moss-owned
//! staging directory, then moss places each entry with containment, conflict
//! handling and a journal.

pub mod conflict;
pub mod contain;
pub mod journal;
pub mod place;
pub mod report;
pub mod select;
pub mod stage;
pub mod translate;

#[cfg(test)]
pub(crate) mod test_support {
    use crate::backup::manifest::{Manifest, ManifestSource, SkipReason, Skipped, Totals};
    use crate::model::{Portability, ProfileCategory, SemanticId};
    use crate::platform::Platform;

    pub fn source(id: &str, category: ProfileCategory, path: &str) -> ManifestSource {
        ManifestSource {
            id: SemanticId::new(id),
            category,
            portable: Portability::Portable,
            path: path.into(),
            sensitive: category == ProfileCategory::Credentials,
            size: 10,
            files: 2,
            snapshot_id: Some(format!("snap-{id}")),
            fatal_errors: 0,
            ignored_errors: 0,
        }
    }

    pub fn sample_manifest() -> Manifest {
        Manifest {
            schema_version: 1,
            run_id: "01TEST".into(),
            profile: "default".into(),
            profile_identity: "rhys".into(),
            source_os: Platform::MacOs,
            source_host: "macbook".into(),
            source_user: "rhys".into(),
            source_home: "/Users/rhys".into(),
            tool_version: "0.1.0".into(),
            kopia_version: "0.23.1".into(),
            created_at: chrono::Utc::now(),
            categories: vec![ProfileCategory::Credentials, ProfileCategory::PersonalData],
            sources: vec![
                source("ssh", ProfileCategory::Credentials, "~/.ssh"),
                source("documents", ProfileCategory::PersonalData, "~/Documents"),
            ],
            skipped: vec![Skipped {
                path: "~/Library/Mail".into(),
                reason: SkipReason::PermissionDenied,
                errno: Some("EPERM".into()),
                detail: None,
            }],
            collisions: vec![],
            sensitive_counts: vec![],
            totals: Totals::default(),
        }
    }
}
