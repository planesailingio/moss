//! Stage one: Kopia restores into a moss-owned staging directory under the
//! state directory (spec §16). The manifest is fetched and validated first;
//! sources are staged one at a time to bound the temporary disk cost.

use std::path::{Path, PathBuf};

use crate::backup::manifest::{MANIFEST_FILE_NAME, Manifest, ManifestSource};
use crate::backup::repository::Repository;
use crate::config::MossPaths;
use crate::error::{MossError, Result};
use crate::restore::select::Run;

/// The staging area for one run: `<state>/staging/<run id>`.
pub struct Staging {
    root: PathBuf,
}

/// A filename-safe form of a run or source id (`custom:a/b` → `custom_a_b`).
pub fn sanitise_id(id: &str) -> String {
    let mut out: String = id
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '.' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() || out.starts_with('.') {
        out.insert(0, '_');
    }
    out
}

impl Staging {
    pub fn create(paths: &MossPaths, run_id: &str) -> Result<Staging> {
        let root = paths.staging_dir().join(sanitise_id(run_id));
        crate::config::paths::create_private_dir(&root)?;
        Ok(Staging { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn target_for(&self, name: &str) -> PathBuf {
        self.root.join(sanitise_id(name))
    }

    /// Fetch the run's manifest snapshot and parse it. The manifest is
    /// attacker-influenceable (spec §4): schema and run identity are checked
    /// here, every path in it is checked by containment later.
    pub fn fetch_manifest(&self, repo: &Repository, run: &Run) -> Result<Manifest> {
        let snapshot_id = run.manifest_snapshot.as_deref().ok_or_else(|| {
            MossError::Integrity(format!(
                "Snapshot {} has no manifest, so moss cannot map its sources onto this machine.\n\nIt may have been made by an interrupted backup or a different tool. Choose another snapshot with `moss snapshots`.",
                run.id
            ))
        })?;
        let target = self.target_for("manifest");
        remove_stale(&target)?;
        repo.snapshot_restore(snapshot_id, &target, true)?;
        let file = if target.is_file() {
            target.clone()
        } else {
            let primary = target.join(MANIFEST_FILE_NAME);
            if primary.is_file() {
                primary
            } else {
                // Tolerate a manifests directory holding `<run>.json`.
                let alt = target.join(format!("{}.json", run.id));
                if alt.is_file() {
                    alt
                } else {
                    return Err(MossError::Integrity(format!(
                        "The manifest snapshot for {} does not contain {MANIFEST_FILE_NAME}.",
                        run.id
                    )));
                }
            }
        };
        let manifest = Manifest::read(&file)?;
        validate_manifest(&manifest, run)?;
        Ok(manifest)
    }

    /// Restore one source into `<staging>/<sanitised id>` and return that path
    /// (a directory or a single file, whichever the snapshot root is).
    pub fn stage_source(
        &self,
        repo: &Repository,
        source: &ManifestSource,
        skip_owners: bool,
    ) -> Result<PathBuf> {
        let snapshot_id = source.snapshot_id.as_deref().ok_or_else(|| {
            MossError::Integrity(format!(
                "The manifest lists {} without a snapshot id; that source was not backed up.",
                source.id
            ))
        })?;
        let target = self.target_for(source.id.as_str());
        remove_stale(&target)?;
        repo.snapshot_restore(snapshot_id, &target, skip_owners)?;
        if std::fs::symlink_metadata(&target).is_err() {
            return Err(MossError::Integrity(format!(
                "Kopia reported success restoring {} but nothing arrived in staging ({}).",
                source.id,
                target.display()
            )));
        }
        Ok(target)
    }

    /// Delete one staged source once it has been placed.
    pub fn discard(&self, staged: &Path) {
        if staged.starts_with(&self.root) {
            let _ = remove_stale(staged);
        }
    }

    /// Remove the whole staging area after a clean run.
    pub fn finish(self) -> Result<()> {
        remove_stale(&self.root)?;
        let _ = std::fs::remove_dir(self.root.parent().unwrap_or(&self.root));
        Ok(())
    }

    /// Keep the staging area (after a failure) and hand back its path.
    pub fn keep(self) -> PathBuf {
        self.root
    }
}

fn remove_stale(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(path)?,
        Ok(_) => std::fs::remove_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Cross-check the manifest against the Kopia run it came with.
pub fn validate_manifest(manifest: &Manifest, run: &Run) -> Result<()> {
    if manifest.run_id != run.id {
        return Err(MossError::Integrity(format!(
            "The manifest inside snapshot {} says it belongs to run {}. The snapshot may have been tampered with; not restoring.",
            run.id, manifest.run_id
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for s in &manifest.sources {
        if !seen.insert(s.id.as_str()) {
            return Err(MossError::Integrity(format!(
                "The manifest lists source {} twice.",
                s.id
            )));
        }
        if let Some(id) = &s.snapshot_id
            && run.snapshot_by_id(id).is_none()
        {
            return Err(MossError::Integrity(format!(
                "The manifest points source {} at snapshot {id}, which is not part of run {}. Not restoring.",
                s.id, run.id
            )));
        }
    }
    Ok(())
}

/// The selection of manifest sources to restore.
pub fn select_sources<'a>(
    manifest: &'a Manifest,
    categories: &[crate::profile::model::ProfileCategory],
    ids: &[String],
) -> Result<Vec<&'a ManifestSource>> {
    let selected: Vec<&ManifestSource> = manifest
        .sources
        .iter()
        .filter(|s| categories.is_empty() || categories.contains(&s.category))
        .filter(|s| ids.is_empty() || ids.iter().any(|i| i == s.id.as_str()))
        .collect();
    if selected.is_empty() {
        let available = manifest
            .sources
            .iter()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(MossError::Usage(format!(
            "Nothing in snapshot {} matches the selection.\n\nSources in this snapshot: {available}",
            manifest.run_id
        )));
    }
    for id in ids {
        if !manifest.sources.iter().any(|s| s.id.as_str() == id) {
            return Err(MossError::Usage(format!(
                "Source {id:?} is not in snapshot {}.\n\nSources in this snapshot: {}",
                manifest.run_id,
                manifest
                    .sources
                    .iter()
                    .map(|s| s.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::model::ProfileCategory;
    use crate::restore::test_support::sample_manifest;

    fn run_for(manifest: &Manifest) -> Run {
        let members = manifest
            .sources
            .iter()
            .map(|s| {
                serde_json::from_value(serde_json::json!({
                    "id": s.snapshot_id,
                    "tags": {"tag:moss-run": manifest.run_id, "tag:moss-source": s.id.as_str()},
                    "rootEntry": {"summ": {"numFailed": 0}}
                }))
                .unwrap()
            })
            .collect();
        Run {
            id: manifest.run_id.clone(),
            started: None,
            host: "macbook".into(),
            user: "rhys".into(),
            os: Some(crate::platform::Platform::MacOs),
            profile: None,
            members,
            manifest_snapshot: Some("m".into()),
            fatal_errors: 0,
            ignored_errors: 0,
            missing_counts: false,
            incomplete: false,
        }
    }

    #[test]
    fn sanitised_ids_are_filenames() {
        assert_eq!(sanitise_id("custom:Projects/a b"), "custom_Projects_a_b");
        assert_eq!(sanitise_id("ssh"), "ssh");
        assert_eq!(sanitise_id(".."), "_..");
        assert_eq!(sanitise_id(""), "_");
    }

    #[test]
    fn manifest_validation() {
        let m = sample_manifest();
        let run = run_for(&m);
        validate_manifest(&m, &run).unwrap();
        let mut wrong_run = m.clone();
        wrong_run.run_id = "OTHER".into();
        assert_eq!(
            validate_manifest(&wrong_run, &run)
                .unwrap_err()
                .exit_code()
                .code(),
            8
        );
        let mut foreign = m.clone();
        foreign.sources[0].snapshot_id = Some("not-in-run".into());
        assert!(validate_manifest(&foreign, &run).is_err());
        let mut dup = m.clone();
        dup.sources.push(dup.sources[0].clone());
        assert!(validate_manifest(&dup, &run).is_err());
    }

    #[test]
    fn source_selection() {
        let m = sample_manifest();
        assert_eq!(select_sources(&m, &[], &[]).unwrap().len(), 2);
        let creds = select_sources(&m, &[ProfileCategory::Credentials], &[]).unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].id.as_str(), "ssh");
        let docs = select_sources(&m, &[], &["documents".to_string()]).unwrap();
        assert_eq!(docs[0].id.as_str(), "documents");
        assert!(select_sources(&m, &[], &["nope".to_string()]).is_err());
        assert!(select_sources(&m, &[ProfileCategory::Cache], &[]).is_err());
    }

    #[test]
    fn staging_layout_and_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = MossPaths {
            config_dir: tmp.path().join("config"),
            state_dir: tmp.path().join("state"),
            cache_dir: tmp.path().join("cache"),
        };
        let staging = Staging::create(&paths, "01TEST").unwrap();
        assert_eq!(staging.root(), tmp.path().join("state/staging/01TEST"));
        assert!(crate::config::paths::mode_is_private(staging.root(), 0o700).unwrap());
        let staged = staging.target_for("custom:a/b");
        std::fs::create_dir_all(&staged).unwrap();
        std::fs::write(staged.join("x"), b"1").unwrap();
        staging.discard(&staged);
        assert!(!staged.exists());
        let root = staging.root().to_path_buf();
        staging.finish().unwrap();
        assert!(!root.exists());
    }
}
