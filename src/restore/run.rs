//! The restore run (spec §15–§18): journal recovery, then for each selected
//! source, plan, stage, place, report. Kopia is behind [`Stager`] and the
//! destination mapping behind [`PlatformAdapter`], so the whole sequence runs
//! under `cargo test` with a fixture tree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::backup::manifest::{Manifest, ManifestSource};
use crate::config::ConflictPolicy;
use crate::error::{ExitCode, MossError, Result};
use crate::model::Platform;
use crate::output::{Console, prompt_line};
use crate::platform::PlatformAdapter;
use crate::profile::locations;
use crate::restore::conflict::Resolver;
use crate::restore::contain::Root;
use crate::restore::journal::{self, Journal, ResumeState};
use crate::restore::place::{PlaceContext, check_collisions, place_source};
use crate::restore::plan::{SourcePlan, plan_source};
use crate::restore::report::{RestoreReport, SourceReport};
use crate::restore::stage::Stager;
use crate::restore::translate::{Origin, scan_restored};
use crate::scan::collisions::probe_insensitive;

/// What the journal said about an earlier, interrupted restore.
#[derive(Debug)]
pub enum Recovery {
    /// Nothing pending; restore proceeds normally.
    Clean,
    /// The user chose (by flag or prompt) to continue the interrupted run.
    Resume { run_id: String, state: ResumeState },
    /// The interrupted run was rolled back; the command is finished.
    RolledBack {
        run_id: String,
        summary: journal::RollbackSummary,
    },
    /// The user declined both options.
    Aborted,
}

/// Inspect the journal and settle an interrupted restore (spec §18). A
/// damaged journal is an error: `--resume` and `--rollback` never guess.
pub fn recover_journal(
    journal_path: &Path,
    resume: bool,
    rollback: bool,
    console: &Console,
) -> Result<Recovery> {
    let records = journal::load(journal_path)?;
    let Some(inc) = journal::incomplete(&records) else {
        return Ok(Recovery::Clean);
    };
    let describe = journal::describe_pending(&inc);
    let do_rollback = |inc: &journal::Incomplete| -> Result<Recovery> {
        let summary = journal::rollback(inc);
        journal::remove(journal_path)?;
        Ok(Recovery::RolledBack {
            run_id: inc.run_id.clone(),
            summary,
        })
    };
    if rollback {
        return do_rollback(&inc);
    }
    if resume {
        return Ok(Recovery::Resume {
            run_id: inc.run_id.clone(),
            state: ResumeState::from_incomplete(&inc),
        });
    }
    if !console.can_prompt() {
        return Err(MossError::InteractionRequired(format!(
            "An earlier restore was interrupted.\n\n{describe}\n\nRe-run with --resume to continue it or --rollback to undo it."
        )));
    }
    console.line(format!(
        "An earlier restore was interrupted.\n\n{describe}\n"
    ));
    let answer = prompt_line(console, "[r] Resume it   [b] Roll it back   [a] Abort:")?;
    match answer.to_ascii_lowercase().as_str() {
        "r" | "resume" => Ok(Recovery::Resume {
            run_id: inc.run_id.clone(),
            state: ResumeState::from_incomplete(&inc),
        }),
        "b" | "rollback" => do_rollback(&inc),
        _ => Ok(Recovery::Aborted),
    }
}

/// Everything a restore run needs that the CLI decided.
pub struct Request<'a> {
    pub run_id: &'a str,
    pub manifest: &'a Manifest,
    pub sources: Vec<&'a ManifestSource>,
    pub policy: ConflictPolicy,
    pub rename_collisions: bool,
    pub keep_owners: bool,
    pub root_override: Option<PathBuf>,
    pub dry_run: bool,
    pub resume: Option<ResumeState>,
    pub journal_path: &'a Path,
}

/// Run the restore. Staging is consumed: finished on success, kept (and named
/// in the report) when a source failed or an interactive conflict needs a
/// terminal that is not there.
pub fn execute(
    req: Request<'_>,
    stager: Box<dyn Stager + '_>,
    adapter: &dyn PlatformAdapter,
    console: &Console,
) -> Result<RestoreReport> {
    let dest_home = adapter.home().to_path_buf();
    let dest_os = adapter.platform();
    let manifest = req.manifest;
    let origin = Origin {
        home: manifest.source_home.clone(),
        user: manifest.source_user.clone(),
    };
    let mut report = RestoreReport::new(
        req.run_id,
        &manifest.source_host,
        manifest.source_os,
        dest_os,
        req.root_override.as_deref().unwrap_or(&dest_home),
        req.dry_run,
    );
    report.resumed = req.resume.is_some();

    let mut resolver = Resolver::new(req.policy, console);
    let mut journal = Journal::open(req.journal_path)?;
    let mut restored_files: Vec<PathBuf> = Vec::new();
    let mut had_failure = false;
    let default_probe = (
        dest_os.default_fs_case_insensitive(),
        dest_os == Platform::MacOs,
    );

    for source in &req.sources {
        let dest_abs = locations::destination_for(adapter, &source.id);
        let (root_path, dest_rel, display) = match plan_source(
            source,
            dest_abs.as_deref(),
            &dest_home,
            req.root_override.as_deref(),
        ) {
            SourcePlan::Skip {
                destination,
                reason,
            } => {
                report.push_source(SourceReport::skipped(source, destination, reason));
                continue;
            }
            SourcePlan::Place {
                root,
                dest_rel,
                display,
            } => (root, dest_rel, display),
        };

        // Collisions recorded at backup time vs. this filesystem (spec §12).
        // The probe writes marker files, so a dry run uses the platform
        // default and touches nothing.
        let probe = if req.dry_run {
            default_probe
        } else {
            prepare_root(&root_path, req.root_override.is_some())?;
            probe_insensitive(&root_path).unwrap_or(default_probe)
        };
        let check = check_collisions(manifest, source, probe, req.rename_collisions);
        if !check.blocked.is_empty() {
            report.collisions.extend(check.blocked);
            report.push_source(SourceReport::failed(
                source,
                display,
                "recorded name collisions would be lost on this filesystem; use --rename-collisions",
            ));
            had_failure = true;
            continue;
        }

        if req.dry_run {
            let exists = Root::open(&root_path)
                .ok()
                .and_then(|root| root.exists(&dest_rel).ok().flatten())
                .is_some();
            let note = exists.then(|| {
                format!("destination exists; conflict policy: {:?}", req.policy).to_lowercase()
            });
            report.push_source(SourceReport::planned(source, display, note));
            continue;
        }

        // Stage through Kopia, then place with containment (spec §16).
        console.line(format!("  {:<24} → {display}", source.id));
        let staged = match stager.stage_source(source, !req.keep_owners) {
            Ok(p) => p,
            Err(e) => {
                report.push_source(SourceReport::failed(source, display, first_line(&e)));
                had_failure = true;
                continue;
            }
        };
        let root = Root::open(&root_path)?;
        let renames: BTreeMap<String, String> = check.renames;
        let mut pctx = PlaceContext {
            run_id: req.run_id,
            source_id: source.id.as_str(),
            source_path: &source.path,
            source_os: manifest.source_os,
            dest_os,
            dest_home: &dest_home,
            resolver: &mut resolver,
            journal: &mut journal,
            resume: req.resume.as_ref(),
            renames: &renames,
        };
        let outcome = match place_source(&root, &staged, &dest_rel, &mut pctx) {
            Ok(o) => o,
            Err(e @ MossError::InteractionRequired(_)) => {
                report.journal = Some(req.journal_path.display().to_string());
                report.staging_kept = Some(stager.keep().display().to_string());
                return Err(e);
            }
            Err(e) => {
                had_failure = true;
                report.push_source(SourceReport::failed(source, display, first_line(&e)));
                continue;
            }
        };
        stager.discard(&staged);
        report.skipped.extend(outcome.skipped.iter().cloned());
        report.renames.extend(outcome.renamed.iter().cloned());
        restored_files.extend(outcome.restored_files.iter().cloned());
        report.push_source(SourceReport::from_outcome(source, display, &outcome));
    }

    // Embedded absolute paths that will not resolve here (spec §15).
    if !req.dry_run {
        report.path_findings = scan_restored(&restored_files, &dest_home, &origin, dest_os);
    }

    let code = report.exit_code();
    if req.dry_run || (!had_failure && code != ExitCode::RestoreConflict) {
        journal.finish()?;
        stager.finish()?;
    } else {
        report.journal = Some(req.journal_path.display().to_string());
        report.staging_kept = Some(stager.keep().display().to_string());
    }
    Ok(report)
}

fn first_line(e: &MossError) -> String {
    e.to_string().lines().next().unwrap_or("").to_string()
}

/// Make sure the containment root exists without touching its permissions.
/// A `--to` directory is created (plain `mkdir -p`, the user's umask applies);
/// the home directory, or a parent of a redirected destination, must already
/// exist. Restore never changes the mode of a directory it did not create.
fn prepare_root(root_path: &Path, is_override: bool) -> Result<()> {
    if root_path.is_dir() {
        return Ok(());
    }
    if is_override {
        std::fs::create_dir_all(root_path)?;
        return Ok(());
    }
    Err(MossError::Usage(format!(
        "destination directory {} does not exist; create it first or restore with --to",
        root_path.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::manifest::Manifest;
    use crate::model::ProfileCategory;
    use crate::platform::macos::MacOsAdapter;
    use crate::restore::report::SourceStatus;
    use crate::restore::select::Run;
    use crate::restore::test_support::{sample_manifest, source};
    use std::cell::RefCell;

    /// Copies fixture trees into a staging directory instead of calling Kopia.
    struct FakeStager {
        staging: PathBuf,
        fixtures: BTreeMap<String, PathBuf>,
        fail: Vec<String>,
        discarded: RefCell<Vec<PathBuf>>,
    }

    impl Stager for FakeStager {
        fn fetch_manifest(&self, _run: &Run) -> Result<Manifest> {
            unreachable!("the test hands the manifest in directly")
        }

        fn stage_source(&self, source: &ManifestSource, _skip_owners: bool) -> Result<PathBuf> {
            if self.fail.iter().any(|f| f == source.id.as_str()) {
                return Err(MossError::Kopia {
                    message: format!("kopia could not restore {}", source.id),
                    detail: String::new(),
                });
            }
            let from = &self.fixtures[source.id.as_str()];
            let to = self.staging.join(source.id.as_str());
            copy_tree(from, &to);
            Ok(to)
        }

        fn discard(&self, staged: &Path) {
            self.discarded.borrow_mut().push(staged.to_path_buf());
            let _ = std::fs::remove_dir_all(staged);
        }

        fn finish(self: Box<Self>) -> Result<()> {
            std::fs::remove_dir_all(&self.staging)?;
            Ok(())
        }

        fn keep(self: Box<Self>) -> PathBuf {
            self.staging
        }
    }

    fn copy_tree(from: &Path, to: &Path) {
        if from.is_dir() {
            std::fs::create_dir_all(to).unwrap();
            for e in std::fs::read_dir(from).unwrap().flatten() {
                copy_tree(&e.path(), &to.join(e.file_name()));
            }
        } else {
            std::fs::copy(from, to).unwrap();
        }
    }

    struct Fx {
        tmp: tempfile::TempDir,
        home: PathBuf,
        manifest: Manifest,
        journal: PathBuf,
    }

    fn fixture() -> Fx {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let fx_root = tmp.path().join("fixtures");
        std::fs::create_dir_all(fx_root.join("ssh")).unwrap();
        std::fs::write(fx_root.join("ssh/config"), "Host x\n").unwrap();
        std::fs::write(fx_root.join("ssh/id_ed25519"), "key").unwrap();
        std::fs::create_dir_all(fx_root.join("documents/notes")).unwrap();
        std::fs::write(fx_root.join("documents/notes/a.txt"), "hello").unwrap();
        let mut manifest = sample_manifest();
        manifest.sources.push(source(
            "mystery_tool",
            ProfileCategory::Development,
            "~/.mystery",
        ));
        Fx {
            journal: tmp.path().join("state/restore-journal.json"),
            tmp,
            home,
            manifest,
        }
    }

    fn stager(fx: &Fx, fail: &[&str]) -> Box<dyn Stager> {
        let staging = fx.tmp.path().join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let fx_root = fx.tmp.path().join("fixtures");
        Box::new(FakeStager {
            staging,
            fixtures: BTreeMap::from([
                ("ssh".to_string(), fx_root.join("ssh")),
                ("documents".to_string(), fx_root.join("documents")),
            ]),
            fail: fail.iter().map(|s| s.to_string()).collect(),
            discarded: RefCell::new(Vec::new()),
        })
    }

    fn request<'a>(fx: &'a Fx, dry_run: bool, to: Option<PathBuf>) -> Request<'a> {
        Request {
            run_id: "01TEST",
            manifest: &fx.manifest,
            sources: fx.manifest.sources.iter().collect(),
            policy: ConflictPolicy::Skip,
            rename_collisions: false,
            keep_owners: false,
            root_override: to,
            dry_run,
            resume: None,
            journal_path: &fx.journal,
        }
    }

    #[test]
    fn places_into_home_and_skips_unmapped_ids() {
        let fx = fixture();
        let adapter = MacOsAdapter::with_home(fx.home.clone());
        let console = Console::for_tests();
        let report = execute(
            request(&fx, false, None),
            stager(&fx, &[]),
            &adapter,
            &console,
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(fx.home.join(".ssh/config")).unwrap(),
            "Host x\n"
        );
        assert_eq!(
            std::fs::read_to_string(fx.home.join("Documents/notes/a.txt")).unwrap(),
            "hello"
        );
        let by_id = |id: &str| report.sources.iter().find(|s| s.id == id).unwrap();
        assert_eq!(by_id("ssh").status, SourceStatus::Restored);
        assert_eq!(by_id("ssh").placed, 2);
        assert_eq!(by_id("documents").destination, "~/Documents");
        let mystery = by_id("mystery_tool");
        assert_eq!(mystery.status, SourceStatus::Skipped);
        assert!(mystery.reason.as_deref().unwrap().contains("no location"));
        // An unmapped id is a skip, so the run is partial (exit 9), and the
        // journal and staging are cleaned up because nothing *failed*.
        assert_eq!(report.exit_code(), ExitCode::PartialSuccess);
        assert!(!fx.journal.exists());
        assert!(!fx.tmp.path().join("staging").exists());
    }

    #[test]
    fn dry_run_writes_nothing_and_plans_everything() {
        let fx = fixture();
        let adapter = MacOsAdapter::with_home(fx.home.clone());
        let console = Console::for_tests();
        let to = fx.tmp.path().join("planned");
        let report = execute(
            request(&fx, true, Some(to.clone())),
            stager(&fx, &[]),
            &adapter,
            &console,
        )
        .unwrap();
        assert!(!to.exists(), "dry run must not create --to");
        assert!(!fx.home.join(".ssh").exists());
        assert!(
            report
                .sources
                .iter()
                .filter(|s| s.status == SourceStatus::Planned)
                .count()
                == 2
        );
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert_eq!(report.destination_root, to.display().to_string());
    }

    #[test]
    fn to_override_creates_root_without_touching_home_mode() {
        let fx = fixture();
        let adapter = MacOsAdapter::with_home(fx.home.clone());
        let console = Console::for_tests();
        #[cfg(unix)]
        let before = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fx.home, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::metadata(&fx.home).unwrap().permissions().mode() & 0o777
        };
        let to = fx.tmp.path().join("out");
        let report = execute(
            request(&fx, false, Some(to.clone())),
            stager(&fx, &[]),
            &adapter,
            &console,
        )
        .unwrap();
        assert!(to.join(".ssh/config").is_file());
        assert!(
            !fx.home.join(".ssh").exists(),
            "nothing lands in home under --to"
        );
        assert_eq!(
            report
                .sources
                .iter()
                .find(|s| s.id == "ssh")
                .unwrap()
                .destination,
            to.join(".ssh").display().to_string()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&fx.home).unwrap().permissions().mode() & 0o777,
                before
            );
        }
    }

    #[test]
    fn staging_failure_keeps_journal_and_staging_and_exits_9() {
        let fx = fixture();
        let adapter = MacOsAdapter::with_home(fx.home.clone());
        let console = Console::for_tests();
        let report = execute(
            request(&fx, false, None),
            stager(&fx, &["documents"]),
            &adapter,
            &console,
        )
        .unwrap();
        let docs = report.sources.iter().find(|s| s.id == "documents").unwrap();
        assert_eq!(docs.status, SourceStatus::Failed);
        assert!(
            docs.reason
                .as_deref()
                .unwrap()
                .contains("kopia could not restore")
        );
        assert_eq!(report.exit_code(), ExitCode::PartialSuccess);
        assert!(report.journal.is_some() && report.staging_kept.is_some());
        assert!(
            fx.home.join(".ssh/config").is_file(),
            "other sources still restored"
        );
    }

    #[test]
    fn journal_recovery_flags() {
        let fx = fixture();
        let console = Console::for_tests();
        assert!(matches!(
            recover_journal(&fx.journal, false, false, &console).unwrap(),
            Recovery::Clean
        ));
        // Leave an intention pending, as a crash would.
        std::fs::create_dir_all(fx.home.join(".ssh")).unwrap();
        let half = fx.home.join(".ssh/half");
        std::fs::write(&half, b"partial").unwrap();
        let mut j = Journal::open(&fx.journal).unwrap();
        j.intend("01OLD", "ssh", &half, journal::Action::Write, None, None)
            .unwrap();
        drop(j);
        // Neither flag, no terminal: exit 13 with instructions.
        let err = recover_journal(&fx.journal, false, false, &console).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::InteractionRequired);
        assert!(err.to_string().contains("--rollback"));
        // --resume hands back the state and the run to continue.
        match recover_journal(&fx.journal, true, false, &console).unwrap() {
            Recovery::Resume { run_id, state } => {
                assert_eq!(run_id, "01OLD");
                assert!(state.is_pending(&half));
            }
            _ => panic!("expected resume"),
        }
        // --rollback removes the half-written file and the journal.
        match recover_journal(&fx.journal, false, true, &console).unwrap() {
            Recovery::RolledBack { run_id, summary } => {
                assert_eq!(run_id, "01OLD");
                assert_eq!(summary.removed.len(), 1);
                assert!(summary.failed.is_empty());
            }
            _ => panic!("expected rollback"),
        }
        assert!(!half.exists());
        assert!(!fx.journal.exists());
    }
}
