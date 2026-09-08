//! `moss restore` (spec §15–§18, §29): select a run, stage it through Kopia,
//! place it with containment, journal every write, report untranslatable paths.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::Args;

use crate::cli::AppContext;
use crate::config::ConflictPolicy;
use crate::error::{ExitCode, MossError, Result};
use crate::lock::Lock;
use crate::model::{ProfileCategory, home_relative};
use crate::output::prompt_line;
use crate::profile::locations;
use crate::restore::conflict::Resolver;
use crate::restore::contain::Root;
use crate::restore::journal::{self, Journal, ResumeState};
use crate::restore::place::{PlaceContext, check_collisions, place_source};
use crate::restore::report::{RestoreReport, SourceReport, SourceStatus};
use crate::restore::select::{list_runs, select_run};
use crate::restore::stage::{Staging, select_sources, validate_manifest};
use crate::restore::translate::{Origin, scan_restored};
use crate::scan::collisions::probe_insensitive;

#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// `latest` or a snapshot id prefix from `moss snapshots`.
    #[arg(default_value = "latest")]
    pub selector: String,
    /// Only consider snapshots made on this host.
    #[arg(long, value_name = "HOST")]
    pub from_host: Option<String>,
    /// Restore only these categories (repeatable): credentials, configuration, personal, …
    #[arg(long, value_parser = crate::cli::misc::parse_category)]
    pub category: Vec<ProfileCategory>,
    /// Restore only these semantic sources (repeatable): ssh, documents, custom:Projects, …
    #[arg(long, value_name = "ID")]
    pub source: Vec<String>,
    /// What to do when a destination file exists (default from config; interactive on a TTY).
    #[arg(long, value_enum)]
    pub conflict: Option<ConflictPolicy>,
    /// Rename recorded case/normalization collisions (name.1, name.2) instead of failing.
    #[arg(long)]
    pub rename_collisions: bool,
    /// Restore under this directory instead of the profile (explicit intent to restore outside it).
    #[arg(long, value_name = "DIR")]
    pub to: Option<PathBuf>,
    /// Continue an interrupted restore recorded in the journal.
    #[arg(long)]
    pub resume: bool,
    /// Undo an interrupted restore: remove pending files, put backups back.
    #[arg(long)]
    pub rollback: bool,
    /// Ask Kopia to restore file ownership (default: skip, current user owns everything).
    #[arg(long)]
    pub keep_owners: bool,
}

pub fn run(ctx: &AppContext, args: RestoreArgs) -> Result<ExitCode> {
    let console = ctx.console;
    if args.resume && args.rollback {
        return Err(MossError::Usage(
            "--resume and --rollback are mutually exclusive".into(),
        ));
    }
    let _lock = Lock::acquire(&ctx.paths.lock_file())?;
    let connected = ctx.connect()?;
    let repo = connected.repository();
    let adapter = ctx.adapter();
    let dest_home = adapter.home().to_path_buf();
    let dest_os = adapter.platform();

    // Interrupted restore? (spec §18)
    let journal_path = ctx.paths.restore_journal();
    let mut resume_state: Option<ResumeState> = None;
    let mut selector = args.selector.clone();
    // A journal that cannot be read describes an interrupted restore in an
    // unknown state; refuse rather than guess (spec §18).
    let records = journal::load(&journal_path)?;
    if let Some(inc) = journal::incomplete(&records) {
        let describe = journal::describe_pending(&inc);
        if args.rollback {
            let summary = journal::rollback(&inc);
            journal::remove(&journal_path)?;
            if console.json {
                console.json_report(&serde_json::json!({
                    "rolled_back": true,
                    "removed": summary.removed,
                    "restored_backups": summary.restored_backups,
                    "failed": summary.failed,
                }))?;
            } else {
                println!(
                    "Rolled back the interrupted restore of {}: {} file(s) removed, {} backup(s) restored{}.",
                    inc.run_id,
                    summary.removed.len(),
                    summary.restored_backups.len(),
                    if summary.failed.is_empty() {
                        String::new()
                    } else {
                        format!(", {} failed", summary.failed.len())
                    }
                );
            }
            return Ok(if summary.failed.is_empty() {
                ExitCode::Success
            } else {
                ExitCode::General
            });
        }
        let resume = if args.resume {
            true
        } else if console.can_prompt() {
            console.line(format!(
                "An earlier restore was interrupted.\n\n{describe}\n"
            ));
            let answer = prompt_line(&console, "[r] Resume it   [b] Roll it back   [a] Abort:")?;
            match answer.to_ascii_lowercase().as_str() {
                "r" | "resume" => true,
                "b" | "rollback" => {
                    let summary = journal::rollback(&inc);
                    journal::remove(&journal_path)?;
                    console.line(format!(
                        "Rolled back: {} removed, {} backups restored.",
                        summary.removed.len(),
                        summary.restored_backups.len()
                    ));
                    return Ok(ExitCode::Success);
                }
                _ => return Ok(ExitCode::General),
            }
        } else {
            return Err(MossError::InteractionRequired(format!(
                "An earlier restore was interrupted.\n\n{describe}\n\nRe-run with --resume to continue it or --rollback to undo it."
            )));
        };
        if resume {
            if selector.eq_ignore_ascii_case("latest") {
                selector = inc.run_id.clone();
            }
            resume_state = Some(ResumeState::from_incomplete(&inc));
        }
    }

    // Select the run and fetch its manifest first (spec §27).
    let runs = list_runs(&repo)?;
    let run = select_run(&runs, &selector, args.from_host.as_deref())?;
    let staging = Staging::create(&ctx.paths, &run.id)?;
    let manifest = match staging.fetch_manifest(&repo, run) {
        Ok(m) => m,
        Err(e) => {
            staging.keep();
            return Err(e);
        }
    };
    validate_manifest(&manifest, run)?;
    let sources = select_sources(&manifest, &args.category, &args.source)?;
    let policy = crate::cli::conflict_policy(args.conflict, &connected.config, &console);
    let origin = Origin {
        home: manifest.source_home.clone(),
        os: manifest.source_os,
        user: manifest.source_user.clone(),
    };

    let root_override = args.to.as_ref().map(|t| {
        if t.is_absolute() {
            t.clone()
        } else {
            std::env::current_dir()
                .map(|c| c.join(t))
                .unwrap_or_else(|_| t.clone())
        }
    });
    let mut report = RestoreReport::new(
        &run.id,
        &manifest.source_host,
        manifest.source_os,
        dest_os,
        root_override.as_deref().unwrap_or(&dest_home),
        ctx.global.dry_run,
    );
    report.resumed = resume_state.is_some();

    console.line(format!(
        "{} snapshot {} from {} ({}) made {} — {} source(s) onto {}",
        if ctx.global.dry_run {
            "Planning"
        } else {
            "Restoring"
        },
        run.id,
        manifest.source_host,
        manifest.source_os.display_name(),
        run.started_display(),
        sources.len(),
        root_override.as_deref().unwrap_or(&dest_home).display()
    ));

    let mut resolver = Resolver::new(policy, &console);
    let mut journal = Journal::open(&journal_path)?;
    let mut restored_files: Vec<PathBuf> = Vec::new();
    let mut had_failure = false;

    for source in &sources {
        let id = source.id.as_str();
        // Destination mapping through this platform's adapter (spec §15).
        let Some(dest_abs) = locations::destination_for(adapter, &source.id) else {
            report.push_source(SourceReport {
                id: id.into(),
                category: source.category,
                destination: "-".into(),
                status: SourceStatus::Skipped,
                placed: 0,
                skipped: 0,
                conflicts: Default::default(),
                size: source.size,
                reason: Some(format!("this platform has no location for {id}")),
            });
            continue;
        };
        let (root_path, dest_rel): (PathBuf, PathBuf) = match dest_abs.strip_prefix(&dest_home) {
            Ok(rel) => (
                root_override.clone().unwrap_or_else(|| dest_home.clone()),
                rel.to_path_buf(),
            ),
            Err(_) => {
                if source.category == ProfileCategory::Credentials || root_override.is_some() {
                    // Spec §16: credentials never land outside the profile;
                    // --to keeps everything under one root.
                    report.push_source(SourceReport {
                        id: id.into(),
                        category: source.category,
                        destination: dest_abs.display().to_string(),
                        status: SourceStatus::Skipped,
                        placed: 0,
                        skipped: 0,
                        conflicts: Default::default(),
                        size: source.size,
                        reason: Some("destination is outside the home directory".into()),
                    });
                    continue;
                }
                let parent = dest_abs
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| dest_abs.clone());
                let name = dest_abs.file_name().map(PathBuf::from).unwrap_or_default();
                (parent, name)
            }
        };
        let destination_display = if root_override.is_some() {
            root_path.join(&dest_rel).display().to_string()
        } else {
            home_relative(&root_path.join(&dest_rel), &dest_home)
        };

        // Collisions recorded at backup time vs. this filesystem (spec §12).
        // The probe writes marker files, so a dry run uses the platform default
        // and touches nothing.
        let default_probe = (
            dest_os.default_fs_case_insensitive(),
            dest_os == crate::platform::Platform::MacOs,
        );
        let probe = if ctx.global.dry_run {
            default_probe
        } else {
            prepare_root(&root_path, root_override.is_some())?;
            probe_insensitive(&root_path).unwrap_or(default_probe)
        };
        let check = check_collisions(&manifest, source, probe, args.rename_collisions);
        if !check.blocked.is_empty() {
            report.collisions.extend(check.blocked);
            report.push_source(SourceReport {
                id: id.into(),
                category: source.category,
                destination: destination_display,
                status: SourceStatus::Failed,
                placed: 0,
                skipped: 0,
                conflicts: Default::default(),
                size: source.size,
                reason: Some("recorded name collisions would be lost on this filesystem; use --rename-collisions".into()),
            });
            had_failure = true;
            continue;
        }

        if ctx.global.dry_run {
            let exists = Root::open(&root_path)
                .ok()
                .and_then(|root| root.exists(&dest_rel).ok().flatten())
                .is_some();
            report.push_source(SourceReport {
                id: id.into(),
                category: source.category,
                destination: destination_display,
                status: SourceStatus::Planned,
                placed: source.files,
                skipped: 0,
                conflicts: Default::default(),
                size: source.size,
                reason: exists.then(|| {
                    format!("destination exists; conflict policy: {policy:?}").to_lowercase()
                }),
            });
            continue;
        }

        // Stage through Kopia, then place with containment (spec §16).
        console.line(format!("  {id:<24} → {destination_display}"));
        let staged = match staging.stage_source(&repo, source, !args.keep_owners) {
            Ok(p) => p,
            Err(e) => {
                report.push_source(SourceReport {
                    id: id.into(),
                    category: source.category,
                    destination: destination_display,
                    status: SourceStatus::Failed,
                    placed: 0,
                    skipped: 0,
                    conflicts: Default::default(),
                    size: source.size,
                    reason: Some(e.to_string().lines().next().unwrap_or("").to_string()),
                });
                had_failure = true;
                continue;
            }
        };
        let root = Root::open(&root_path)?;
        let renames: BTreeMap<String, String> = check.renames;
        let mut pctx = PlaceContext {
            run_id: &run.id,
            source_id: id,
            source_path: &source.path,
            source_os: manifest.source_os,
            dest_os,
            dest_home: &dest_home,
            resolver: &mut resolver,
            journal: &mut journal,
            resume: resume_state.as_ref(),
            renames: &renames,
        };
        let outcome = match place_source(&root, &staged, &dest_rel, &mut pctx) {
            Ok(o) => o,
            Err(e @ MossError::InteractionRequired(_)) => {
                report.journal = Some(journal_path.display().to_string());
                report.staging_kept = Some(staging.keep().display().to_string());
                return Err(e);
            }
            Err(e) => {
                had_failure = true;
                report.push_source(SourceReport {
                    id: id.into(),
                    category: source.category,
                    destination: destination_display,
                    status: SourceStatus::Failed,
                    placed: 0,
                    skipped: 0,
                    conflicts: Default::default(),
                    size: source.size,
                    reason: Some(e.to_string().lines().next().unwrap_or("").to_string()),
                });
                continue;
            }
        };
        staging.discard(&staged);
        let status = if outcome.skipped.is_empty() {
            SourceStatus::Restored
        } else {
            SourceStatus::Partial
        };
        report.skipped.extend(outcome.skipped.iter().cloned());
        report.renames.extend(outcome.renamed.iter().cloned());
        restored_files.extend(outcome.restored_files.iter().cloned());
        report.push_source(SourceReport {
            id: id.into(),
            category: source.category,
            destination: destination_display,
            status,
            placed: outcome.placed,
            skipped: outcome.skipped.len() as u64,
            conflicts: outcome.conflicts.clone(),
            size: source.size,
            reason: None,
        });
    }

    // Embedded absolute paths that will not resolve here (spec §15).
    if !ctx.global.dry_run {
        report.path_findings = scan_restored(&restored_files, &dest_home, &origin, dest_os);
    }

    let code = report.exit_code();
    if ctx.global.dry_run || (!had_failure && code != ExitCode::RestoreConflict) {
        journal.finish()?;
        staging.finish()?;
    } else {
        report.journal = Some(journal_path.display().to_string());
        report.staging_kept = Some(staging.keep().display().to_string());
    }

    if console.json {
        console.json_report(&report)?;
    } else {
        println!("{}", report.render_human(&console));
    }
    Ok(code)
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
