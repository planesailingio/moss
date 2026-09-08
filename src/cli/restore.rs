//! `moss restore` (spec §15–§18, §29): clap arguments, the connect path, and
//! rendering. The run itself is `restore::run::execute`, which is exercised
//! without Kopia in its own tests.

use std::path::PathBuf;

use clap::Args;

use crate::cli::{AppContext, reports};
use crate::config::ConflictPolicy;
use crate::error::{ExitCode, MossError, Result};
use crate::lock::Lock;
use crate::model::ProfileCategory;
use crate::restore::run::{self as restore_run, Recovery, Request};
use crate::restore::select::{list_runs, select_run};
use crate::restore::stage::{KopiaStager, Stager, select_sources, validate_manifest};

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
    let console = &ctx.console;
    if args.resume && args.rollback {
        return Err(MossError::Usage(
            "--resume and --rollback are mutually exclusive".into(),
        ));
    }
    let _lock = Lock::acquire(&ctx.paths.lock_file())?;
    let connected = ctx.connect()?;
    let repo = connected.repository();
    let adapter = ctx.adapter();

    // Interrupted restore? (spec §18)
    let journal_path = ctx.paths.restore_journal();
    let mut selector = args.selector.clone();
    let resume_state = match restore_run::recover_journal(
        &journal_path,
        args.resume,
        args.rollback,
        console,
    )? {
        Recovery::Clean => None,
        Recovery::Aborted => return Ok(ExitCode::General),
        Recovery::RolledBack { run_id, summary } => {
            if console.json {
                console.json_report(&reports::RollbackReport {
                    rolled_back: true,
                    removed: summary.removed.clone(),
                    restored_backups: summary.restored_backups.clone(),
                    failed: summary.failed.clone(),
                })?;
            } else {
                console.line(format!(
                    "Rolled back the interrupted restore of {run_id}: {} file(s) removed, {} backup(s) restored{}.",
                    summary.removed.len(),
                    summary.restored_backups.len(),
                    if summary.failed.is_empty() {
                        String::new()
                    } else {
                        format!(", {} failed", summary.failed.len())
                    }
                ));
            }
            return Ok(if summary.failed.is_empty() {
                ExitCode::Success
            } else {
                ExitCode::General
            });
        }
        Recovery::Resume { run_id, state } => {
            if selector.eq_ignore_ascii_case("latest") {
                selector = run_id;
            }
            Some(state)
        }
    };

    // Select the run and fetch its manifest first (spec §27).
    let runs = list_runs(&repo)?;
    let run = select_run(&runs, &selector, args.from_host.as_deref())?;
    let stager: Box<dyn Stager + '_> = Box::new(KopiaStager::create(&ctx.paths, &run.id, &repo)?);
    let manifest = match stager.fetch_manifest(run) {
        Ok(m) => m,
        Err(e) => {
            stager.keep();
            return Err(e);
        }
    };
    validate_manifest(&manifest, run)?;
    let sources = select_sources(&manifest, &args.category, &args.source)?;
    let policy = crate::cli::conflict_policy(args.conflict, &connected.config, console);
    let root_override = args.to.as_ref().map(|t| {
        if t.is_absolute() {
            t.clone()
        } else {
            std::env::current_dir()
                .map(|c| c.join(t))
                .unwrap_or_else(|_| t.clone())
        }
    });

    console.line(format!(
        "{} snapshot {} from {} ({}) made {} — {} source(s) onto {}",
        if ctx.options.dry_run {
            "Planning"
        } else {
            "Restoring"
        },
        run.id,
        manifest.source_host,
        manifest.source_os.display_name(),
        run.started_display(),
        sources.len(),
        root_override.as_deref().unwrap_or(adapter.home()).display()
    ));

    let report = restore_run::execute(
        Request {
            run_id: &run.id,
            manifest: &manifest,
            sources,
            policy,
            rename_collisions: args.rename_collisions,
            keep_owners: args.keep_owners,
            root_override,
            dry_run: ctx.options.dry_run,
            resume: resume_state,
            journal_path: &journal_path,
        },
        stager,
        adapter,
        console,
    )?;

    if console.json {
        console.json_report(&report)?;
    } else {
        console.line(report.render_human(console));
    }
    Ok(report.exit_code())
}
