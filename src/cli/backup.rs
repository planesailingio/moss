//! `moss backup` (spec §14, §18, §29, §32).

use clap::Args;

use crate::backup::{gate, run};
use crate::cli::AppContext;
use crate::error::{ExitCode, MossError, Result};
use crate::lock::Lock;
use crate::output::{confirm, human};
use crate::profile::discovery;
use crate::scan::{self, ScanOptions};

#[derive(Debug, Args)]
pub struct BackupArgs {
    /// Force a full scan, ignoring the scan index.
    #[arg(long)]
    pub rescan: bool,
    /// Back up to the local repository copy only (Phase 2).
    #[arg(long)]
    pub local_only: bool,
    /// Proceed past guardrail warnings without prompting.
    #[arg(long)]
    pub yes: bool,
}

pub fn run(ctx: &AppContext, args: BackupArgs) -> Result<ExitCode> {
    let console = ctx.console;
    if args.local_only {
        return Err(MossError::Usage(
            "--local-only is not available in this version (Phase 2).".into(),
        ));
    }
    let _lock = Lock::acquire(&ctx.paths.lock_file())?;
    let connected = ctx.connect()?;
    let config = &connected.config;
    let repo_cfg = &connected.repo;

    // Recovery gate (spec §6).
    if repo_cfg.recovery_acknowledged_at.is_none() && !ctx.global.dry_run {
        return Err(MossError::InteractionRequired(
            "The recovery sheet for this repository has not been acknowledged. Run `moss init` again and confirm you have stored it (or pass --recovery-acknowledged to init under --non-interactive).".into(),
        ));
    }

    let adapter = ctx.adapter();
    let host = crate::platform::host_info(adapter);
    ctx.paths.ensure()?;
    let sources = if config.sources.is_empty() {
        discovery::discover(adapter, config)
    } else {
        config.sources.clone()
    };
    let selected = discovery::selected(&sources, config);
    if selected.is_empty() {
        return Err(MossError::Config(
            "No sources are selected for backup. Run `moss inspect` and `moss include <path>`."
                .into(),
        ));
    }

    let mut index = scan::index::ScanIndex::load(&ctx.paths.scan_index());
    let rules = scan::build_rules(config, adapter, &ctx.paths, &mut index)?;
    let result = scan::scan(
        ctx.progress_mode(),
        &ctx.paths,
        &host.home,
        &rules,
        &selected,
        &mut index,
        &ScanOptions {
            rescan: args.rescan,
            measure_excluded: false,
            follow_links: config.backup.follow_symlinks,
            label: "Scanning".into(),
        },
    )?;

    // Sensitive-data gate (spec §14), then guardrails (spec §10).
    let flags = gate::Flags {
        yes: args.yes,
        non_interactive: ctx.global.non_interactive,
        dry_run: ctx.global.dry_run,
        can_prompt: console.can_prompt(),
    };
    if let Some(code) = settle(&console, gate::sensitive_gate(config, &result, flags))? {
        return Ok(code);
    }
    let warnings = scan::guardrails(&result, config);
    for w in &warnings {
        console.warn(format!("{} guardrail: {}", console.warn_mark(), w.message));
    }
    if let Some(code) = settle(&console, gate::guardrail_gate(&warnings, flags))? {
        return Ok(code);
    }

    let run_id = crate::backup::tags::new_run_id();
    let kopia_version = crate::backup::kopia::version(&connected.kopia.binary)?.display();
    let manifest = run::build_manifest(&run_id, config, &host, &kopia_version, &selected, &result);

    if ctx.global.dry_run {
        if console.json {
            console.json_report(&serde_json::json!({
                "dry_run": true,
                "run_id": run_id,
                "repository": repo_cfg.display_url(),
                "manifest": manifest,
                "excluded": result.excluded,
            }))?;
        } else {
            println!("Dry run — nothing will be written.\n");
            println!("Repository: {}\n", repo_cfg.display_url());
            println!("Sources ({}):", selected.len());
            for s in &result.sources {
                println!(
                    "  {:<40} {:>9}  {:>8} files{}",
                    s.home_relative,
                    human::bytes(s.size),
                    s.files,
                    if s.sensitive { "  [sensitive]" } else { "" }
                );
            }
            println!(
                "\nExcluded: {}",
                result
                    .excluded
                    .iter()
                    .map(|(k, v)| format!("{} {}", k.display_name(), v.entries))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("Skipped: {}", result.skipped.len());
            for s in result.skipped.iter().take(10) {
                println!("  {:<40} {}", s.path, s.reason.display());
            }
            println!("Collisions recorded: {}", result.collisions.len());
            println!(
                "\nTotal: {} in {} files",
                human::bytes(result.total_size),
                result.total_files
            );
        }
        return Ok(ExitCode::Success);
    }

    console.line(format!(
        "Backing up {} sources ({}) to {} …",
        selected.len(),
        human::bytes(result.total_size),
        repo_cfg.display_url()
    ));
    let repo = connected.repository();
    let outcome = run::execute(
        &repo,
        &ctx.paths.manifests_dir(),
        manifest,
        &selected,
        &rules,
    )?;

    if console.json {
        console.json_report(&outcome)?;
    } else {
        println!();
        for s in &outcome.snapshots {
            let status = if s.fatal_errors + s.ignored_errors == 0 {
                "ok".to_string()
            } else {
                format!("{} errors", s.fatal_errors + s.ignored_errors)
            };
            println!(
                "  {:<24} {:<34} {:>9}  {}",
                s.source,
                s.snapshot_id,
                human::bytes(s.size),
                status
            );
        }
        println!(
            "\nRun {}: {}",
            outcome.run_id,
            if outcome.complete {
                "complete"
            } else {
                "PARTIAL"
            }
        );
        if !outcome.skipped.is_empty() {
            println!("\nSkipped ({}):", outcome.skipped.len());
            for s in outcome.skipped.iter().take(20) {
                println!("  {:<40} {}", s.path, s.reason.display());
            }
            if outcome.skipped.len() > 20 {
                println!(
                    "  … and {} more (moss inspect --all)",
                    outcome.skipped.len() - 20
                );
            }
        }
    }
    if outcome.complete {
        Ok(ExitCode::Success)
    } else {
        // Exit 9 so schedulers notice (spec §18, §23).
        console.warn(format!(
            "Backup completed with {} skipped path(s). Exit code 9.",
            outcome.skipped.len()
        ));
        Ok(ExitCode::PartialSuccess)
    }
}

/// Act on a gate decision: `Ok(None)` means carry on, `Ok(Some(code))` ends
/// the command with that code.
fn settle(console: &crate::output::Console, gate: gate::Gate) -> Result<Option<ExitCode>> {
    match gate {
        gate::Gate::Proceed => Ok(None),
        gate::Gate::Refuse(e) => Err(e),
        gate::Gate::Confirm {
            preamble,
            question,
            on_decline,
        } => {
            if let Some(text) = preamble {
                console.line(text);
            }
            if confirm(console, question, false)? {
                return Ok(None);
            }
            match on_decline {
                gate::Decline::Refuse(e) => Err(e),
                gate::Decline::Cancel => Ok(Some(ExitCode::General)),
            }
        }
    }
}
