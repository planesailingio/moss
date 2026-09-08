//! `moss snapshots` (spec §19): Kopia snapshots grouped into moss runs.
//!
//! Grouping and status labels live in [`crate::restore::select`] so this
//! command, `moss status`, `moss verify` and `moss restore` agree.

use clap::Args;

use crate::cli::{AppContext, reports};
use crate::error::{ExitCode, Result};
use crate::output::human;
use crate::restore::select::{RunSummary, list_runs};

#[derive(Debug, Args)]
pub struct SnapshotsArgs {
    /// Only runs from this host.
    #[arg(long)]
    pub host: Option<String>,
    /// Only the most recent run.
    #[arg(long)]
    pub latest: bool,
}

pub fn run(ctx: &AppContext, args: SnapshotsArgs) -> Result<ExitCode> {
    let console = &ctx.console;
    let connected = ctx.connect()?;
    let repo = connected.repository();
    let mut runs = list_runs(&repo)?;
    if let Some(h) = &args.host {
        runs.retain(|r| r.host.eq_ignore_ascii_case(h));
    }
    if args.latest {
        runs.truncate(1);
    }
    let summaries: Vec<RunSummary> = runs.iter().map(|r| r.summary()).collect();
    if console.json {
        console.json_report(&reports::RunsReport { runs: summaries })?;
        return Ok(ExitCode::Success);
    }
    if runs.is_empty() {
        console.result("No snapshots yet. Run `moss backup`.");
        return Ok(ExitCode::Success);
    }
    let rows: Vec<Vec<String>> = runs
        .iter()
        .zip(&summaries)
        .map(|(run, s)| {
            vec![
                s.id.chars().take(10).collect(),
                run.started_display(),
                s.host.clone(),
                s.os.clone(),
                human::bytes(s.size),
                s.status.clone(),
            ]
        })
        .collect();
    console.result(human::table(
        &["ID", "DATE", "HOST", "OS", "SIZE", "STATUS"],
        &rows,
    ));
    Ok(ExitCode::Success)
}
