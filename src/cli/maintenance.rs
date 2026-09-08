//! `moss status`, `verify`, `prune`, `maintenance` (spec §30).

use clap::Args;

use crate::cli::{AppContext, reports};
use crate::error::{ExitCode, MossError, Result};
use crate::output::{confirm, human};
use crate::restore::select::{self, RunSummary};

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Run to verify: `latest` (default) or a run id prefix.
    #[arg(default_value = "latest")]
    pub selector: String,
    /// Percentage of file contents to download and verify (0–100).
    #[arg(long, default_value_t = 0)]
    pub files_percent: u8,
    /// Also check modes of restored credential paths on this machine.
    #[arg(long)]
    pub check_modes: bool,
}

#[derive(Debug, Args)]
pub struct PruneArgs {
    /// Actually delete expired snapshots (default: report only).
    #[arg(long)]
    pub delete: bool,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct MaintenanceArgs {
    /// Run full maintenance (compaction) instead of quick.
    #[arg(long)]
    pub full: bool,
}

pub fn status(ctx: &AppContext) -> Result<ExitCode> {
    let console = &ctx.console;
    let connected = ctx.connect()?;
    let repo = connected.repository();
    let st = repo.status()?;
    let maint = repo.maintenance_info().ok();
    let runs: Vec<RunSummary> = select::list_runs(&repo)?
        .iter()
        .map(|r| r.summary())
        .collect();
    let mut hosts: std::collections::BTreeMap<String, &RunSummary> =
        std::collections::BTreeMap::new();
    for r in &runs {
        hosts.entry(r.host.clone()).or_insert(r);
    }
    if console.json {
        console.json_report(&reports::StatusReport {
            repository: connected.repo.display_url(),
            repository_id: connected.repo.id.clone(),
            kopia_unique_id: st.unique_id_hex.clone(),
            credentials: match connected.credential_source {
                crate::credentials::CredentialSource::Environment => "environment",
                crate::credentials::CredentialSource::Keyring => "keyring",
            },
            maintenance_owner: maint.as_ref().map(|m| m.owner.clone()),
            next_full_maintenance: maint.as_ref().and_then(|m| m.schedule.next_full),
            runs: runs.len(),
            latest_by_host: hosts
                .values()
                .map(|r| reports::HostLatest::from_summary(r))
                .collect(),
        })?;
        return Ok(ExitCode::Success);
    }
    console.result("Repository");
    console.result(human::kv_block(&[
        ("Location:".into(), connected.repo.display_url()),
        (
            "Credentials:".into(),
            match connected.credential_source {
                crate::credentials::CredentialSource::Environment => "environment".into(),
                crate::credentials::CredentialSource::Keyring => connected.store_name.into(),
            },
        ),
        (
            "Kopia id:".into(),
            st.unique_id_hex.chars().take(16).collect(),
        ),
        ("Runs:".into(), runs.len().to_string()),
    ]));
    if let Some(m) = maint {
        console.result("\nMaintenance");
        console.result(human::kv_block(&[
            (
                "Owner:".into(),
                format!(
                    "{}  (only this identity runs maintenance automatically)",
                    m.owner
                ),
            ),
            (
                "Next full:".into(),
                m.schedule
                    .next_full
                    .map(|t| {
                        t.with_timezone(&chrono::Local)
                            .format("%Y-%m-%d %H:%M")
                            .to_string()
                    })
                    .unwrap_or_else(|| "-".into()),
            ),
        ]));
    }
    console.result(format!("\nProfile: {}", connected.config.profile.identity));
    console.result("Hosts:");
    let rows: Vec<Vec<String>> = hosts
        .values()
        .map(|r| {
            vec![
                r.host.clone(),
                r.os.clone(),
                format!("user {}", r.user),
                r.started
                    .map(|t| t.format("%Y-%m-%d").to_string())
                    .unwrap_or_default(),
                r.status.clone(),
            ]
        })
        .collect();
    if rows.is_empty() {
        console.result("  (none yet)");
    } else {
        for row in rows {
            console.result(format!("  {}", row.join("  ")));
        }
    }
    Ok(ExitCode::Success)
}

pub fn verify(ctx: &AppContext, args: VerifyArgs) -> Result<ExitCode> {
    let console = &ctx.console;
    let connected = ctx.connect()?;
    let repo = connected.repository();
    let runs = select::list_runs(&repo)?;
    let run = select::select_run(&runs, &args.selector, None)?;
    let mut ids: Vec<&str> = run.members.iter().map(|m| m.id.as_str()).collect();
    if let Some(m) = &run.manifest_snapshot {
        ids.push(m);
    }
    console.line(format!(
        "Verifying run {} ({} snapshots, {}% of file data) …",
        run.id,
        ids.len(),
        args.files_percent
    ));
    repo.snapshot_verify(&ids, args.files_percent.min(100))?;

    let mut mode_problems = Vec::new();
    if args.check_modes {
        mode_problems = check_credential_modes(ctx.adapter().home());
    }
    if console.json {
        console.json_report(&reports::VerifyReport {
            run: &run.id,
            snapshots_verified: ids.len(),
            files_percent: args.files_percent,
            mode_problems: &mode_problems,
        })?;
    } else {
        console.result(format!("{} run {} verified.", console.ok_mark(), run.id));
        for p in &mode_problems {
            console.result(format!("{} {p}", console.fail_mark()));
        }
    }
    if mode_problems.is_empty() {
        Ok(ExitCode::Success)
    } else {
        Err(MossError::Integrity(format!(
            "{} credential path(s) have unsafe modes.",
            mode_problems.len()
        )))
    }
}

/// spec §12: ssh hard-fails on group/world-readable private keys; config must
/// not be writable by others.
pub fn check_credential_modes(home: &std::path::Path) -> Vec<String> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut problems = Vec::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let ssh = home.join(".ssh");
        if let Ok(rd) = std::fs::read_dir(&ssh) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let Ok(meta) = e.metadata() else { continue };
                if !meta.is_file() {
                    continue;
                }
                let mode = meta.permissions().mode() & 0o777;
                let is_private_key =
                    crate::profile::sensitive::classify(&format!("~/.ssh/{name}")).is_some();
                if is_private_key && mode & 0o077 != 0 {
                    problems.push(format!(
                        "~/.ssh/{name} is mode {mode:04o}; ssh will refuse it (needs 0600)"
                    ));
                }
                if name == "config" && mode & 0o022 != 0 {
                    problems.push(format!(
                        "~/.ssh/config is mode {mode:04o}; must not be group/world-writable"
                    ));
                }
            }
        }
        for rel in [".aws/credentials", ".kube/config", ".docker/config.json"] {
            let p = home.join(rel);
            if let Ok(meta) = std::fs::metadata(&p) {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    problems.push(format!("~/{rel} is mode {mode:04o}; recommended 0600"));
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = home;
    }
    problems
}

pub fn prune(ctx: &AppContext, args: PruneArgs) -> Result<ExitCode> {
    let console = &ctx.console;
    let connected = ctx.connect()?;
    let repo = connected.repository();
    if args.delete
        && !args.yes
        && !confirm(
            console,
            "Delete snapshots that fall outside the retention policy?",
            false,
        )?
    {
        return Ok(ExitCode::General);
    }
    let out = repo.snapshot_expire(args.delete)?;
    if console.json {
        console.json_report(&reports::PruneReport {
            deleted: args.delete,
            kopia_output: out.stdout.trim(),
        })?;
    } else {
        console.result(out.stdout.trim());
        if !args.delete {
            console.result("\n(report only; pass --delete to remove expired snapshots)");
        }
    }
    Ok(ExitCode::Success)
}

pub fn run(ctx: &AppContext, args: MaintenanceArgs) -> Result<ExitCode> {
    let console = &ctx.console;
    let connected = ctx.connect()?;
    let repo = connected.repository();
    let info = repo.maintenance_info()?;
    let me = format!(
        "{}@{}",
        crate::platform::username(),
        crate::platform::hostname()
    );
    if info.owner != me {
        console.warn(format!(
            "Maintenance owner is {} (this machine is {me}). Kopia only lets the owner run maintenance; run it there, or transfer ownership with `moss kopia maintenance set --owner={me}`.",
            info.owner
        ));
    }
    let out = repo.maintenance_run(args.full)?;
    if console.json {
        console.json_report(&reports::MaintenanceReport {
            full: args.full,
            owner: &info.owner,
            kopia_output: out.stdout.trim(),
        })?;
    } else {
        console.result(out.stdout.trim());
        console.result(format!(
            "{} maintenance {} run finished.",
            console.ok_mark(),
            if args.full { "full" } else { "quick" }
        ));
    }
    Ok(ExitCode::Success)
}
