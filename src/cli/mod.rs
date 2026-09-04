//! Command-line surface (spec §7, §44).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::config::{self, Config, ConflictPolicy, MossPaths};
use crate::error::{ExitCode, MossError, Result};
use crate::output::Console;

pub mod backup;
pub mod context;
pub mod doctor;
pub mod init;
pub mod inspect;
pub mod maintenance;
pub mod misc;
pub mod restore;
pub mod snapshots;

pub use context::AppContext;

#[derive(Debug, Parser)]
#[command(
    name = "moss",
    version,
    about = "Cross-platform user-profile backup and restore, on top of Kopia.",
    long_about = "moss discovers your profile, backs it up with Kopia, and restores it safely onto any OS.\n\nThere is deliberately no --password flag: the repository password lives in the OS credential store and is printed once as a recovery sheet.",
    propagate_version = true
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Args, Clone)]
pub struct GlobalArgs {
    /// Configuration file (default: platform config dir, or $MOSS_CONFIG).
    #[arg(long, global = true, value_name = "PATH", env = "MOSS_CONFIG")]
    pub config: Option<PathBuf>,
    /// Profile name (v1 supports `default` only).
    #[arg(long, global = true, value_name = "NAME")]
    pub profile: Option<String>,
    /// Repository URL override (path or s3://bucket/prefix).
    #[arg(long, global = true, value_name = "URL")]
    pub repository: Option<String>,
    /// Machine-readable JSON output with schema_version.
    #[arg(long, global = true)]
    pub json: bool,
    /// Suppress informational output.
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,
    /// Increase diagnostic output (repeatable).
    #[arg(long, short = 'v', global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Show what would happen without changing anything.
    #[arg(long, global = true)]
    pub dry_run: bool,
    /// Never prompt; fail with exit code 13 when a prompt would be needed.
    #[arg(long, global = true)]
    pub non_interactive: bool,
    /// Proceed even if the installed Kopia is outside the tested range.
    #[arg(long, global = true)]
    pub skip_version_check: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Configure a repository and generate the recovery sheet.
    Init(init::InitArgs),
    /// Check every environmental precondition.
    Doctor,
    /// Show what will be backed up, what is excluded, and what was skipped.
    Inspect(inspect::InspectArgs),
    /// Back up the profile.
    Backup(backup::BackupArgs),
    /// Push a local repository to S3 (Phase 2).
    Upload,
    /// List profile snapshots.
    Snapshots(snapshots::SnapshotsArgs),
    /// Restore a snapshot onto this machine.
    Restore(restore::RestoreArgs),
    /// Repository status and maintenance owner.
    Status,
    /// Verify snapshot integrity and restored credential modes.
    Verify(maintenance::VerifyArgs),
    /// Apply retention and expire old snapshots (wraps `kopia snapshot expire`).
    Prune(maintenance::PruneArgs),
    /// Run repository maintenance (wraps `kopia maintenance run`).
    Maintenance(maintenance::MaintenanceArgs),
    /// Show or locate the configuration.
    Config(misc::ConfigArgs),
    /// List profiles (Phase 2).
    Profiles,
    /// Add a path to the backup.
    Include(misc::IncludeArgs),
    /// Exclude a path or gitignore-style pattern.
    Exclude(misc::ExcludeArgs),
    /// Recovery sheet commands.
    Recovery(misc::RecoveryArgs),
    /// YubiKey commands (Phase 2).
    Yubikey(misc::YubikeyArgs),
    /// Escape hatch: run Kopia against the moss repository.
    #[command(trailing_var_arg = true, allow_hyphen_values = true)]
    Kopia(misc::KopiaArgs),
}

/// Entry point: parse, run, map to an exit code.
pub fn main() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // clap prints help/version itself with exit 0; usage errors get 2.
            let code = if e.use_stderr() {
                ExitCode::Usage.code()
            } else {
                0
            };
            let _ = e.print();
            return code;
        }
    };
    let console = Console::new(
        cli.global.json,
        cli.global.quiet,
        cli.global.verbose,
        cli.global.non_interactive,
    );
    init_tracing(cli.global.verbose);
    match run(cli, console) {
        Ok(code) => code.code(),
        Err(err) => {
            report_error(&console, &err);
            err.exit_code().code()
        }
    }
}

fn init_tracing(verbose: u8) {
    use tracing_subscriber::EnvFilter;
    let default = match verbose {
        0 => "moss=warn",
        1 => "moss=info",
        2 => "moss=debug",
        _ => "moss=trace",
    };
    let filter = EnvFilter::try_from_env("MOSS_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .try_init();
}

pub fn report_error(console: &Console, err: &MossError) {
    if console.json {
        let value = serde_json::json!({
            "schema_version": crate::output::JSON_SCHEMA_VERSION,
            "error": err.to_string(),
            "exit_code": err.exit_code().code(),
            "exit_code_name": err.exit_code().description(),
        });
        let _ = crate::output::Console::json_report(console, &value);
    }
    console.error(format!("error: {err}"));
    if console.verbose > 0
        && let Some(detail) = err.verbose_detail()
    {
        console.error(format!("\nkopia said:\n{detail}"));
    }
}

fn run(cli: Cli, console: Console) -> Result<ExitCode> {
    let paths = MossPaths::resolve()?;
    let config_path = config::config_path(cli.global.config.as_deref(), &paths);
    if let Some(p) = &cli.global.profile
        && p != "default"
    {
        return Err(MossError::Usage(format!(
            "Named profiles are not available in this version (got --profile {p}); only `default` is supported."
        )));
    }
    let ctx = AppContext {
        console,
        paths,
        config_path,
        global: cli.global.clone(),
    };
    match cli.command {
        Command::Init(args) => init::run(&ctx, args),
        Command::Doctor => doctor::run(&ctx),
        Command::Inspect(args) => inspect::run(&ctx, args),
        Command::Backup(args) => backup::run(&ctx, args),
        Command::Snapshots(args) => snapshots::run(&ctx, args),
        Command::Restore(args) => restore::run(&ctx, args),
        Command::Status => maintenance::status(&ctx),
        Command::Verify(args) => maintenance::verify(&ctx, args),
        Command::Prune(args) => maintenance::prune(&ctx, args),
        Command::Maintenance(args) => maintenance::run(&ctx, args),
        Command::Config(args) => misc::config(&ctx, args),
        Command::Include(args) => misc::include(&ctx, args),
        Command::Exclude(args) => misc::exclude(&ctx, args),
        Command::Recovery(args) => misc::recovery(&ctx, args),
        Command::Kopia(args) => misc::kopia(&ctx, args),
        Command::Upload => Err(MossError::Usage(
            "`moss upload` is not available in this version. Offline backup and deferred upload arrive in Phase 2.".into(),
        )),
        Command::Profiles => Err(MossError::Usage(
            "Named profiles are not available in this version; only `default` exists.".into(),
        )),
        Command::Yubikey(args) => misc::yubikey(&ctx, args),
    }
}

/// Shared helper: parse `--conflict` and config into a policy.
pub fn conflict_policy(
    flag: Option<ConflictPolicy>,
    config: &Config,
    console: &Console,
) -> ConflictPolicy {
    let policy = flag.unwrap_or(config.restore.conflict);
    if policy == ConflictPolicy::Interactive && !console.can_prompt() {
        ConflictPolicy::Skip
    } else {
        policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn there_is_no_password_flag() {
        let cmd = Cli::command();
        fn walk(c: &clap::Command) {
            for a in c.get_arguments() {
                assert_ne!(
                    a.get_id().as_str(),
                    "password",
                    "spec §6: no --password flag"
                );
            }
            for s in c.get_subcommands() {
                walk(s);
            }
        }
        walk(&cmd);
    }
}
