//! `config`, `include`, `exclude`, `recovery`, `yubikey`, `kopia`.

use clap::{Args, Subcommand};

use crate::cli::AppContext;
use crate::config::PathRule;
use crate::error::{ExitCode, MossError, Result};
use crate::profile::model::{ProfileCategory, expand_tilde};
use crate::security::recovery::{self, SheetInfo};

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: Option<ConfigSubcommand>,
}

#[derive(Debug, Subcommand)]
pub enum ConfigSubcommand {
    /// Print the effective configuration.
    Show,
    /// Print the configuration file path.
    Path,
}

#[derive(Debug, Args)]
pub struct IncludeArgs {
    /// Path to add (may start with ~).
    pub path: String,
    /// Category for the new source.
    #[arg(long, value_parser = parse_category)]
    pub category: Option<ProfileCategory>,
}

#[derive(Debug, Args)]
pub struct ExcludeArgs {
    /// Path (~/Movies) or gitignore-style pattern (node_modules/) to exclude.
    pub pattern: String,
}

#[derive(Debug, Args)]
pub struct RecoveryArgs {
    #[command(subcommand)]
    pub command: RecoverySubcommand,
}

#[derive(Debug, Subcommand)]
pub enum RecoverySubcommand {
    /// Re-display the recovery sheet (reads the credential store).
    Show,
}

#[derive(Debug, Args)]
pub struct YubikeyArgs {
    #[command(subcommand)]
    pub command: YubikeySubcommand,
}

#[derive(Debug, Subcommand)]
pub enum YubikeySubcommand {
    Detect,
    Setup,
    Status,
    Remove,
}

#[derive(Debug, Args)]
pub struct KopiaArgs {
    /// Arguments passed to Kopia verbatim.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn parse_category(s: &str) -> std::result::Result<ProfileCategory, String> {
    ProfileCategory::parse(s).ok_or_else(|| {
        format!(
            "unknown category {s:?}; one of: {}",
            ProfileCategory::ALL
                .iter()
                .map(|c| format!("{c:?}").to_lowercase())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

pub fn config(ctx: &AppContext, args: ConfigArgs) -> Result<ExitCode> {
    match args.command.unwrap_or(ConfigSubcommand::Show) {
        ConfigSubcommand::Path => {
            println!("{}", ctx.config_path.display());
        }
        ConfigSubcommand::Show => {
            let cfg = ctx.load_config_or_default()?;
            if ctx.console.json {
                ctx.console.json_report(&cfg)?;
            } else {
                print!("{}", crate::config::render(&cfg)?);
            }
        }
    }
    Ok(ExitCode::Success)
}

pub fn include(ctx: &AppContext, args: IncludeArgs) -> Result<ExitCode> {
    let mut cfg = ctx.load_config_or_default()?;
    let home = ctx.adapter().home();
    let path = expand_tilde(&args.path, &home);
    if !path.exists() {
        return Err(MossError::Usage(format!(
            "{} does not exist",
            path.display()
        )));
    }
    let entry = if path.starts_with(&home) {
        crate::profile::model::home_relative(&path, &home)
    } else {
        path.display().to_string()
    };
    if cfg.include.iter().any(|r| r.path == entry) {
        ctx.console.line(format!("{entry} is already included."));
        return Ok(ExitCode::Success);
    }
    cfg.include.push(PathRule {
        path: entry.clone(),
        category: args.category,
    });
    refresh_sources(ctx, &mut cfg);
    ctx.save_config(&cfg)?;
    ctx.console.line(format!("Included {entry}."));
    Ok(ExitCode::Success)
}

pub fn exclude(ctx: &AppContext, args: ExcludeArgs) -> Result<ExitCode> {
    let mut cfg = ctx.load_config_or_default()?;
    let entry = args.pattern.trim().to_string();
    if entry.is_empty() {
        return Err(MossError::Usage("empty pattern".into()));
    }
    if cfg.exclude.iter().any(|r| r.path == entry) {
        ctx.console.line(format!("{entry} is already excluded."));
        return Ok(ExitCode::Success);
    }
    cfg.exclude.push(PathRule::new(entry.clone()));
    ctx.save_config(&cfg)?;
    ctx.console.line(format!("Excluded {entry}."));
    Ok(ExitCode::Success)
}

fn refresh_sources(ctx: &AppContext, cfg: &mut crate::config::Config) {
    if !cfg.sources.is_empty() {
        cfg.sources = crate::profile::discovery::discover(ctx.adapter().as_ref(), cfg);
    }
}

pub fn recovery(ctx: &AppContext, args: RecoveryArgs) -> Result<ExitCode> {
    let RecoverySubcommand::Show = args.command;
    let connected = ctx.connect()?;
    let kopia_version = crate::backup::kopia::version(&connected.kopia.binary)
        .map(|v| v.display())
        .unwrap_or_else(|_| "?".into());
    let sheet = recovery::format_sheet(
        &SheetInfo {
            repository: &connected.repo.display_url(),
            endpoint: connected.repo.endpoint.as_deref(),
            created: &connected
                .repo
                .created_at
                .map(|t| t.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "?".into()),
            profile: &connected.config.profile.identity,
            moss_version: crate::VERSION,
            kopia_version: &kopia_version,
        },
        &connected.password,
    );
    if ctx.console.json {
        return Err(MossError::Usage("The recovery sheet is never emitted as JSON; run without --json and redirect the output.".into()));
    }
    println!("{sheet}");
    Ok(ExitCode::Success)
}

pub fn yubikey(ctx: &AppContext, args: YubikeyArgs) -> Result<ExitCode> {
    let provider = crate::yubikey::provider();
    match args.command {
        YubikeySubcommand::Detect | YubikeySubcommand::Status => {
            let keys = provider.detect()?;
            if ctx.console.json {
                ctx.console.json_report(&serde_json::json!({ "detected": keys.len(), "configured": false, "available": false }))?;
            } else if keys.is_empty() {
                println!(
                    "No YubiKey detected.\n\nYubiKey-protected repositories are not available in this version (Phase 2). The recovery code protects the repository."
                );
            }
            Ok(ExitCode::Success)
        }
        YubikeySubcommand::Setup | YubikeySubcommand::Remove => Err(MossError::YubiKey(
            "YubiKey support is not available in this version (Phase 2).".into(),
        )),
    }
}

/// Escape hatch: `moss kopia <args…>` runs Kopia with moss's config file and
/// credentials so the user's own Kopia invocations see the same repository.
pub fn kopia(ctx: &AppContext, args: KopiaArgs) -> Result<ExitCode> {
    if args.args.is_empty() {
        return Err(MossError::Usage(
            "usage: moss kopia <kopia arguments…>".into(),
        ));
    }
    let connected = ctx.connect()?;
    let refs: Vec<&str> = args.args.iter().map(String::as_str).collect();
    let out = connected.repository().passthrough(&refs)?;
    print!("{}", out.stdout);
    eprint!("{}", out.stderr);
    Ok(if out.success() {
        ExitCode::Success
    } else {
        ExitCode::General
    })
}
