//! `moss init` (spec §6, §7, §31): configure a repository, generate and store
//! the password, discover sources, gate on the recovery sheet.

use clap::{Args, Subcommand};

use crate::backup::kopia::{self, KopiaRunner};
use crate::backup::repository::{Repository, S3Credentials};
use crate::cli::AppContext;
use crate::cli::context::{parse_repository_url, repository_id};
use crate::config::{Config, CredentialStoreKind, RepositoryType};
use crate::credentials::{self, ENV_PASSWORD};
use crate::error::{ExitCode, MossError, Result};
use crate::output::{confirm, prompt_line};
use crate::profile::discovery;
use crate::security::recovery::{self, SheetInfo};
use crate::security::secret::Secret;

#[derive(Debug, Args)]
#[command(subcommand_negates_reqs = true, args_conflicts_with_subcommands = true)]
pub struct InitArgs {
    /// Repository location: a filesystem path or s3://bucket/prefix.
    #[arg(long, value_name = "URL", required = true)]
    pub repository: Option<String>,
    /// S3-compatible endpoint (host or https://host). See `init list-backup-endpoints`.
    #[arg(long, value_name = "URL")]
    pub endpoint: Option<String>,
    /// S3 region (default: auto).
    #[arg(long, value_name = "REGION")]
    pub region: Option<String>,
    /// Stable profile identity, independent of username and hostname.
    #[arg(long, value_name = "NAME")]
    pub identity: Option<String>,
    /// Where the repository password is kept.
    #[arg(long, value_enum, default_value = "keyring")]
    pub credential_store: CredentialStoreArg,
    /// Required with --non-interactive: the caller has stored the recovery sheet.
    #[arg(long)]
    pub recovery_acknowledged: bool,
    /// Print the recovery sheet only (after init) without the acknowledgement prompt.
    #[arg(long)]
    pub print: bool,
    #[command(subcommand)]
    pub command: Option<InitSubcommand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CredentialStoreArg {
    Keyring,
    Env,
}

#[derive(Debug, Subcommand)]
pub enum InitSubcommand {
    /// List known S3-compatible vendors and their endpoint patterns.
    ListBackupEndpoints {
        /// Filter by vendor name.
        #[arg(long)]
        name: Option<String>,
    },
}

pub fn run(ctx: &AppContext, args: InitArgs) -> Result<ExitCode> {
    if let Some(InitSubcommand::ListBackupEndpoints { name }) = args.command {
        if ctx.console.json {
            ctx.console
                .json_report(&serde_json::json!({ "endpoints": crate::endpoints::ENDPOINTS }))?;
        } else {
            println!("{}", crate::endpoints::render_table(name.as_deref()));
        }
        return Ok(ExitCode::Success);
    }
    let url = args
        .repository
        .clone()
        .ok_or_else(|| MossError::Usage("--repository is required".into()))?;
    let console = ctx.console;
    let adapter = ctx.adapter();
    let host = crate::platform::host_info(adapter);
    let mut config = ctx.load_config_or_default()?;

    console.line("Welcome to moss.\n");
    console.line("Detected:");
    console.line(format!("  OS:   {}", host.platform.display_name()));
    console.line(format!("  User: {}", host.username));
    console.line(format!("  Home: {}\n", host.home.display()));

    // Repository configuration.
    let mut repo = parse_repository_url(&url)?;
    if let Some(e) = &args.endpoint {
        if repo.kind != RepositoryType::S3 {
            return Err(MossError::Usage(
                "--endpoint applies to s3:// repositories only".into(),
            ));
        }
        repo.endpoint = Some(e.clone());
    }
    if let Some(r) = &args.region {
        repo.region = Some(r.clone());
    }
    repo.id = repository_id(&repo);
    repo.credential_store = match args.credential_store {
        CredentialStoreArg::Keyring => CredentialStoreKind::Keyring,
        CredentialStoreArg::Env => CredentialStoreKind::Env,
    };
    if let RepositoryType::Filesystem = repo.kind
        && let Some(p) = &repo.path
        && !p.exists()
    {
        crate::config::paths::create_private_dir(p)?;
    }

    // Identity (spec §22).
    let identity = match args
        .identity
        .clone()
        .or_else(|| (!config.profile.identity.is_empty()).then(|| config.profile.identity.clone()))
    {
        Some(i) => i,
        None if console.can_prompt() => {
            let answer = prompt_line(&console, &format!("Profile identity [{}]:", host.username))?;
            if answer.is_empty() {
                host.username.clone()
            } else {
                answer
            }
        }
        None => host.username.clone(),
    };
    config.profile.identity = identity.clone();

    // Credential store.
    let store = ctx.store(repo.credential_store);
    if repo.credential_store == CredentialStoreKind::Keyring {
        if let Err(e) = store.probe() {
            return Err(MossError::Credential(format!(
                "{e}\n\nNo usable credential store was found. Re-run with --credential-store=env and supply {ENV_PASSWORD} yourself; moss will not store the password anywhere in that mode."
            )));
        }
    } else {
        console.warn(format!(
            "Credential store is `env`: you are responsible for supplying {ENV_PASSWORD} on every run. It is not stored anywhere by moss."
        ));
    }

    let kopia_ctx = ctx.kopia_runner(&repo.id)?;
    let kopia_version = kopia::check_version(kopia_ctx.binary(), ctx.options.skip_version_check)?;
    let s3 = if repo.kind == RepositoryType::S3 {
        s3_credentials(ctx)?
    } else {
        None
    };

    // Existing password on this machine (re-init) or in the environment?
    let existing =
        credentials::env_store::from_env().or_else(|| store.get_password(&repo.id).ok().flatten());

    console.line("Generating repository encryption key...");
    let (password, created) = match existing {
        Some(pw) => {
            let r = Repository::new(kopia_ctx.as_ref(), &repo, &pw);
            match r.connect(s3.as_ref()) {
                Ok(()) => {
                    console.line("Connected to the existing repository with the stored password.");
                    (pw, false)
                }
                Err(MossError::RepositoryNotInitialised { .. }) => {
                    r.create(s3.as_ref())?;
                    // The password may have come from the environment; make
                    // sure the configured store has it too.
                    store.set_password(&repo.id, &pw)?;
                    (pw, true)
                }
                Err(MossError::AuthFailure { .. }) => {
                    bootstrap(ctx, kopia_ctx.as_ref(), &repo, s3.as_ref(), store.as_ref())?
                }
                Err(e) => return Err(e),
            }
        }
        None => {
            let pw = recovery::generate()?;
            let r = Repository::new(kopia_ctx.as_ref(), &repo, &pw);
            match r.create(s3.as_ref()) {
                Ok(()) => {
                    store.set_password(&repo.id, &pw)?;
                    (pw, true)
                }
                Err(MossError::RepositoryExists { .. }) => {
                    console.line("A repository already exists at this location.");
                    bootstrap(ctx, kopia_ctx.as_ref(), &repo, s3.as_ref(), store.as_ref())?
                }
                Err(e) => return Err(e),
            }
        }
    };
    // Kopia's config holds storage details (and S3 keys); keep it private (spec §5).
    crate::config::paths::make_private_file(kopia_ctx.config_file())?;

    // Discovery (spec §8): written into config so the user can see and edit it.
    config.sources = discovery::discover(adapter, &config);
    // Re-init keeps what the previous configuration knew about this
    // repository; only a genuine create stamps a new creation time.
    if let Some(prev) = config.repository.as_ref().filter(|r| r.id == repo.id) {
        repo.recovery_acknowledged_at = prev.recovery_acknowledged_at;
        repo.created_at = prev.created_at;
    }
    if created || repo.created_at.is_none() {
        repo.created_at = Some(chrono::Utc::now());
    }
    config.repository = Some(repo.clone());
    ctx.save_config(&config)?;
    console.line(format!(
        "Discovered {} sources; written to {}.\n",
        config.sources.len(),
        ctx.config_path.display()
    ));

    // Recovery sheet gate (spec §6).
    let sheet = recovery::format_sheet(
        &SheetInfo {
            repository: &repo.display_url(),
            endpoint: repo.endpoint.as_deref(),
            created: &repo
                .created_at
                .unwrap_or_else(chrono::Utc::now)
                .format("%Y-%m-%d")
                .to_string(),
            profile: &identity,
            moss_version: crate::VERSION,
            kopia_version: &kopia_version.display(),
        },
        &password,
    );
    if repo.recovery_acknowledged_at.is_some() && !args.print {
        console.line("Recovery sheet already acknowledged for this repository. Run `moss recovery show` to see it again.");
        return finish(ctx, &config, &console);
    }
    println!("{sheet}");
    if args.print {
        return Ok(ExitCode::Success);
    }
    let acknowledged = if args.recovery_acknowledged {
        true
    } else if console.can_prompt() {
        confirm(
            &console,
            "\n  [ ] I have stored this somewhere safe   (required to continue)\n\nType y to confirm:",
            false,
        )?
    } else {
        return Err(MossError::InteractionRequired(
            "The recovery sheet must be acknowledged before the first backup. Pass --recovery-acknowledged to confirm that you have stored it.".into(),
        ));
    };
    if !acknowledged {
        console.warn("Not acknowledged. `moss backup` will refuse to run until you re-run `moss init` and confirm.");
        return Ok(ExitCode::InteractionRequired);
    }
    if let Some(r) = config.repository.as_mut() {
        r.recovery_acknowledged_at = Some(chrono::Utc::now());
    }
    ctx.save_config(&config)?;
    finish(ctx, &config, &console)
}

fn finish(ctx: &AppContext, config: &Config, console: &crate::output::Console) -> Result<ExitCode> {
    if console.json {
        console.json_report(&serde_json::json!({
            "repository": config.repository.as_ref().map(|r| r.display_url()),
            "repository_id": config.repository.as_ref().map(|r| r.id.clone()),
            "identity": config.profile.identity,
            "sources": config.sources.len(),
            "recovery_acknowledged": config.repository.as_ref().and_then(|r| r.recovery_acknowledged_at.is_some().then_some(true)).unwrap_or(false),
            "config": ctx.config_path,
        }))?;
    } else {
        console.line("\nNext:\n  moss doctor\n  moss inspect\n  moss backup");
    }
    Ok(ExitCode::Success)
}

/// Second-machine bootstrap (spec §6): the recovery code is the only input.
fn bootstrap(
    ctx: &AppContext,
    kopia_ctx: &dyn KopiaRunner,
    repo: &crate::config::RepositoryConfig,
    s3: Option<&S3Credentials>,
    store: &dyn credentials::CredentialStore,
) -> Result<(Secret, bool)> {
    let console = ctx.console;
    if !console.can_prompt() {
        return Err(MossError::InteractionRequired(format!(
            "The repository at {} already exists and needs its recovery code. Re-run interactively, or set {ENV_PASSWORD} to the 24-word recovery code.",
            repo.display_url()
        )));
    }
    for attempt in 1..=3 {
        let input = prompt_line(&console, "Enter the 24-word recovery code from your sheet:")?;
        let pw = match recovery::parse(&input) {
            Ok(pw) => pw,
            Err(e) => {
                console.warn(format!("{e}"));
                continue;
            }
        };
        let r = Repository::new(kopia_ctx, repo, &pw);
        match r.connect(s3) {
            Ok(()) => {
                store.set_password(&repo.id, &pw)?;
                console.line("Recovery code accepted; stored in this machine's credential store.");
                return Ok((pw, false));
            }
            Err(MossError::AuthFailure { .. }) if attempt < 3 => {
                console
                    .warn("The repository rejected that code. Check the word order and try again.");
            }
            Err(e) => return Err(e),
        }
    }
    Err(MossError::AuthFailure {
        context: format!("Repository: {}", repo.display_url()),
    })
}

fn s3_credentials(ctx: &AppContext) -> Result<Option<S3Credentials>> {
    if let Some(c) = S3Credentials::from_env() {
        ctx.console
            .line("Using S3 credentials from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.");
        return Ok(Some(c));
    }
    if !ctx.console.can_prompt() {
        ctx.console.warn("No AWS_* credentials in the environment; relying on the SDK's IAM / instance-role chain.");
        return Ok(None);
    }
    let ak = prompt_line(
        &ctx.console,
        "S3 access key id (leave empty to use IAM / instance role):",
    )?;
    if ak.is_empty() {
        return Ok(None);
    }
    let sk = prompt_line(&ctx.console, "S3 secret access key:")?;
    ctx.console.warn(
        "Note: Kopia stores these keys in its own config file under moss's state directory (mode 0600). See SECURITY.md.",
    );
    Ok(Some(S3Credentials {
        access_key: Secret::new(ak),
        secret_key: Secret::new(sk),
        session_token: None,
    }))
}
