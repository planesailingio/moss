//! Per-invocation state shared by all commands.

use std::path::PathBuf;

use crate::backup::kopia::{KopiaContext, KopiaRunner};
use crate::backup::repository::Repository;
use crate::cli::GlobalArgs;
use crate::config::{
    self, Config, CredentialStoreKind, MossPaths, RepositoryConfig, RepositoryType,
};
use crate::credentials::{self, CredentialSource, CredentialStore};
use crate::error::{MossError, Result};
use crate::output::Console;
use crate::platform::{self, PlatformAdapter};
use crate::security::secret::Secret;

/// The global flags that change behaviour, detached from clap so library
/// code and tests can build them without parsing a command line.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub verbose: u8,
    pub dry_run: bool,
    pub non_interactive: bool,
    pub skip_version_check: bool,
    /// `--repository`: replaces the configured storage location.
    pub repository_override: Option<String>,
}

impl From<&GlobalArgs> for Options {
    fn from(g: &GlobalArgs) -> Options {
        Options {
            verbose: g.verbose,
            dry_run: g.dry_run,
            non_interactive: g.non_interactive,
            skip_version_check: g.skip_version_check,
            repository_override: g.repository.clone(),
        }
    }
}

/// Builds the credential store for a configured kind. Tests inject `MockStore`.
pub type StoreFactory = fn(CredentialStoreKind) -> Box<dyn CredentialStore>;

/// Builds the Kopia runner for a repository id. The default locates the
/// binary on PATH; tests inject a `FixtureRunner` and never spawn anything.
pub type KopiaFactory = fn(&MossPaths, &str, &Options) -> Result<Box<dyn KopiaRunner>>;

fn default_kopia_factory(
    paths: &MossPaths,
    repo_id: &str,
    options: &Options,
) -> Result<Box<dyn KopiaRunner>> {
    let ctx = KopiaContext::new(
        paths,
        repo_id,
        options.verbose > 0,
        options.skip_version_check,
    )?;
    Ok(Box::new(ctx))
}

pub struct AppContext {
    pub console: Console,
    pub paths: MossPaths,
    pub config_path: PathBuf,
    pub options: Options,
    pub store_factory: StoreFactory,
    pub kopia_factory: KopiaFactory,
    adapter: Box<dyn PlatformAdapter>,
}

/// A connected repository with everything needed to call Kopia.
pub struct Connected {
    pub config: Config,
    pub repo: RepositoryConfig,
    pub kopia: Box<dyn KopiaRunner>,
    pub password: Secret,
    pub credential_source: CredentialSource,
    /// Display name of the store the password came from (`doctor`, `status`).
    pub store_name: &'static str,
}

impl Connected {
    pub fn repository(&self) -> Repository<'_> {
        Repository::new(self.kopia.as_ref(), &self.repo, &self.password)
    }
}

impl AppContext {
    pub fn new(
        console: Console,
        paths: MossPaths,
        config_path: PathBuf,
        global: GlobalArgs,
    ) -> Self {
        AppContext {
            console,
            paths,
            config_path,
            options: Options::from(&global),
            store_factory: credentials::store_for,
            kopia_factory: default_kopia_factory,
            adapter: platform::current_adapter(),
        }
    }

    pub fn load_config(&self) -> Result<Config> {
        config::load(&self.config_path)
    }

    pub fn load_config_or_default(&self) -> Result<Config> {
        config::load_or_default(&self.config_path)
    }

    pub fn save_config(&self, cfg: &Config) -> Result<()> {
        config::save(&self.config_path, cfg)
    }

    /// The platform adapter, detected once per invocation.
    pub fn adapter(&self) -> &dyn PlatformAdapter {
        self.adapter.as_ref()
    }

    /// The credential store for a configured kind, through the injectable factory.
    pub fn store(&self, kind: CredentialStoreKind) -> Box<dyn CredentialStore> {
        (self.store_factory)(kind)
    }

    /// The Kopia runner for a repository, through the injectable factory.
    pub fn kopia_runner(&self, repo_id: &str) -> Result<Box<dyn KopiaRunner>> {
        (self.kopia_factory)(&self.paths, repo_id, &self.options)
    }

    /// How a scan should report progress, from the console settings.
    pub fn progress_mode(&self) -> crate::scan::ProgressMode {
        if self.console.quiet || self.console.json {
            crate::scan::ProgressMode::Silent
        } else if self.console.stderr_tty {
            crate::scan::ProgressMode::Spinner
        } else {
            crate::scan::ProgressMode::Plain
        }
    }

    /// The repository from config, with the `--repository` override applied.
    pub fn repository_config(&self, cfg: &Config) -> Result<RepositoryConfig> {
        let mut repo = cfg.repository.clone().ok_or(MossError::NotConfigured)?;
        if let Some(url) = &self.options.repository_override {
            let parsed = parse_repository_url(url)?;
            repo.kind = parsed.kind;
            repo.path = parsed.path;
            repo.bucket = parsed.bucket;
            repo.prefix = parsed.prefix;
            repo.id = repository_id(&repo);
        }
        Ok(repo)
    }

    /// Resolve credentials and build the Kopia runner. Does not talk to Kopia
    /// beyond the version probe.
    pub fn connect(&self) -> Result<Connected> {
        let config = self.load_config()?;
        let repo = self.repository_config(&config)?;
        let store = self.store(repo.credential_store);
        let (password, credential_source) =
            credentials::resolve_password(store.as_ref(), &repo.id)?;
        let kopia = self.kopia_runner(&repo.id)?;
        Ok(Connected {
            config,
            repo,
            kopia,
            password,
            credential_source,
            store_name: store.name(),
        })
    }
}

/// `s3://bucket/prefix` or a filesystem path.
pub fn parse_repository_url(url: &str) -> Result<RepositoryConfig> {
    let mut repo = RepositoryConfig {
        kind: RepositoryType::Filesystem,
        id: String::new(),
        path: None,
        bucket: None,
        prefix: None,
        endpoint: None,
        region: None,
        tls: None,
        credential_store: Default::default(),
        recovery_acknowledged_at: None,
        created_at: None,
        local: None,
    };
    if let Some(rest) = url.strip_prefix("s3://") {
        let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        if bucket.is_empty() {
            return Err(MossError::Usage(format!(
                "invalid repository URL {url:?}: missing bucket"
            )));
        }
        repo.kind = RepositoryType::S3;
        repo.bucket = Some(bucket.to_string());
        let prefix = prefix.trim_matches('/');
        if !prefix.is_empty() {
            repo.prefix = Some(prefix.to_string());
        }
    } else if url.contains("://") {
        return Err(MossError::Usage(format!(
            "unsupported repository URL {url:?}: use a filesystem path or s3://bucket/prefix"
        )));
    } else {
        let home = platform::home_dir();
        let p = crate::model::expand_tilde(url, &home);
        let p = if p.is_absolute() {
            p
        } else {
            std::env::current_dir().map(|c| c.join(&p)).unwrap_or(p)
        };
        repo.path = Some(p);
    }
    repo.id = repository_id(&repo);
    Ok(repo)
}

/// A stable, filename-safe id derived from the storage location. FNV-1a over
/// the key bytes: the id names the keychain entry and the Kopia config file,
/// so it must not depend on the Rust toolchain (`DefaultHasher` does).
pub fn repository_id(repo: &RepositoryConfig) -> String {
    let key = match repo.kind {
        RepositoryType::Filesystem => format!(
            "fs:{}",
            repo.path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ),
        RepositoryType::S3 => format!(
            "s3:{}:{}:{}",
            repo.endpoint.clone().unwrap_or_default(),
            repo.bucket.clone().unwrap_or_default(),
            repo.prefix.clone().unwrap_or_default()
        ),
    };
    format!("{:016x}", fnv1a64(key.as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    bytes
        .iter()
        .fold(OFFSET, |h, b| (h ^ u64::from(*b)).wrapping_mul(PRIME))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::backup::kopia::testing::FixtureRunner;
    use crate::credentials::mock::MockStore;

    #[test]
    fn parse_urls() {
        let s3 = parse_repository_url("s3://bucket/rhys/").unwrap();
        assert_eq!(s3.kind, RepositoryType::S3);
        assert_eq!(s3.bucket.as_deref(), Some("bucket"));
        assert_eq!(s3.prefix.as_deref(), Some("rhys"));
        assert!(!s3.id.is_empty());
        let fs = parse_repository_url("/tmp/repo").unwrap();
        assert_eq!(fs.kind, RepositoryType::Filesystem);
        assert!(parse_repository_url("ftp://x").is_err());
        assert!(parse_repository_url("s3://").is_err());
        assert_ne!(fs.id, s3.id);
    }

    /// The id is a persisted contract (keychain entry, Kopia config file name);
    /// this pins the algorithm so a refactor can never silently change it.
    #[test]
    fn repository_id_is_stable() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        let fs = parse_repository_url("/tmp/repo").unwrap();
        assert_eq!(fs.id, "71c0c64b14b241b7");
    }

    /// Repository id for `/tmp/repo`, pinned above.
    pub(crate) const REPO_ID: &str = "71c0c64b14b241b7";

    /// An `AppContext` rooted in a temp dir with a configured `/tmp/repo`
    /// repository, a `MockStore` holding its password, and a `FixtureRunner`
    /// in place of Kopia. Nothing here touches PATH or the OS keychain.
    pub(crate) fn test_context(tmp: &std::path::Path) -> AppContext {
        let paths = MossPaths {
            config_dir: tmp.join("config"),
            state_dir: tmp.join("state"),
            cache_dir: tmp.join("cache"),
        };
        paths.ensure().unwrap();
        let config_path = paths.config_file();
        let cfg = Config {
            repository: Some(parse_repository_url("/tmp/repo").unwrap()),
            ..Config::default()
        };
        config::save(&config_path, &cfg).unwrap();
        let global = GlobalArgs {
            config: None,
            profile: None,
            repository: None,
            json: false,
            quiet: true,
            verbose: 0,
            dry_run: false,
            non_interactive: true,
            skip_version_check: false,
        };
        let mut ctx = AppContext::new(
            Console::new(false, true, 0, true),
            paths,
            config_path,
            global,
        );
        // An existing, private Kopia config file: the repository counts as
        // connected, so reachability is a `repository status` (the fixture).
        let kopia_config = ctx.paths.kopia_config(REPO_ID);
        config::paths::create_private_dir(kopia_config.parent().unwrap()).unwrap();
        std::fs::write(&kopia_config, "{}").unwrap();
        config::paths::make_private_file(&kopia_config).unwrap();
        ctx.store_factory = |_| Box::new(MockStore::with(REPO_ID, "fixture-password"));
        ctx.kopia_factory = |paths, repo_id, _| {
            Ok(Box::new(
                FixtureRunner::new()
                    .with_config_file(paths.kopia_config(repo_id))
                    .on_fixture(&["repository", "status"], "repository-status.json", 0),
            ))
        };
        ctx
    }

    #[test]
    fn options_come_from_global_args() {
        let g = GlobalArgs {
            config: None,
            profile: None,
            repository: Some("s3://b/p".into()),
            json: false,
            quiet: false,
            verbose: 2,
            dry_run: true,
            non_interactive: true,
            skip_version_check: true,
        };
        let o = Options::from(&g);
        assert_eq!(o.verbose, 2);
        assert!(o.dry_run && o.non_interactive && o.skip_version_check);
        assert_eq!(o.repository_override.as_deref(), Some("s3://b/p"));
    }

    #[test]
    fn connect_resolves_password_from_injected_store_and_runner() {
        if std::env::var_os(credentials::ENV_PASSWORD).is_some() {
            eprintln!("{} is set; skipping", credentials::ENV_PASSWORD);
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_context(tmp.path());
        let connected = ctx.connect().unwrap();
        assert_eq!(connected.repo.id, REPO_ID);
        assert_eq!(connected.password.expose(), "fixture-password");
        assert_eq!(connected.credential_source, CredentialSource::Keyring);
        assert_eq!(connected.store_name, "mock");
        // The runner is the fixture, so status parses without any Kopia.
        let status = connected.repository().status().unwrap();
        assert_eq!(status.client_options.hostname, "fixture-host");
        assert_eq!(
            connected.kopia.binary().to_string_lossy(),
            "/nonexistent/bin/kopia"
        );
    }

    #[test]
    fn connect_without_a_stored_password_is_a_credential_error() {
        if std::env::var_os(credentials::ENV_PASSWORD).is_some() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_context(tmp.path());
        ctx.store_factory = |_| Box::new(MockStore::default());
        let err = match ctx.connect() {
            Ok(_) => panic!("connect succeeded without a password"),
            Err(e) => e,
        };
        assert!(matches!(err, MossError::Credential(_)), "{err}");
        assert!(err.to_string().contains("mock"), "{err}");
    }
}
