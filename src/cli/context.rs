//! Per-invocation state shared by all commands.

use std::path::PathBuf;

use crate::backup::kopia::KopiaContext;
use crate::backup::repository::Repository;
use crate::cli::GlobalArgs;
use crate::config::{self, Config, MossPaths, RepositoryConfig, RepositoryType};
use crate::credentials::{self, CredentialSource, CredentialStore};
use crate::error::{MossError, Result};
use crate::output::Console;
use crate::platform::{self, PlatformAdapter};
use crate::security::secret::Secret;

pub struct AppContext {
    pub console: Console,
    pub paths: MossPaths,
    pub config_path: PathBuf,
    pub global: GlobalArgs,
}

/// A connected repository with everything needed to call Kopia.
pub struct Connected {
    pub config: Config,
    pub repo: RepositoryConfig,
    pub kopia: KopiaContext,
    pub password: Secret,
    pub credential_source: CredentialSource,
    pub store: Box<dyn CredentialStore>,
}

impl Connected {
    pub fn repository(&self) -> Repository<'_> {
        Repository {
            ctx: &self.kopia,
            config: &self.repo,
            password: &self.password,
        }
    }
}

impl AppContext {
    pub fn load_config(&self) -> Result<Config> {
        config::load(&self.config_path)
    }

    pub fn load_config_or_default(&self) -> Result<Config> {
        config::load_or_default(&self.config_path)
    }

    pub fn save_config(&self, cfg: &Config) -> Result<()> {
        config::save(&self.config_path, cfg)
    }

    pub fn adapter(&self) -> Box<dyn PlatformAdapter> {
        platform::current_adapter()
    }

    /// The repository from config, with the `--repository` override applied.
    pub fn repository_config(&self, cfg: &Config) -> Result<RepositoryConfig> {
        let mut repo = cfg.repository.clone().ok_or(MossError::NotConfigured)?;
        if let Some(url) = &self.global.repository {
            let parsed = parse_repository_url(url)?;
            repo.kind = parsed.kind;
            repo.path = parsed.path;
            repo.bucket = parsed.bucket;
            repo.prefix = parsed.prefix;
            repo.id = repository_id(&repo);
        }
        Ok(repo)
    }

    /// Resolve credentials and build the Kopia context. Does not talk to Kopia
    /// beyond the version probe.
    pub fn connect(&self) -> Result<Connected> {
        let config = self.load_config()?;
        let repo = self.repository_config(&config)?;
        let store = credentials::store_for(repo.credential_store);
        let (password, credential_source) =
            credentials::resolve_password(store.as_ref(), &repo.id)?;
        let kopia = KopiaContext::new(
            &self.paths,
            &repo.id,
            self.global.verbose > 0,
            self.global.skip_version_check,
        )?;
        Ok(Connected {
            config,
            repo,
            kopia,
            password,
            credential_source,
            store,
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
        let p = crate::profile::model::expand_tilde(url, &home);
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

/// A stable, filename-safe id derived from the storage location.
pub fn repository_id(repo: &RepositoryConfig) -> String {
    use std::hash::{Hash, Hasher};
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
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    format!("{:016x}", h.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
