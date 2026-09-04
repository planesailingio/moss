//! Repository password storage (spec §6).
//!
//! The OS credential store holds exactly one secret per repository: the
//! password, which is also the recovery code. `MOSS_REPOSITORY_PASSWORD` in the
//! environment takes precedence on every platform.

pub mod env_store;
pub mod keyring_store;
pub mod mock;

use crate::config::CredentialStoreKind;
use crate::error::{MossError, Result};
use crate::security::secret::Secret;

pub const ENV_PASSWORD: &str = "MOSS_REPOSITORY_PASSWORD";

/// How a password was obtained, for `doctor` and `status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSource {
    Environment,
    Keyring,
}

pub trait CredentialStore: Send + Sync {
    fn name(&self) -> &'static str;
    fn get_password(&self, repo_id: &str) -> Result<Option<Secret>>;
    fn set_password(&self, repo_id: &str, secret: &Secret) -> Result<()>;
    fn delete_password(&self, repo_id: &str) -> Result<()>;

    /// Verify the store works by writing and removing a sentinel (spec §6, §7).
    fn probe(&self) -> Result<()> {
        let id = format!("probe-{}", std::process::id());
        self.set_password(&id, &Secret::new("moss-probe"))?;
        let back = self.get_password(&id)?;
        self.delete_password(&id)?;
        match back {
            Some(s) if s.expose() == "moss-probe" => Ok(()),
            _ => Err(MossError::Credential(
                "credential store returned a different value than was written".into(),
            )),
        }
    }
}

/// Build the store the configuration asks for.
pub fn store_for(kind: CredentialStoreKind) -> Box<dyn CredentialStore> {
    match kind {
        CredentialStoreKind::Keyring => Box::new(keyring_store::KeyringStore),
        CredentialStoreKind::Env => Box::new(env_store::EnvStore),
    }
}

/// Resolve the repository password: environment first, then the store.
pub fn resolve_password(
    store: &dyn CredentialStore,
    repo_id: &str,
) -> Result<(Secret, CredentialSource)> {
    if let Some(s) = env_store::from_env() {
        return Ok((s, CredentialSource::Environment));
    }
    match store.get_password(repo_id)? {
        Some(s) => Ok((s, CredentialSource::Keyring)),
        None => Err(MossError::Credential(format!(
            "No repository password found in the {} for this repository.\n\nIf this machine was set up before, unlock the credential store and retry. Otherwise run `moss init` and enter the recovery code from your sheet, or set {ENV_PASSWORD}.",
            store.name()
        ))),
    }
}
