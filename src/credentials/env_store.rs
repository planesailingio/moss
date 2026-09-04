//! `--credential-store=env`: the user supplies `MOSS_REPOSITORY_PASSWORD`.

use super::{CredentialStore, ENV_PASSWORD};
use crate::error::{MossError, Result};
use crate::security::secret::Secret;

pub struct EnvStore;

pub fn from_env() -> Option<Secret> {
    std::env::var(ENV_PASSWORD)
        .ok()
        .filter(|s| !s.is_empty())
        .map(Secret::new)
}

impl CredentialStore for EnvStore {
    fn name(&self) -> &'static str {
        "environment"
    }

    fn get_password(&self, _repo_id: &str) -> Result<Option<Secret>> {
        Ok(from_env())
    }

    fn set_password(&self, _repo_id: &str, _secret: &Secret) -> Result<()> {
        // Nothing is persisted: the user owns the secret.
        Ok(())
    }

    fn delete_password(&self, _repo_id: &str) -> Result<()> {
        Ok(())
    }

    fn probe(&self) -> Result<()> {
        if from_env().is_some() {
            Ok(())
        } else {
            Err(MossError::Credential(format!(
                "credential store is `env` but {ENV_PASSWORD} is not set"
            )))
        }
    }
}
