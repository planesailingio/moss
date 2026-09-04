//! OS credential store via the `keyring` crate (Keychain, Secret Service,
//! Credential Manager).

use super::CredentialStore;
use crate::error::{MossError, Result};
use crate::security::secret::Secret;

pub struct KeyringStore;

const SERVICE: &str = "moss";

fn entry(repo_id: &str) -> Result<keyring::Entry> {
    let user = format!("{repo_id}/repository-password");
    keyring::Entry::new(SERVICE, &user).map_err(map_err)
}

fn map_err(e: keyring::Error) -> MossError {
    match e {
        keyring::Error::NoEntry => MossError::Credential("no entry".into()),
        keyring::Error::NoStorageAccess(inner) => MossError::Credential(format!(
            "The OS credential store is locked or unavailable ({inner}).\n\nUnlock it, or use --credential-store=env and set MOSS_REPOSITORY_PASSWORD."
        )),
        keyring::Error::PlatformFailure(inner) => MossError::Credential(format!(
            "The OS credential store is not available ({inner}).\n\nOn a headless Linux host there is usually no Secret Service; use --credential-store=env and set MOSS_REPOSITORY_PASSWORD."
        )),
        other => MossError::Credential(format!("credential store error: {other}")),
    }
}

impl CredentialStore for KeyringStore {
    fn name(&self) -> &'static str {
        if cfg!(target_os = "macos") {
            "macOS Keychain"
        } else if cfg!(target_os = "windows") {
            "Windows Credential Manager"
        } else {
            "Secret Service"
        }
    }

    fn get_password(&self, repo_id: &str) -> Result<Option<Secret>> {
        match entry(repo_id)?.get_password() {
            Ok(p) => Ok(Some(Secret::new(p))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(map_err(e)),
        }
    }

    fn set_password(&self, repo_id: &str, secret: &Secret) -> Result<()> {
        entry(repo_id)?
            .set_password(secret.expose())
            .map_err(map_err)
    }

    fn delete_password(&self, repo_id: &str) -> Result<()> {
        match entry(repo_id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(map_err(e)),
        }
    }
}
