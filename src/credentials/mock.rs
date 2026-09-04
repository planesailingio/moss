//! In-memory store for tests.

use std::collections::HashMap;
use std::sync::Mutex;

use super::CredentialStore;
use crate::error::Result;
use crate::security::secret::Secret;

#[derive(Default)]
pub struct MockStore {
    entries: Mutex<HashMap<String, Secret>>,
}

impl MockStore {
    pub fn with(repo_id: &str, secret: &str) -> MockStore {
        let store = MockStore::default();
        store
            .entries
            .lock()
            .unwrap()
            .insert(repo_id.to_string(), Secret::new(secret));
        store
    }
}

impl CredentialStore for MockStore {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn get_password(&self, repo_id: &str) -> Result<Option<Secret>> {
        Ok(self.entries.lock().unwrap().get(repo_id).cloned())
    }

    fn set_password(&self, repo_id: &str, secret: &Secret) -> Result<()> {
        self.entries
            .lock()
            .unwrap()
            .insert(repo_id.to_string(), secret.clone());
        Ok(())
    }

    fn delete_password(&self, repo_id: &str) -> Result<()> {
        self.entries.lock().unwrap().remove(repo_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_round_trips() {
        let m = MockStore::default();
        m.probe().unwrap();
        assert!(m.entries.lock().unwrap().is_empty());
    }
}
