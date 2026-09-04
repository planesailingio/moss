//! Hardware-key abstraction (spec §36). Phase 2 implements it with
//! age-plugin-yubikey; v1 ships the trait, a mock, and honest "not configured"
//! answers so the rest of the application never learns about PC/SC.

use crate::error::Result;
use crate::security::secret::Secret;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareKey {
    pub model: String,
    pub serial_masked: String,
    pub piv_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity(pub String);

pub trait HardwareKeyProvider: Send + Sync {
    fn detect(&self) -> Result<Vec<HardwareKey>>;
    fn recipients(&self) -> Result<Vec<Recipient>>;
    fn decrypt(&self, identity: &Identity, envelope: &[u8]) -> Result<Secret>;
}

/// v1: no hardware support. Reports nothing detected.
pub struct NoneProvider;

impl HardwareKeyProvider for NoneProvider {
    fn detect(&self) -> Result<Vec<HardwareKey>> {
        Ok(Vec::new())
    }
    fn recipients(&self) -> Result<Vec<Recipient>> {
        Ok(Vec::new())
    }
    fn decrypt(&self, _identity: &Identity, _envelope: &[u8]) -> Result<Secret> {
        Err(crate::error::MossError::YubiKey(
            "YubiKey support is not available in this version.".into(),
        ))
    }
}

/// Test double with one fake key.
pub struct MockProvider {
    pub key: HardwareKey,
    pub secret: Secret,
}

impl HardwareKeyProvider for MockProvider {
    fn detect(&self) -> Result<Vec<HardwareKey>> {
        Ok(vec![self.key.clone()])
    }
    fn recipients(&self) -> Result<Vec<Recipient>> {
        Ok(vec![Recipient("age1yubikey1mock".into())])
    }
    fn decrypt(&self, _identity: &Identity, _envelope: &[u8]) -> Result<Secret> {
        Ok(self.secret.clone())
    }
}

pub fn provider() -> Box<dyn HardwareKeyProvider> {
    Box::new(NoneProvider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_round_trip() {
        let p = MockProvider {
            key: HardwareKey {
                model: "YubiKey 5".into(),
                serial_masked: "********".into(),
                piv_available: true,
            },
            secret: Secret::new("pw"),
        };
        assert_eq!(p.detect().unwrap().len(), 1);
        assert_eq!(
            p.decrypt(&Identity("x".into()), b"env").unwrap().expose(),
            "pw"
        );
        assert_eq!(NoneProvider.detect().unwrap().len(), 0);
        assert_eq!(
            NoneProvider
                .decrypt(&Identity("x".into()), b"")
                .unwrap_err()
                .exit_code()
                .code(),
            7
        );
    }
}
