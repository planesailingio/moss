//! Hardware-key abstraction (spec §36). Phase 2 implements it with
//! age-plugin-yubikey; v1 ships the detection half of the trait, a mock, and
//! honest "not configured" answers so the rest of the application never
//! learns about PC/SC. Recipients and decryption arrive with the real
//! implementation rather than as unused surface now.

use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareKey {
    pub model: String,
    pub serial_masked: String,
    pub piv_available: bool,
}

pub trait HardwareKeyProvider {
    fn detect(&self) -> Result<Vec<HardwareKey>>;
}

/// v1: no hardware support. Reports nothing detected.
pub struct NoneProvider;

impl HardwareKeyProvider for NoneProvider {
    fn detect(&self) -> Result<Vec<HardwareKey>> {
        Ok(Vec::new())
    }
}

/// The provider for this build: v1 has none.
pub fn provider() -> Box<dyn HardwareKeyProvider> {
    Box::new(NoneProvider)
}

/// Test double with one fake key.
pub struct MockProvider {
    pub key: HardwareKey,
}

impl HardwareKeyProvider for MockProvider {
    fn detect(&self) -> Result<Vec<HardwareKey>> {
        Ok(vec![self.key.clone()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_provider_detects_nothing() {
        assert!(NoneProvider.detect().unwrap().is_empty());
        let mock = MockProvider {
            key: HardwareKey {
                model: "YubiKey 5".into(),
                serial_masked: "***1234".into(),
                piv_available: true,
            },
        };
        assert_eq!(mock.detect().unwrap().len(), 1);
    }
}
