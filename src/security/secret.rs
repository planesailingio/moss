//! Secret values that cannot leak through `Debug` or `Display` (spec §34).

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// A secret string. Zeroised on drop; formats as `[redacted]`.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(Zeroizing::new(value.into()))
    }

    /// Expose the secret. Callers must not log or persist the result.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time enough for our purposes: secrets are compared only in
        // tests and during recovery-code validation, never against attacker
        // input at scale.
        let a = self.0.as_bytes();
        let b = other.0.as_bytes();
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_redact() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s:?}"), "Secret([redacted])");
        assert_eq!(format!("{s}"), "[redacted]");
        assert!(!format!("{s:?}{s}").contains("hunter2"));
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn equality() {
        assert_eq!(Secret::new("a"), Secret::new("a"));
        assert_ne!(Secret::new("a"), Secret::new("b"));
        assert_ne!(Secret::new("a"), Secret::new("aa"));
    }
}
