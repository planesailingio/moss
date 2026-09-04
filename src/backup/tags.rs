//! Kopia snapshot tags that group one moss run (spec §19).
//!
//! Kopia splits `--tags` on the first colon and rejects duplicate keys, so the
//! keys use hyphens: `moss-run:<ulid>`.

use crate::platform::Platform;
use crate::profile::model::SemanticId;

pub const RUN: &str = "moss-run";
pub const PROFILE: &str = "moss-profile";
pub const SOURCE: &str = "moss-source";
pub const OS: &str = "moss-os";
pub const SCHEMA: &str = "moss-schema";
pub const MANIFEST_SOURCE: &str = "manifest";
pub const SCHEMA_VERSION: &str = "1";

pub fn new_run_id() -> String {
    ulid::Ulid::new().to_string()
}

/// Tags common to every snapshot in a run.
pub fn run_tags(run_id: &str, profile_identity: &str, platform: Platform) -> Vec<(String, String)> {
    vec![
        (RUN.into(), run_id.into()),
        (PROFILE.into(), sanitize(profile_identity)),
        (OS.into(), platform.tag_value().into()),
        (SCHEMA.into(), SCHEMA_VERSION.into()),
    ]
}

pub fn source_tag(id: &SemanticId) -> (String, String) {
    (SOURCE.into(), sanitize(id.as_str()))
}

/// Tag values must not contain colons (Kopia's separator) or whitespace.
pub fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c == ':' || c.is_whitespace() {
                '_'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_have_no_colons_in_keys_or_values() {
        let tags = run_tags("01ABC", "rhys: laptop", Platform::MacOs);
        for (k, v) in &tags {
            assert!(!k.contains(':'), "{k}");
            assert!(!v.contains(':'), "{v}");
        }
        assert_eq!(
            source_tag(&SemanticId::custom(std::path::Path::new("a b"))).1,
            "custom_a_b".replace("custom_", "custom:").replace(':', "_")
        );
    }

    #[test]
    fn run_ids_are_unique_and_sortable() {
        let a = new_run_id();
        let b = new_run_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 26);
    }
}
