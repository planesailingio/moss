//! Metadata-based sensitive-file classification (spec §14).
//!
//! Path, filename and extension only. File contents are never read.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveKind {
    SshPrivateKey,
    AwsCredentials,
    GpgPrivateKey,
    KubernetesCredentials,
    DockerCredentials,
    CloudProviderCredentials,
    GitCredentials,
    PasswordManagerExport,
    ApiToken,
    DotEnv,
    CredentialCache,
    TlsPrivateKey,
}

impl SensitiveKind {
    pub fn display_name(self) -> &'static str {
        match self {
            SensitiveKind::SshPrivateKey => "SSH",
            SensitiveKind::AwsCredentials => "AWS",
            SensitiveKind::GpgPrivateKey => "GPG",
            SensitiveKind::KubernetesCredentials => "Kubernetes",
            SensitiveKind::DockerCredentials => "Docker",
            SensitiveKind::CloudProviderCredentials => "Cloud provider",
            SensitiveKind::GitCredentials => "Git credentials",
            SensitiveKind::PasswordManagerExport => "Password manager export",
            SensitiveKind::ApiToken => "API tokens",
            SensitiveKind::DotEnv => ".env files",
            SensitiveKind::CredentialCache => "Credential caches",
            SensitiveKind::TlsPrivateKey => "TLS private keys",
        }
    }
}

/// Classify a path relative to the home directory (forward slashes).
pub fn classify(home_relative: &str) -> Option<SensitiveKind> {
    let rel = home_relative
        .trim_start_matches("~/")
        .trim_start_matches('/');
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let lower = name.to_ascii_lowercase();
    let first = rel.split('/').next().unwrap_or("");

    // Directory-scoped rules.
    match first {
        ".ssh" => {
            if is_ssh_private_key(name) {
                return Some(SensitiveKind::SshPrivateKey);
            }
        }
        ".aws" => {
            if lower == "credentials" || lower.starts_with("credentials.") {
                return Some(SensitiveKind::AwsCredentials);
            }
        }
        ".gnupg" => {
            if rel.starts_with(".gnupg/private-keys-v1.d")
                || lower == "secring.gpg"
                || lower.ends_with(".key")
            {
                return Some(SensitiveKind::GpgPrivateKey);
            }
        }
        ".kube" => {
            if lower == "config"
                || lower.ends_with(".kubeconfig")
                || lower.ends_with(".yaml") && rel.contains("/cache/")
            {
                return Some(SensitiveKind::KubernetesCredentials);
            }
        }
        ".docker" => {
            if lower == "config.json" {
                return Some(SensitiveKind::DockerCredentials);
            }
        }
        ".azure" | ".config"
            if (rel.starts_with(".azure/") || rel.starts_with(".config/gcloud/"))
                && (lower.contains("token")
                    || lower.contains("credential")
                    || lower == "accesstokens.json") =>
        {
            return Some(SensitiveKind::CloudProviderCredentials);
        }
        _ => {}
    }

    // Name-based rules anywhere.
    if lower == ".git-credentials" || lower == "git-credentials" {
        return Some(SensitiveKind::GitCredentials);
    }
    if lower == ".netrc" || lower == "_netrc" || lower == ".npmrc" && false {
        return Some(SensitiveKind::ApiToken);
    }
    if lower == ".env"
        || lower.starts_with(".env.") && !lower.ends_with(".example") && !lower.ends_with(".sample")
    {
        return Some(SensitiveKind::DotEnv);
    }
    if lower.ends_with(".1pux")
        || lower.ends_with(".opvault")
        || lower.ends_with(".kdbx")
        || lower.ends_with(".agilekeychain")
    {
        return Some(SensitiveKind::PasswordManagerExport);
    }
    if lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.ends_with(".p12")
        || lower.ends_with(".pfx")
    {
        if lower.contains("pub") || lower.ends_with(".pub.pem") {
            return None;
        }
        return Some(SensitiveKind::TlsPrivateKey);
    }
    if lower == ".npmrc"
        || lower == ".pypirc"
        || lower == ".gem/credentials"
        || lower.ends_with("/credentials") && rel.starts_with(".gem")
    {
        return Some(SensitiveKind::ApiToken);
    }
    if lower.contains("token")
        && (lower.ends_with(".json") || lower.ends_with(".txt") || lower.ends_with(".yaml"))
        && !rel.contains("node_modules")
    {
        return Some(SensitiveKind::ApiToken);
    }
    if lower == "credentials.json"
        || lower == "client_secret.json"
        || lower.starts_with("client_secret_") && lower.ends_with(".json")
    {
        return Some(SensitiveKind::CloudProviderCredentials);
    }
    if rel.starts_with(".terraform.d/") && lower == "credentials.tfrc.json" {
        return Some(SensitiveKind::ApiToken);
    }
    if lower == "krb5cc" || lower.starts_with("krb5cc_") || lower == ".aws/sso/cache" {
        return Some(SensitiveKind::CredentialCache);
    }
    None
}

fn is_ssh_private_key(name: &str) -> bool {
    if name.ends_with(".pub") {
        return false;
    }
    matches!(
        name,
        "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519" | "id_ecdsa_sk" | "id_ed25519_sk"
    ) || name.starts_with("id_") && !name.contains('.')
        || name.ends_with(".pem")
        || name.ends_with(".key")
}

/// Whether a whole source directory is a credentials source (spec §9 `sensitive`).
pub fn is_sensitive_source(home_relative: &str) -> bool {
    matches!(
        home_relative.trim_start_matches("~/"),
        ".ssh"
            | ".aws"
            | ".gnupg"
            | ".kube"
            | ".docker"
            | ".azure"
            | ".config/gcloud"
            | ".terraform.d"
    )
}

pub fn classify_path(path: &Path, home: &Path) -> Option<SensitiveKind> {
    let rel = crate::profile::model::home_relative(path, home);
    classify(&rel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_keys() {
        assert_eq!(
            classify("~/.ssh/id_ed25519"),
            Some(SensitiveKind::SshPrivateKey)
        );
        assert_eq!(classify("~/.ssh/id_ed25519.pub"), None);
        assert_eq!(classify("~/.ssh/config"), None);
        assert_eq!(classify("~/.ssh/known_hosts"), None);
        assert_eq!(
            classify("~/.ssh/work.pem"),
            Some(SensitiveKind::SshPrivateKey)
        );
    }

    #[test]
    fn cloud_and_containers() {
        assert_eq!(
            classify("~/.aws/credentials"),
            Some(SensitiveKind::AwsCredentials)
        );
        assert_eq!(classify("~/.aws/config"), None);
        assert_eq!(
            classify("~/.kube/config"),
            Some(SensitiveKind::KubernetesCredentials)
        );
        assert_eq!(
            classify("~/.docker/config.json"),
            Some(SensitiveKind::DockerCredentials)
        );
        assert_eq!(
            classify("~/.gnupg/private-keys-v1.d/abc.key"),
            Some(SensitiveKind::GpgPrivateKey)
        );
        assert_eq!(classify("~/.gnupg/pubring.kbx"), None);
    }

    #[test]
    fn anywhere_rules() {
        assert_eq!(classify("~/git/app/.env"), Some(SensitiveKind::DotEnv));
        assert_eq!(
            classify("~/git/app/.env.local"),
            Some(SensitiveKind::DotEnv)
        );
        assert_eq!(classify("~/git/app/.env.example"), None);
        assert_eq!(
            classify("~/certs/server.key"),
            Some(SensitiveKind::TlsPrivateKey)
        );
        assert_eq!(classify("~/certs/server.pub.pem"), None);
        assert_eq!(
            classify("~/.git-credentials"),
            Some(SensitiveKind::GitCredentials)
        );
        assert_eq!(classify("~/.npmrc"), Some(SensitiveKind::ApiToken));
        assert_eq!(
            classify("~/Downloads/export.1pux"),
            Some(SensitiveKind::PasswordManagerExport)
        );
        assert_eq!(classify("~/Documents/notes.txt"), None);
    }

    #[test]
    fn sensitive_sources() {
        assert!(is_sensitive_source("~/.ssh"));
        assert!(!is_sensitive_source("~/Documents"));
    }
}
