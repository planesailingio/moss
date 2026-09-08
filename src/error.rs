//! Typed errors and the exit-code contract (spec §23).
//!
//! Every failure that reaches `main` is a [`MossError`]; `main` maps it to an
//! [`ExitCode`] and prints a §37-style message. Kopia's own exit code is never
//! propagated: it carries almost no information (spec §18).

use std::fmt;
use std::path::{Path, PathBuf};

/// Process exit codes. Stable within a major version (spec §23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    Success = 0,
    General = 1,
    Usage = 2,
    RepositoryUnavailable = 3,
    AuthFailure = 4,
    RestoreConflict = 5,
    SensitiveRefusal = 6,
    YubiKeyUnavailable = 7,
    Integrity = 8,
    PartialSuccess = 9,
    AlreadyRunning = 10,
    KopiaNotFound = 11,
    KopiaVersion = 12,
    InteractionRequired = 13,
}

impl ExitCode {
    pub fn code(self) -> i32 {
        self as u8 as i32
    }

    pub fn description(self) -> &'static str {
        match self {
            ExitCode::Success => "success",
            ExitCode::General => "general failure",
            ExitCode::Usage => "invalid CLI usage",
            ExitCode::RepositoryUnavailable => "repository unavailable",
            ExitCode::AuthFailure => "authentication failure",
            ExitCode::RestoreConflict => "restore conflict",
            ExitCode::SensitiveRefusal => "sensitive-data safety refusal",
            ExitCode::YubiKeyUnavailable => "YubiKey unavailable",
            ExitCode::Integrity => "integrity/verification failure",
            ExitCode::PartialSuccess => "partial success — completed with skipped files",
            ExitCode::AlreadyRunning => "already running — another moss holds the lock",
            ExitCode::KopiaNotFound => "Kopia not found",
            ExitCode::KopiaVersion => "Kopia version incompatible",
            ExitCode::InteractionRequired => "interaction required under --non-interactive",
        }
    }

    pub const ALL: [ExitCode; 14] = [
        ExitCode::Success,
        ExitCode::General,
        ExitCode::Usage,
        ExitCode::RepositoryUnavailable,
        ExitCode::AuthFailure,
        ExitCode::RestoreConflict,
        ExitCode::SensitiveRefusal,
        ExitCode::YubiKeyUnavailable,
        ExitCode::Integrity,
        ExitCode::PartialSuccess,
        ExitCode::AlreadyRunning,
        ExitCode::KopiaNotFound,
        ExitCode::KopiaVersion,
        ExitCode::InteractionRequired,
    ];
}

/// The single error type that crosses module boundaries.
///
/// Messages are written for the user (spec §37): what happened and what to do
/// next. Raw Kopia text is only attached under `--verbose` via `detail`.
#[derive(Debug, thiserror::Error)]
pub enum MossError {
    #[error("{0}")]
    Usage(String),

    #[error(
        "Kopia was not found on PATH.\n\nInstall it from https://kopia.io/docs/installation/ (Homebrew: `brew install kopia`) and run `moss doctor`."
    )]
    KopiaNotFound,

    #[error(
        "Kopia {found} is outside the tested range {min} – {max}.\n\nInstall a tested version, or pass --skip-version-check to proceed at your own risk."
    )]
    KopiaVersion {
        found: String,
        min: String,
        max: String,
    },

    #[error(
        "Unable to reach the repository.\n\n{context}\n\nCheck:\n  - the path or endpoint\n  - bucket permissions\n  - network connectivity\n\nRun `moss doctor` for a full diagnostic, or --verbose for details."
    )]
    RepositoryUnreachable { context: String },

    #[error(
        "No repository is initialised at this location.\n\n{context}\n\nRun `moss init` to create one, or check the repository path in your configuration."
    )]
    RepositoryNotInitialised { context: String },

    #[error(
        "The repository rejected the credentials.\n\n{context}\n\nThe stored password does not open this repository. Run `moss recovery show` to check which repository this machine is configured for, or `moss init` with the recovery code from your sheet."
    )]
    AuthFailure { context: String },

    #[error(
        "A repository already exists at this location.\n\n{context}\n\nTo connect this machine to it, run `moss init` again and enter the recovery code from your sheet."
    )]
    RepositoryExists { context: String },

    #[error("No repository is configured.\n\nRun `moss init` first.")]
    NotConfigured,

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("{0}")]
    Credential(String),

    #[error(
        "Another moss process holds the lock (pid {pid}, started {started}).\n\nWait for it to finish, or remove {path} if that process is gone."
    )]
    AlreadyRunning {
        pid: u32,
        started: String,
        path: PathBuf,
    },

    #[error(
        "{0}\n\nRe-run interactively, or supply the flag that answers this question (see --help)."
    )]
    InteractionRequired(String),

    #[error("{0}")]
    SensitiveRefusal(String),

    #[error("{0}")]
    Integrity(String),

    #[error("{0}")]
    YubiKey(String),

    #[error("{message}")]
    Kopia {
        message: String,
        /// Raw stderr; shown only under --verbose.
        detail: String,
    },

    #[error("{0}")]
    Other(String),

    /// An I/O failure, with the path when the call site knew it (`IoAt::at`).
    #[error("{}", io_message(path.as_deref(), source))]
    Io {
        path: Option<PathBuf>,
        #[source]
        source: std::io::Error,
    },
}

fn io_message(path: Option<&Path>, source: &std::io::Error) -> String {
    match path {
        Some(p) => format!("{}: {source}", p.display()),
        None => source.to_string(),
    }
}

impl From<std::io::Error> for MossError {
    fn from(source: std::io::Error) -> Self {
        MossError::Io { path: None, source }
    }
}

/// Attach the path to an I/O result: `std::fs::write(&p, ..).at(&p)?`. A bare
/// `?` still works and yields a message without the path.
pub trait IoAt<T> {
    fn at(self, path: &Path) -> Result<T>;
}

impl<T> IoAt<T> for std::io::Result<T> {
    fn at(self, path: &Path) -> Result<T> {
        self.map_err(|source| MossError::Io {
            path: Some(path.to_path_buf()),
            source,
        })
    }
}

impl MossError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            MossError::Usage(_) => ExitCode::Usage,
            MossError::KopiaNotFound => ExitCode::KopiaNotFound,
            MossError::KopiaVersion { .. } => ExitCode::KopiaVersion,
            MossError::RepositoryUnreachable { .. }
            | MossError::RepositoryNotInitialised { .. }
            | MossError::RepositoryExists { .. }
            | MossError::NotConfigured => ExitCode::RepositoryUnavailable,
            MossError::AuthFailure { .. } => ExitCode::AuthFailure,
            MossError::Config(_) | MossError::Credential(_) => ExitCode::General,
            MossError::AlreadyRunning { .. } => ExitCode::AlreadyRunning,
            MossError::InteractionRequired(_) => ExitCode::InteractionRequired,
            MossError::SensitiveRefusal(_) => ExitCode::SensitiveRefusal,
            MossError::Integrity(_) => ExitCode::Integrity,
            MossError::YubiKey(_) => ExitCode::YubiKeyUnavailable,
            MossError::Kopia { .. } | MossError::Other(_) | MossError::Io { .. } => {
                ExitCode::General
            }
        }
    }

    /// Detail that is safe to show under `--verbose` only.
    pub fn verbose_detail(&self) -> Option<&str> {
        match self {
            MossError::Kopia { detail, .. } if !detail.is_empty() => Some(detail),
            _ => None,
        }
    }

    pub fn other(msg: impl fmt::Display) -> Self {
        MossError::Other(msg.to_string())
    }
}

impl From<serde_json::Error> for MossError {
    fn from(e: serde_json::Error) -> Self {
        MossError::Other(format!("JSON error: {e}"))
    }
}

impl From<serde_yaml_ng::Error> for MossError {
    fn from(e: serde_yaml_ng::Error) -> Self {
        MossError::Config(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, MossError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_spec_table() {
        let expected: Vec<(i32, &str)> = vec![
            (0, "success"),
            (1, "general failure"),
            (2, "invalid CLI usage"),
            (3, "repository unavailable"),
            (4, "authentication failure"),
            (5, "restore conflict"),
            (6, "sensitive-data safety refusal"),
            (7, "YubiKey unavailable"),
            (8, "integrity/verification failure"),
            (9, "partial success — completed with skipped files"),
            (10, "already running — another moss holds the lock"),
            (11, "Kopia not found"),
            (12, "Kopia version incompatible"),
            (13, "interaction required under --non-interactive"),
        ];
        for (code, desc) in expected {
            let found = ExitCode::ALL.iter().find(|c| c.code() == code).unwrap();
            assert_eq!(found.description(), desc);
        }
    }

    #[test]
    fn errors_map_to_codes() {
        assert_eq!(
            MossError::KopiaNotFound.exit_code(),
            ExitCode::KopiaNotFound
        );
        assert_eq!(
            MossError::AuthFailure {
                context: String::new()
            }
            .exit_code(),
            ExitCode::AuthFailure
        );
        assert_eq!(
            MossError::InteractionRequired(String::new())
                .exit_code()
                .code(),
            13
        );
    }

    #[test]
    fn io_errors_name_the_path_when_known() {
        let bare: MossError = std::io::Error::from(std::io::ErrorKind::PermissionDenied).into();
        assert!(!bare.to_string().contains('/'));
        let err =
            std::io::Result::<()>::Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                .at(Path::new("/x/state/index.json"))
                .unwrap_err();
        assert!(
            err.to_string().starts_with("/x/state/index.json: "),
            "{err}"
        );
        assert_eq!(err.exit_code(), ExitCode::General);
    }
}
