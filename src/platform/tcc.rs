//! macOS Transparency, Consent and Control detection (spec §8).
//!
//! Apple's rule: `EACCES` is mode bits or ACL; `EPERM` is TCC, SIP or a Data
//! Vault. Never conflate the two. The probe attempts `opendir` on a path known
//! to require Full Disk Access and reads errno.

use std::path::{Path, PathBuf};

use crate::model::SkipReason;

/// Classify an io error from a directory read or file open.
pub fn classify_io_error(err: &std::io::Error) -> (SkipReason, Option<String>) {
    match err.raw_os_error() {
        Some(code) if code == eperm() => (SkipReason::PermissionDenied, Some("EPERM".into())),
        Some(code) if code == eacces() => (SkipReason::AccessDenied, Some("EACCES".into())),
        _ if err.kind() == std::io::ErrorKind::NotFound => (SkipReason::NotFound, None),
        _ if err.kind() == std::io::ErrorKind::PermissionDenied => (SkipReason::AccessDenied, None),
        Some(code) => (SkipReason::IoError, Some(format!("errno {code}"))),
        None => (SkipReason::IoError, None),
    }
}

#[cfg(unix)]
fn eperm() -> i32 {
    libc::EPERM
}
#[cfg(unix)]
fn eacces() -> i32 {
    libc::EACCES
}
#[cfg(not(unix))]
fn eperm() -> i32 {
    -1
}
#[cfg(not(unix))]
fn eacces() -> i32 {
    5 // ERROR_ACCESS_DENIED
}

/// Paths known to require Full Disk Access, by evidence strength (spec §8).
pub const FDA_PATHS: [(&str, &str); 8] = [
    ("Library/Mail", "Apple DTS"),
    ("Library/Safari", "well corroborated"),
    ("Library/Messages", "well corroborated"),
    (
        "Library/Application Support/AddressBook",
        "well corroborated",
    ),
    ("Library/Calendars", "well corroborated"),
    ("Library/Cookies", "well corroborated"),
    ("Library/Containers", "well corroborated"),
    ("Library/Suggestions", "unverified"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdaStatus {
    Granted,
    Denied {
        probe: PathBuf,
    },
    /// Not macOS, or no probe path exists.
    NotApplicable,
}

/// Probe Full Disk Access by attempting to read a TCC-protected directory.
pub fn full_disk_access(home: &Path) -> FdaStatus {
    if !cfg!(target_os = "macos") {
        return FdaStatus::NotApplicable;
    }
    for (rel, _) in FDA_PATHS.iter().take(3) {
        let p = home.join(rel);
        if !p.exists() {
            continue;
        }
        match std::fs::read_dir(&p) {
            Ok(_) => return FdaStatus::Granted,
            Err(e) if e.raw_os_error() == Some(eperm()) => return FdaStatus::Denied { probe: p },
            Err(_) => continue,
        }
    }
    FdaStatus::NotApplicable
}

pub const FDA_HELP: &str = "Grant Full Disk Access to your terminal application in\nSystem Settings → Privacy & Security → Full Disk Access.\nGranting it to the moss binary itself does not work: TCC keys on the\nresponsible process, which is the terminal. Scheduled (launchd) runs\ndo not inherit the terminal's grant.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eperm_and_eacces_are_distinct() {
        #[cfg(unix)]
        {
            let eperm_err = std::io::Error::from_raw_os_error(libc::EPERM);
            let eacces_err = std::io::Error::from_raw_os_error(libc::EACCES);
            assert_eq!(
                classify_io_error(&eperm_err).0,
                SkipReason::PermissionDenied
            );
            assert_eq!(classify_io_error(&eacces_err).0, SkipReason::AccessDenied);
        }
        let nf = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        assert_eq!(classify_io_error(&nf).0, SkipReason::NotFound);
    }
}
