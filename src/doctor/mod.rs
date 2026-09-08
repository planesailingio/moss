//! The environmental checks behind `moss doctor` (spec §7), as a library.
//!
//! Each check takes explicit inputs and appends to a [`Report`]; `cli/doctor`
//! wires them to the invocation and renders the result. Nothing here reads
//! the command line or prints.

use std::path::Path;

use serde::Serialize;

use crate::backup::kopia::{self, KopiaRunner};
use crate::backup::repository::Repository;
use crate::config::{CredentialStoreKind, MossPaths, RepositoryConfig, paths};
use crate::credentials::{self, CredentialStore};
use crate::error::ExitCode;
use crate::platform::tcc::{self, FdaStatus};
use crate::scan::index::ScanIndex;
use crate::security::secret::Secret;

/// A scan index older than this is reported stale.
pub const INDEX_STALE_AFTER_SECONDS: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub section: &'static str,
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
}

impl Check {
    fn new(
        status: CheckStatus,
        section: &'static str,
        name: &'static str,
        detail: impl Into<String>,
    ) -> Check {
        Check {
            section,
            name,
            status,
            detail: detail.into(),
            help: None,
        }
    }

    pub fn ok(section: &'static str, name: &'static str, detail: impl Into<String>) -> Check {
        Check::new(CheckStatus::Ok, section, name, detail)
    }

    pub fn warn(section: &'static str, name: &'static str, detail: impl Into<String>) -> Check {
        Check::new(CheckStatus::Warn, section, name, detail)
    }

    pub fn fail(section: &'static str, name: &'static str, detail: impl Into<String>) -> Check {
        Check::new(CheckStatus::Fail, section, name, detail)
    }

    pub fn skip(section: &'static str, name: &'static str, detail: impl Into<String>) -> Check {
        Check::new(CheckStatus::Skip, section, name, detail)
    }

    /// What to do about it; shown for warnings and failures.
    pub fn help(mut self, text: impl Into<String>) -> Check {
        self.help = Some(text.into());
        self
    }
}

/// Every check from one `doctor` run, in display order.
#[derive(Debug, Default)]
pub struct Report {
    checks: Vec<Check>,
}

impl Report {
    pub fn push(&mut self, check: Check) {
        self.checks.push(check);
    }

    pub fn checks(&self) -> &[Check] {
        &self.checks
    }

    /// No check failed (warnings and skips are fine).
    pub fn ok(&self) -> bool {
        self.checks.iter().all(|c| c.status != CheckStatus::Fail)
    }

    pub fn exit_code(&self) -> ExitCode {
        if self.ok() {
            ExitCode::Success
        } else {
            ExitCode::General
        }
    }
}

impl Serialize for Report {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("Report", 2)?;
        st.serialize_field("ok", &self.ok())?;
        st.serialize_field("checks", &self.checks)?;
        st.end()
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
}

/// Kopia on PATH and within the tested range. Returns the binary when found.
pub fn check_kopia(report: &mut Report) -> Option<std::path::PathBuf> {
    let bin =
        match kopia::find_binary() {
            Ok(bin) => bin,
            Err(_) => {
                report.push(Check::fail("Kopia", "found", "not on PATH").help(
                    "Install Kopia: https://kopia.io/docs/installation/ (brew install kopia)",
                ));
                return None;
            }
        };
    report.push(Check::ok("Kopia", "found", bin.display().to_string()));
    match kopia::version(&bin) {
        Ok(v) => {
            let detail = format!(
                "{}  (tested: {})",
                v.display(),
                kopia::version_range_display()
            );
            report.push(if v.in_tested_range() {
                Check::ok("Kopia", "version", detail)
            } else {
                Check::fail("Kopia", "version", detail)
                    .help("Install a tested Kopia, or use --skip-version-check.")
            });
        }
        Err(e) => report.push(Check::fail("Kopia", "version", e.to_string())),
    }
    Some(bin)
}

/// No repository in the configuration.
pub fn check_not_configured(report: &mut Report) {
    report.push(
        Check::warn("Repository", "configured", "no repository configured")
            .help("Run `moss init --repository <path or s3://bucket/prefix>`."),
    );
}

/// The password resolves (environment, then the store). Returns it when it does.
pub fn check_credentials(
    report: &mut Report,
    repo: &RepositoryConfig,
    store: &dyn CredentialStore,
) -> Option<Secret> {
    match credentials::resolve_password(store, &repo.id) {
        Ok((pw, source)) => {
            let detail = match source {
                credentials::CredentialSource::Environment => {
                    format!("environment ({})", credentials::ENV_PASSWORD)
                }
                credentials::CredentialSource::Keyring => store.name().to_string(),
            };
            report.push(Check::ok("Repository", "credentials", detail));
            Some(pw)
        }
        Err(e) => {
            report.push(
                Check::fail("Repository", "credentials", first_line(&e.to_string()))
                    .help(e.to_string()),
            );
            None
        }
    }
}

/// The keyring store is writable and unlocked (a sentinel round-trip).
/// Nothing is checked for the `env` store: there is nothing to probe.
pub fn check_store_probe(
    report: &mut Report,
    repo: &RepositoryConfig,
    store: &dyn CredentialStore,
) {
    if repo.credential_store != CredentialStoreKind::Keyring {
        return;
    }
    match store.probe() {
        Ok(()) => report.push(Check::ok(
            "Repository",
            "credential store",
            format!("{} writable and unlocked", store.name()),
        )),
        Err(e) => report.push(
            Check::fail("Repository", "credential store", first_line(&e.to_string())).help(
                "Scheduled runs need an unlockable store; see SECURITY.md for the MOSS_REPOSITORY_PASSWORD fallback.",
            ),
        ),
    }
}

/// The repository answers: `repository status` when already connected,
/// otherwise a connect.
pub fn check_reachable(
    report: &mut Report,
    runner: &dyn KopiaRunner,
    repo: &RepositoryConfig,
    password: &Secret,
) {
    let r = Repository::new(runner, repo, password);
    let reachable = if r.is_connected() {
        r.status().map(|_| ())
    } else {
        r.connect(None)
    };
    match reachable {
        Ok(()) => report.push(Check::ok("Repository", "reachable", repo.display_url())),
        Err(e) => report.push(
            Check::fail(
                "Repository",
                "reachable",
                format!("{} — {}", repo.display_url(), first_line(&e.to_string())),
            )
            .help(e.to_string()),
        ),
    }
}

/// Reachability could not be attempted.
pub fn check_reachable_skipped(report: &mut Report) {
    report.push(Check::skip(
        "Repository",
        "reachable",
        "not checked (no credentials or no Kopia)",
    ));
}

/// Kopia's config file is private (spec §5: it can hold S3 keys). Nothing is
/// reported when the file does not exist yet.
pub fn check_kopia_config_mode(report: &mut Report, config_file: &Path) {
    if !config_file.exists() {
        return;
    }
    let private = paths::mode_is_private(config_file, 0o600).unwrap_or(true);
    let detail = format!(
        "{} ({})",
        config_file.display(),
        if private { "0600" } else { "too permissive" }
    );
    report.push(if private {
        Check::ok("Repository", "kopia config", detail)
    } else {
        Check::fail("Repository", "kopia config", detail)
            .help("Fix with chmod 600; this file can hold S3 keys.")
    });
}

/// The recovery sheet has been acknowledged (spec §6 gate).
pub fn check_recovery_acknowledged(report: &mut Report, repo: &RepositoryConfig) {
    match repo.recovery_acknowledged_at {
        Some(t) => report.push(Check::ok(
            "Repository",
            "recovery",
            format!("acknowledged {}", t.format("%Y-%m-%d")),
        )),
        None => report.push(
            Check::fail("Repository", "recovery", "recovery sheet not acknowledged").help(
                "Run `moss init` again and confirm you stored the sheet; `moss backup` refuses until then.",
            ),
        ),
    }
}

/// Full Disk Access (macOS TCC) by probing a protected path under `home`.
pub fn check_full_disk_access(report: &mut Report, home: &Path) {
    match tcc::full_disk_access(home) {
        FdaStatus::Granted => report.push(Check::ok("Platform", "full disk access", "granted")),
        FdaStatus::Denied { probe } => report.push(
            Check::fail(
                "Platform",
                "full disk access",
                format!(
                    "NOT granted ({} is EPERM)",
                    crate::model::home_relative(&probe, home)
                ),
            )
            .help(format!(
                "~/Library/Mail and other protected paths will be skipped.\n{}",
                tcc::FDA_HELP
            )),
        ),
        FdaStatus::NotApplicable => report.push(Check::skip(
            "Platform",
            "full disk access",
            if cfg!(target_os = "macos") {
                "no protected path present to probe"
            } else {
                "not applicable"
            },
        )),
    }
}

/// Running outside a terminal on macOS: the terminal's TCC grant does not
/// apply (spec §32). No adapter equivalent exists yet, hence the cfg.
pub fn check_session(report: &mut Report, stdout_tty: bool) {
    #[cfg(target_os = "macos")]
    if std::env::var_os("XPC_SERVICE_NAME").is_some_and(|v| v.to_string_lossy().contains("launchd"))
        || std::env::var_os("TERM_PROGRAM").is_none() && !stdout_tty
    {
        report.push(
            Check::warn(
                "Platform",
                "session",
                "not running from a terminal; TCC grants of your terminal do not apply",
            )
            .help("A launchd job may capture less than an interactive run (spec §32)."),
        );
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (report, stdout_tty);
    }
}

/// moss's own directories can be created.
pub fn check_state_dir(report: &mut Report, paths: &MossPaths) {
    let detail = paths.state_dir.display().to_string();
    report.push(if paths.ensure().is_ok() {
        Check::ok("Platform", "state directory", detail)
    } else {
        Check::fail("Platform", "state directory", detail)
    });
}

/// YubiKey presence (informational until Phase 2).
pub fn check_yubikey(report: &mut Report) {
    let keys = crate::yubikey::provider().detect().unwrap_or_default();
    report.push(Check::skip(
        "YubiKey",
        "status",
        if keys.is_empty() {
            "not configured".to_string()
        } else {
            format!("{} detected", keys.len())
        },
    ));
}

/// Age of the scan index at `index_path`, relative to `now`.
pub fn check_scan_index(
    report: &mut Report,
    index_path: &Path,
    now: chrono::DateTime<chrono::Utc>,
) {
    let index = ScanIndex::load(index_path);
    match index.refreshed_at {
        Some(t) => {
            let age = (now - t).num_seconds();
            let fresh = age < INDEX_STALE_AFTER_SECONDS;
            let detail = format!(
                "last scanned {} ({} ago)",
                t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M"),
                crate::output::human::age(age)
            );
            report.push(if fresh {
                Check::ok("Scan index", "fresh", detail)
            } else {
                Check::warn("Scan index", "stale", detail)
            });
        }
        None => report
            .push(Check::warn("Scan index", "absent", "no scan yet").help("Run `moss inspect`.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_ok_and_exit_code_follow_failures() {
        let mut r = Report::default();
        r.push(Check::ok("A", "one", "fine"));
        r.push(Check::warn("A", "two", "meh").help("do x"));
        r.push(Check::skip("B", "three", "n/a"));
        assert!(r.ok());
        assert_eq!(r.exit_code(), ExitCode::Success);
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["checks"][1]["status"], "warn");
        assert_eq!(json["checks"][1]["help"], "do x");
        assert!(json["checks"][0].get("help").is_none());
        r.push(Check::fail("B", "four", "broken"));
        assert!(!r.ok());
        assert_eq!(r.exit_code(), ExitCode::General);
        assert_eq!(serde_json::to_value(&r).unwrap()["ok"], false);
    }

    #[cfg(unix)]
    #[test]
    fn kopia_config_mode_check() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("repo.config");

        let mut r = Report::default();
        check_kopia_config_mode(&mut r, &file);
        assert!(r.checks().is_empty(), "absent file reports nothing");

        std::fs::write(&file, "{}").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut r = Report::default();
        check_kopia_config_mode(&mut r, &file);
        assert_eq!(r.checks()[0].status, CheckStatus::Fail);
        assert!(r.checks()[0].detail.ends_with("(too permissive)"));
        assert!(r.checks()[0].help.as_deref().unwrap().contains("chmod 600"));

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut r = Report::default();
        check_kopia_config_mode(&mut r, &file);
        assert_eq!(r.checks()[0].status, CheckStatus::Ok);
        assert!(r.checks()[0].detail.ends_with("(0600)"));
    }

    #[test]
    fn scan_index_age_check() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("index.json");
        let now = chrono::Utc::now();

        let mut r = Report::default();
        check_scan_index(&mut r, &path, now);
        assert_eq!(r.checks()[0].name, "absent");
        assert_eq!(r.checks()[0].status, CheckStatus::Warn);
        assert!(r.checks()[0].help.is_some());

        let mut index = ScanIndex::load(&path);
        index.refreshed_at = Some(now - chrono::Duration::hours(1));
        index.save(&path).unwrap();
        let mut r = Report::default();
        check_scan_index(&mut r, &path, now);
        assert_eq!(r.checks()[0].name, "fresh");
        assert_eq!(r.checks()[0].status, CheckStatus::Ok);
        assert!(r.checks()[0].detail.contains("1 hour ago"));

        index.refreshed_at = Some(now - chrono::Duration::days(3));
        index.save(&path).unwrap();
        let mut r = Report::default();
        check_scan_index(&mut r, &path, now);
        assert_eq!(r.checks()[0].name, "stale");
        assert_eq!(r.checks()[0].status, CheckStatus::Warn);
        assert!(r.checks()[0].detail.contains("3 days ago"));
    }

    #[test]
    fn recovery_and_not_configured_checks() {
        let mut repo = crate::config::RepositoryConfig {
            kind: crate::config::RepositoryType::Filesystem,
            id: "x".into(),
            path: Some("/tmp/r".into()),
            bucket: None,
            prefix: None,
            endpoint: None,
            region: None,
            tls: None,
            credential_store: Default::default(),
            recovery_acknowledged_at: None,
            created_at: None,
            local: None,
        };
        let mut r = Report::default();
        check_recovery_acknowledged(&mut r, &repo);
        assert_eq!(r.checks()[0].status, CheckStatus::Fail);
        repo.recovery_acknowledged_at = Some(chrono::Utc::now());
        let mut r = Report::default();
        check_recovery_acknowledged(&mut r, &repo);
        assert_eq!(r.checks()[0].status, CheckStatus::Ok);
        assert!(r.checks()[0].detail.starts_with("acknowledged "));

        let mut r = Report::default();
        check_not_configured(&mut r);
        assert_eq!(r.checks()[0].status, CheckStatus::Warn);
        assert!(r.ok());
    }

    #[test]
    fn credentials_and_store_probe_with_mock() {
        use crate::credentials::mock::MockStore;
        if std::env::var_os(credentials::ENV_PASSWORD).is_some() {
            return;
        }
        let repo = crate::config::RepositoryConfig {
            kind: crate::config::RepositoryType::Filesystem,
            id: "repo".into(),
            path: Some("/tmp/r".into()),
            bucket: None,
            prefix: None,
            endpoint: None,
            region: None,
            tls: None,
            credential_store: CredentialStoreKind::Keyring,
            recovery_acknowledged_at: None,
            created_at: None,
            local: None,
        };
        let store = MockStore::with("repo", "pw");
        let mut r = Report::default();
        let pw = check_credentials(&mut r, &repo, &store);
        assert_eq!(pw.unwrap().expose(), "pw");
        assert_eq!(r.checks()[0].detail, "mock");
        check_store_probe(&mut r, &repo, &store);
        assert_eq!(r.checks()[1].status, CheckStatus::Ok);

        let empty = MockStore::default();
        let mut r = Report::default();
        assert!(check_credentials(&mut r, &repo, &empty).is_none());
        assert_eq!(r.checks()[0].status, CheckStatus::Fail);
    }
}
