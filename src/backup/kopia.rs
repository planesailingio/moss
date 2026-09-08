//! The Kopia subprocess runner (spec §5 "Kopia process hygiene").
//!
//! One function builds every command line and child environment. The parent
//! environment is never copied wholesale; the password reaches the child via
//! `KOPIA_PASSWORD` only and is zeroised after spawn.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

use crate::config::MossPaths;
use crate::error::{MossError, Result};
use crate::security::secret::Secret;

/// Tested Kopia range (spec §5). Update both together with the fixtures.
pub const KOPIA_MIN: (u64, u64, u64) = (0, 23, 0);
pub const KOPIA_MAX_MINOR: (u64, u64) = (0, 23);

pub fn version_range_display() -> String {
    format!(
        "{}.{}.{} – {}.{}.x",
        KOPIA_MIN.0, KOPIA_MIN.1, KOPIA_MIN.2, KOPIA_MAX_MINOR.0, KOPIA_MAX_MINOR.1
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KopiaVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub raw: String,
}

impl KopiaVersion {
    pub fn parse(output: &str) -> Option<KopiaVersion> {
        // "0.23.1 build: 72ec08f... from: ..."
        let first = output.split_whitespace().next()?;
        let first = first.trim_start_matches('v');
        let mut parts = first.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts
            .next()
            .map(|p| {
                p.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
            })
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        Some(KopiaVersion {
            major,
            minor,
            patch,
            raw: first.to_string(),
        })
    }

    pub fn in_tested_range(&self) -> bool {
        let v = (self.major, self.minor, self.patch);
        v >= KOPIA_MIN && (self.major, self.minor) <= KOPIA_MAX_MINOR
    }

    pub fn display(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Where Kopia's per-invocation state goes.
#[derive(Debug, Clone)]
pub struct KopiaContext {
    pub binary: PathBuf,
    pub config_file: PathBuf,
    pub cache_dir: PathBuf,
    pub log_dir: PathBuf,
    pub verbose: bool,
    pub skip_version_check: bool,
}

#[derive(Debug)]
pub struct KopiaOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl KopiaOutput {
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }
}

static VERSION: OnceLock<std::result::Result<KopiaVersion, String>> = OnceLock::new();

/// Locate the Kopia binary. `MOSS_KOPIA` overrides PATH lookup.
pub fn find_binary() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("MOSS_KOPIA").filter(|s| !s.is_empty()) {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        return Err(MossError::KopiaNotFound);
    }
    if let Ok(p) = which::which("kopia") {
        return Ok(p);
    }
    // `which` resolves a bare name on Windows via PATHEXT; a sparse
    // environment (no PATHEXT) would otherwise miss `kopia.exe` on PATH.
    #[cfg(windows)]
    if let Ok(p) = which::which("kopia.exe") {
        return Ok(p);
    }
    Err(MossError::KopiaNotFound)
}

/// Probe `kopia --version` once per process.
pub fn version(binary: &Path) -> Result<KopiaVersion> {
    let cached = VERSION.get_or_init(|| {
        let out = Command::new(binary)
            .arg("--version")
            .env_clear()
            .envs(base_env())
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run kopia: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        KopiaVersion::parse(&text)
            .ok_or_else(|| format!("unrecognised `kopia --version` output: {}", text.trim()))
    });
    match cached {
        Ok(v) => Ok(v.clone()),
        Err(e) => Err(MossError::Kopia {
            message: "Kopia was found but `kopia --version` failed.".into(),
            detail: e.clone(),
        }),
    }
}

pub fn check_version(binary: &Path, skip: bool) -> Result<KopiaVersion> {
    let v = version(binary)?;
    if !skip && !v.in_tested_range() {
        return Err(MossError::KopiaVersion {
            found: v.display(),
            min: format!("{}.{}.{}", KOPIA_MIN.0, KOPIA_MIN.1, KOPIA_MIN.2),
            max: format!("{}.{}.x", KOPIA_MAX_MINOR.0, KOPIA_MAX_MINOR.1),
        });
    }
    Ok(v)
}

/// Environment allowlist (spec §5). Everything else from the parent is dropped.
fn base_env() -> Vec<(OsString, OsString)> {
    const PASS: [&str; 14] = [
        "PATH",
        "HOME",
        "USERPROFILE",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LANG",
        "LC_ALL",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    ];
    let mut env: Vec<(OsString, OsString)> = PASS
        .iter()
        .filter_map(|k| std::env::var_os(k).map(|v| (OsString::from(k), v)))
        .collect();
    #[cfg(windows)]
    {
        for k in [
            "SYSTEMROOT",
            "SystemRoot",
            "APPDATA",
            "LOCALAPPDATA",
            "COMSPEC",
        ] {
            if let Some(v) = std::env::var_os(k) {
                env.push((OsString::from(k), v));
            }
        }
    }
    env.push(("KOPIA_CHECK_FOR_UPDATES".into(), "false".into()));
    env
}

impl KopiaContext {
    pub fn new(
        paths: &MossPaths,
        repo_id: &str,
        verbose: bool,
        skip_version_check: bool,
    ) -> Result<KopiaContext> {
        Ok(KopiaContext {
            binary: find_binary()?,
            config_file: paths.kopia_config(repo_id),
            cache_dir: paths.kopia_cache(),
            log_dir: paths.kopia_logs(),
            verbose,
            skip_version_check,
        })
    }

    pub fn prepare_dirs(&self) -> Result<()> {
        if let Some(d) = self.config_file.parent() {
            crate::config::paths::create_private_dir(d)?;
        }
        crate::config::paths::create_private_dir(&self.cache_dir)?;
        crate::config::paths::create_private_dir(&self.log_dir)?;
        Ok(())
    }

    /// Build the command with moss's standard flags. `connect` adds the
    /// create/connect-only flags.
    fn command(&self, args: &[&OsStr], connect: bool) -> Command {
        let mut cmd = Command::new(&self.binary);
        cmd.env_clear();
        cmd.envs(base_env());
        cmd.arg(format!("--config-file={}", self.config_file.display()));
        if self.verbose {
            cmd.arg(format!("--log-dir={}", self.log_dir.display()));
        } else {
            cmd.arg("--disable-file-logging");
        }
        cmd.arg("--no-progress");
        // Kopia's own persistence is never used (spec §6). The keychain flag
        // only exists in the macOS build of Kopia; Linux and Windows reject it.
        cmd.arg("--no-persist-credentials");
        if cfg!(target_os = "macos") {
            cmd.arg("--no-use-keychain");
        }
        cmd.args(args);
        if connect {
            cmd.arg("--no-check-for-updates");
            cmd.arg(format!("--cache-directory={}", self.cache_dir.display()));
        }
        cmd.stdin(Stdio::null());
        cmd
    }

    /// Run a repository command with the password in the child environment.
    pub fn run(
        &self,
        password: &Secret,
        args: &[&str],
        extra_env: &[(&str, &Secret)],
    ) -> Result<KopiaOutput> {
        self.run_inner(Some(password), args, extra_env, false)
    }

    /// `repository create|connect` (adds cache-directory and update-check flags).
    pub fn run_connect(
        &self,
        password: &Secret,
        args: &[&str],
        extra_env: &[(&str, &Secret)],
    ) -> Result<KopiaOutput> {
        self.run_inner(Some(password), args, extra_env, true)
    }

    /// Commands that need no repository password.
    pub fn run_plain(&self, args: &[&str]) -> Result<KopiaOutput> {
        self.run_inner(None, args, &[], false)
    }

    fn run_inner(
        &self,
        password: Option<&Secret>,
        args: &[&str],
        extra_env: &[(&str, &Secret)],
        connect: bool,
    ) -> Result<KopiaOutput> {
        check_version(&self.binary, self.skip_version_check)?;
        let os_args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        let mut cmd = self.command(&os_args, connect);
        if let Some(p) = password {
            cmd.env("KOPIA_PASSWORD", p.expose());
        }
        for (k, v) in extra_env {
            cmd.env(k, v.expose());
        }
        tracing::debug!(args = ?redact_args(args), "running kopia");
        let out: Output = cmd.output().map_err(|e| MossError::Kopia {
            message: "Failed to start Kopia.".into(),
            detail: e.to_string(),
        })?;
        // The Command (and its copy of the password) drops here.
        drop(cmd);
        Ok(KopiaOutput {
            status: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// Arguments are never secret by construction (no --password, no keys), but
/// keep the log line short.
fn redact_args(args: &[&str]) -> Vec<String> {
    args.iter()
        .map(|a| {
            if a.starts_with("--secret-access-key")
                || a.starts_with("--access-key")
                || a.starts_with("--session-token")
            {
                "[redacted]".to_string()
            } else {
                a.to_string()
            }
        })
        .collect()
}

/// Which Kopia verb failed. A missing path means "no repository here" when
/// connecting or creating, but "the source directory is gone" during a
/// snapshot; the classifier must know which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KopiaOp {
    Connect,
    Create,
    Snapshot,
    Other,
}

/// Translate Kopia stderr into a typed error (spec §37). Raw text goes to
/// `detail`, shown only under --verbose.
pub fn classify_failure(out: &KopiaOutput, context: &str, op: KopiaOp) -> MossError {
    let err = out.stderr.to_ascii_lowercase();
    let detail = out.stderr.trim().to_string();
    let storage_missing =
        err.contains("no such file or directory") || err.contains("cannot access storage path");
    if storage_missing && op == KopiaOp::Snapshot {
        return MossError::Kopia {
            message: format!(
                "A source path could not be read while taking the snapshot. {context}"
            ),
            detail,
        };
    }
    if err.contains("invalid repository password") || err.contains("invalid password") {
        return MossError::AuthFailure {
            context: context.to_string(),
        };
    }
    if err.contains("found existing data in storage location") {
        return MossError::RepositoryExists {
            context: context.to_string(),
        };
    }
    if err.contains("repository not initialized")
        || err.contains("not a kopia repository")
        || err.contains("kopia.repository")
        || (storage_missing && matches!(op, KopiaOp::Connect | KopiaOp::Create))
    {
        return MossError::RepositoryNotInitialised {
            context: context.to_string(),
        };
    }
    if err.contains("not connected to a repository")
        || err.contains("open repository")
        || err.contains("unable to open repository")
    {
        return MossError::RepositoryUnreachable {
            context: context.to_string(),
        };
    }
    if err.contains("access denied")
        || err.contains("accessdenied")
        || err.contains("invalidaccesskeyid")
        || err.contains("signaturedoesnotmatch")
        || err.contains("403")
    {
        return MossError::AuthFailure {
            context: format!("{context}\n\nThe storage provider rejected the S3 credentials."),
        };
    }
    if err.contains("connection refused")
        || err.contains("no such host")
        || err.contains("timeout")
        || err.contains("i/o timeout")
        || err.contains("network is unreachable")
        || err.contains("tls")
    {
        return MossError::RepositoryUnreachable {
            context: context.to_string(),
        };
    }
    MossError::Kopia {
        message: format!(
            "Kopia reported an error.\n\n{context}\n\nRun with --verbose to see Kopia's output."
        ),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing() {
        let v = KopiaVersion::parse("0.23.1 build: 72ec08fd8edb from:").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (0, 23, 1));
        assert!(v.in_tested_range());
        let old = KopiaVersion::parse("0.17.0").unwrap();
        assert!(!old.in_tested_range());
        let newer = KopiaVersion::parse("0.24.0").unwrap();
        assert!(!newer.in_tested_range());
        assert!(KopiaVersion::parse("garbage").is_none());
        assert_eq!(version_range_display(), "0.23.0 – 0.23.x");
    }

    #[test]
    fn failure_classification() {
        let out = |stderr: &str| KopiaOutput {
            status: Some(1),
            stdout: String::new(),
            stderr: stderr.into(),
        };
        assert_eq!(
            classify_failure(
                &out("failed to open repository: invalid repository password"),
                "x",
                KopiaOp::Connect
            )
            .exit_code()
            .code(),
            4
        );
        assert_eq!(
            classify_failure(&out("can't connect to storage: cannot access storage path: stat /x: no such file or directory"), "x", KopiaOp::Connect)
                .exit_code()
                .code(),
            3
        );
        // The same text during a snapshot means the *source* vanished, not
        // that the repository is missing.
        let gone = classify_failure(
            &out("error: lstat /Users/x/Downloads: no such file or directory"),
            "x",
            KopiaOp::Snapshot,
        );
        assert_eq!(gone.exit_code().code(), 1);
        assert!(gone.to_string().contains("source path"), "{gone}");
        assert_eq!(
            classify_failure(&out("dial tcp: connection refused"), "x", KopiaOp::Connect)
                .exit_code()
                .code(),
            3
        );
        let generic = classify_failure(&out("something odd"), "ctx", KopiaOp::Other);
        assert_eq!(generic.exit_code().code(), 1);
        assert_eq!(generic.verbose_detail(), Some("something odd"));
    }

    #[test]
    fn base_env_is_an_allowlist() {
        let env = base_env();
        assert!(env.iter().any(|(k, _)| k == "KOPIA_CHECK_FOR_UPDATES"));
        assert!(!env.iter().any(|(k, _)| k == "KOPIA_PASSWORD"));
        assert!(!env.iter().any(|(k, _)| k == "AWS_SECRET_ACCESS_KEY"));
    }
}
