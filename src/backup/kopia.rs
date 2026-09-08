//! The Kopia subprocess runner (spec §5 "Kopia process hygiene").
//!
//! One function builds every command line and child environment. The parent
//! environment is never copied wholesale; the password reaches the child via
//! `KOPIA_PASSWORD` only. The `Command` holding that copy is dropped as soon
//! as the child exits, but `std::process::Command` does not zeroise its
//! environment, so the copy is freed rather than scrubbed; only the `Secret`
//! it was read from is zeroised on drop.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::config::MossPaths;
use crate::error::{MossError, Result};
use crate::security::secret::Secret;

/// Tested Kopia range (spec §5). Update both together with the fixtures.
pub const KOPIA_MIN: (u64, u64, u64) = (0, 23, 0);
pub const KOPIA_MAX_MINOR: (u64, u64) = (0, 23);

/// How long a metadata command (`repository status`, `maintenance info`,
/// `--version`) may take before moss gives up on it. Long-running verbs
/// (`snapshot create|restore|verify`, `maintenance run`) have no limit.
pub const METADATA_TIMEOUT: Duration = Duration::from_secs(60);

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

/// Per-invocation knobs for one Kopia command.
#[derive(Debug, Clone, Copy, Default)]
pub struct RunOptions {
    /// `repository create|connect`: adds the cache-directory and update-check
    /// flags and prepares moss's Kopia directories first.
    pub connect: bool,
    /// Kill the child and fail if it has not exited by then. `None` for
    /// commands whose duration is data-dependent.
    pub timeout: Option<Duration>,
}

impl RunOptions {
    /// A short metadata query that must answer promptly.
    pub fn metadata() -> RunOptions {
        RunOptions {
            connect: false,
            timeout: Some(METADATA_TIMEOUT),
        }
    }

    pub fn connect() -> RunOptions {
        RunOptions {
            connect: true,
            timeout: None,
        }
    }
}

/// Anything that can run Kopia for moss. `KopiaContext` is the real one;
/// tests substitute a `FixtureRunner`. `Repository` talks only to this.
pub trait KopiaRunner: Send + Sync {
    /// Run kopia with moss's config file and environment allowlist.
    fn run_with(
        &self,
        password: Option<&Secret>,
        args: &[OsString],
        extra_env: &[(&str, &Secret)],
        options: RunOptions,
    ) -> Result<KopiaOutput>;

    /// `run_with` without a timeout; `connect` selects the create/connect flags.
    fn run(
        &self,
        password: Option<&Secret>,
        args: &[OsString],
        extra_env: &[(&str, &Secret)],
        connect: bool,
    ) -> Result<KopiaOutput> {
        self.run_with(
            password,
            args,
            extra_env,
            RunOptions {
                connect,
                timeout: None,
            },
        )
    }

    /// Kopia's config file for this repository (`--config-file`).
    fn config_file(&self) -> &Path;

    /// The Kopia executable.
    fn binary(&self) -> &Path;
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

#[derive(Debug, Clone, Default)]
pub struct KopiaOutput {
    /// Exit code, `None` when the child was killed by a signal (or the output
    /// is synthetic).
    pub status: Option<i32>,
    /// The full exit status when a real child ran.
    pub exit: Option<ExitStatus>,
    pub stdout: String,
    pub stderr: String,
}

impl KopiaOutput {
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }

    /// Synthetic output (tests, fixtures): a code and captured streams.
    pub fn synthetic(status: i32, stdout: impl Into<String>, stderr: impl Into<String>) -> Self {
        KopiaOutput {
            status: Some(status),
            exit: None,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    /// The signal that terminated the child, if any.
    #[cfg(unix)]
    pub fn signal(&self) -> Option<i32> {
        use std::os::unix::process::ExitStatusExt;
        self.exit.and_then(|e| e.signal())
    }
}

/// Message and detail of a failed version probe, cached for the process.
static VERSION: OnceLock<std::result::Result<KopiaVersion, (String, String)>> = OnceLock::new();

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
        let mut cmd = Command::new(binary);
        cmd.arg("--version")
            .env_clear()
            .envs(base_env())
            .stdin(Stdio::null());
        let out = run_command(cmd, Some(METADATA_TIMEOUT), "--version").map_err(|e| match e {
            MossError::Kopia { message, detail } => (message, detail),
            other => (
                "Kopia was found but `kopia --version` failed.".to_string(),
                other.to_string(),
            ),
        })?;
        KopiaVersion::parse(&out.stdout).ok_or_else(|| {
            (
                "Kopia was found but `kopia --version` failed.".to_string(),
                format!(
                    "unrecognised `kopia --version` output: {}",
                    out.stdout.trim()
                ),
            )
        })
    });
    match cached {
        Ok(v) => Ok(v.clone()),
        Err((message, detail)) => Err(MossError::Kopia {
            message: message.clone(),
            detail: detail.clone(),
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
    fn command(&self, args: &[OsString], connect: bool) -> Command {
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
}

impl KopiaRunner for KopiaContext {
    fn run_with(
        &self,
        password: Option<&Secret>,
        args: &[OsString],
        extra_env: &[(&str, &Secret)],
        options: RunOptions,
    ) -> Result<KopiaOutput> {
        check_version(&self.binary, self.skip_version_check)?;
        if options.connect {
            self.prepare_dirs()?;
        }
        let mut cmd = self.command(args, options.connect);
        if let Some(p) = password {
            cmd.env("KOPIA_PASSWORD", p.expose());
        }
        for (k, v) in extra_env {
            cmd.env(k, v.expose());
        }
        tracing::debug!(args = ?redact_args(args), "running kopia");
        // `run_command` consumes the Command, so its copy of the password is
        // freed (not zeroised; see the module docs) when the child exits.
        run_command(cmd, options.timeout, &verb(args))
    }

    fn config_file(&self) -> &Path {
        &self.config_file
    }

    fn binary(&self) -> &Path {
        &self.binary
    }
}

/// The Kopia verb for messages: the first two non-flag arguments
/// (`repository status`), or the first argument when there are none.
fn verb(args: &[OsString]) -> String {
    let words: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .filter(|a| !a.starts_with('-'))
        .take(2)
        .collect();
    if words.is_empty() {
        args.first()
            .map(|a| a.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        words.join(" ")
    }
}

/// Spawn, drain both pipes on their own threads (stderr line by line into
/// the `kopia` tracing target), and wait — polling when a timeout applies.
fn run_command(mut cmd: Command, timeout: Option<Duration>, verb: &str) -> Result<KopiaOutput> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| MossError::Kopia {
        message: "Failed to start Kopia.".into(),
        detail: e.to_string(),
    })?;
    drop(cmd);

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut s) = stdout {
            let _ = s.read_to_end(&mut buf);
        }
        buf
    });
    // Shared so a timeout can report what Kopia said so far without waiting
    // for the reader: a grandchild holding the pipe would keep it alive.
    let stderr_text = Arc::new(Mutex::new(String::new()));
    let err_thread = {
        let collected = Arc::clone(&stderr_text);
        std::thread::spawn(move || {
            if let Some(s) = stderr {
                for line in BufReader::new(s).split(b'\n') {
                    let Ok(line) = line else { break };
                    let text = String::from_utf8_lossy(&line);
                    let text = text.trim_end_matches('\r');
                    tracing::debug!(target: "kopia", "{text}");
                    let mut c = collected.lock().unwrap_or_else(|p| p.into_inner());
                    c.push_str(text);
                    c.push('\n');
                }
            }
        })
    };

    let exit = match wait_for(&mut child, timeout) {
        Ok(status) => status,
        Err(e) => {
            // Kill and reap, but do not join the readers: they finish when the
            // last holder of the pipes goes away, which may not be the child.
            let _ = child.kill();
            let _ = child.wait();
            drop(out_thread);
            drop(err_thread);
            let stderr = stderr_text
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            return Err(match e {
                WaitError::TimedOut => MossError::Kopia {
                    message: format!(
                        "Kopia did not respond within {} s: {verb}",
                        timeout.unwrap_or_default().as_secs()
                    ),
                    detail: stderr.trim().to_string(),
                },
                WaitError::Io(io) => MossError::Kopia {
                    message: format!("Failed while waiting for Kopia ({verb})."),
                    detail: io.to_string(),
                },
            });
        }
    };
    let stdout = out_thread.join().unwrap_or_default();
    let _ = err_thread.join();
    let stderr = std::mem::take(&mut *stderr_text.lock().unwrap_or_else(|p| p.into_inner()));
    Ok(KopiaOutput {
        status: exit.code(),
        exit: Some(exit),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr,
    })
}

enum WaitError {
    TimedOut,
    Io(std::io::Error),
}

fn wait_for(
    child: &mut Child,
    timeout: Option<Duration>,
) -> std::result::Result<ExitStatus, WaitError> {
    let Some(limit) = timeout else {
        return child.wait().map_err(WaitError::Io);
    };
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(WaitError::Io)? {
            return Ok(status);
        }
        if start.elapsed() >= limit {
            return Err(WaitError::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Arguments are never secret by construction (no --password, no keys), but
/// keep the log line short.
fn redact_args(args: &[OsString]) -> Vec<String> {
    args.iter()
        .map(|a| {
            let a = a.to_string_lossy();
            if a.starts_with("--secret-access-key")
                || a.starts_with("--access-key")
                || a.starts_with("--session-token")
            {
                "[redacted]".to_string()
            } else {
                a.into_owned()
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

/// Test doubles for the runner. Compiled into unit tests only.
#[cfg(test)]
pub mod testing {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use super::{KopiaOutput, KopiaRunner, RunOptions};
    use crate::error::Result;
    use crate::security::secret::Secret;

    /// Directory holding the captured Kopia 0.23.1 JSON.
    pub fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kopia/0.23.1")
    }

    /// Read one fixture file.
    pub fn fixture(name: &str) -> String {
        let p = fixture_dir().join(name);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    /// A `KopiaRunner` that answers from canned output instead of spawning.
    ///
    /// Rules are tried in order; a rule matches when each of its tokens
    /// appears, in order, somewhere in the argument vector (a subsequence,
    /// so `["snapshot", "create", "moss-source:manifest"]` singles out the
    /// manifest snapshot). Unmatched calls succeed with empty output, which
    /// is what `policy set` and friends produce.
    #[derive(Default)]
    pub struct FixtureRunner {
        rules: Vec<(Vec<String>, KopiaOutput)>,
        calls: Mutex<Vec<Vec<String>>>,
        config_file: PathBuf,
        binary: PathBuf,
    }

    impl FixtureRunner {
        pub fn new() -> FixtureRunner {
            FixtureRunner {
                config_file: PathBuf::from("/nonexistent/moss/kopia/fixture.config"),
                binary: PathBuf::from("/nonexistent/bin/kopia"),
                ..Default::default()
            }
        }

        pub fn with_config_file(mut self, path: impl Into<PathBuf>) -> FixtureRunner {
            self.config_file = path.into();
            self
        }

        /// Answer calls matching `tokens` with `output`.
        pub fn on(mut self, tokens: &[&str], output: KopiaOutput) -> FixtureRunner {
            self.rules
                .push((tokens.iter().map(|t| t.to_string()).collect(), output));
            self
        }

        /// Answer calls matching `tokens` with the contents of a fixture file
        /// on stdout and the given exit code.
        pub fn on_fixture(self, tokens: &[&str], file: &str, status: i32) -> FixtureRunner {
            self.on(tokens, KopiaOutput::synthetic(status, fixture(file), ""))
        }

        /// Every argument vector this runner has been asked to run.
        pub fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }

        fn matches(tokens: &[String], args: &[String]) -> bool {
            let mut rest = args.iter();
            tokens.iter().all(|t| rest.any(|a| a == t))
        }
    }

    impl KopiaRunner for FixtureRunner {
        fn run_with(
            &self,
            _password: Option<&Secret>,
            args: &[OsString],
            _extra_env: &[(&str, &Secret)],
            _options: RunOptions,
        ) -> Result<KopiaOutput> {
            let args: Vec<String> = args
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            self.calls.lock().unwrap().push(args.clone());
            for (tokens, out) in &self.rules {
                if Self::matches(tokens, &args) {
                    return Ok(out.clone());
                }
            }
            Ok(KopiaOutput::synthetic(0, "", ""))
        }

        fn config_file(&self) -> &Path {
            &self.config_file
        }

        fn binary(&self) -> &Path {
            &self.binary
        }
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
        let out = |stderr: &str| KopiaOutput::synthetic(1, "", stderr);
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

    #[test]
    fn verb_skips_flags() {
        let args = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(
            verb(&args(&["repository", "status", "--json"])),
            "repository status"
        );
        assert_eq!(verb(&args(&["--version"])), "--version");
        assert_eq!(verb(&args(&[])), "");
    }

    /// The subprocess plumbing against a real shell: both streams are
    /// captured, stderr survives, and the exit code comes back.
    #[cfg(unix)]
    #[test]
    fn run_command_captures_both_streams() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo out; echo err >&2; exit 3"]);
        let out = run_command(cmd, None, "sh").unwrap();
        assert_eq!(out.status, Some(3));
        assert_eq!(out.stdout, "out\n");
        assert_eq!(out.stderr, "err\n");
        assert!(out.exit.is_some());
        assert_eq!(out.signal(), None);
    }

    #[cfg(unix)]
    #[test]
    fn run_command_times_out_and_kills() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo started >&2; sleep 30"]);
        let started = Instant::now();
        let err = run_command(cmd, Some(Duration::from_secs(1)), "repository status").unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "child was not killed"
        );
        match err {
            MossError::Kopia { message, detail } => {
                assert_eq!(
                    message,
                    "Kopia did not respond within 1 s: repository status"
                );
                assert_eq!(detail, "started");
            }
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn fixture_runner_matches_subsequences() {
        let r = testing::FixtureRunner::new()
            .on_fixture(
                &["snapshot", "create", "moss-source:manifest"],
                "snapshot-create-clean.json",
                0,
            )
            .on_fixture(&["snapshot", "create"], "snapshot-create-fatal.json", 1);
        let args = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
        let a = r
            .run(
                None,
                &args(&["snapshot", "create", "--json", "/x"]),
                &[],
                false,
            )
            .unwrap();
        assert_eq!(a.status, Some(1));
        let b = r
            .run(
                None,
                &args(&[
                    "snapshot",
                    "create",
                    "--json",
                    "--tags",
                    "moss-source:manifest",
                    "/m",
                ]),
                &[],
                false,
            )
            .unwrap();
        assert_eq!(b.status, Some(0));
        let c = r
            .run(None, &args(&["policy", "set", "/x"]), &[], false)
            .unwrap();
        assert!(c.success() && c.stdout.is_empty());
        assert_eq!(r.calls().len(), 3);
    }
}
