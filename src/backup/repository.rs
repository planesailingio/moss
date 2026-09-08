//! Typed repository operations over the Kopia runner.

use std::ffi::{OsStr, OsString};
use std::path::Path;

use crate::backup::json::{MaintenanceInfo, RepositoryStatus, SnapshotManifest};
use crate::backup::kopia::{KopiaOp, KopiaOutput, KopiaRunner, RunOptions, classify_failure};
use crate::config::{RepositoryConfig, RepositoryType};
use crate::error::{MossError, Result};
use crate::security::secret::Secret;

/// S3 credentials passed to Kopia once, at connect time (spec §5).
pub struct S3Credentials {
    pub access_key: Secret,
    pub secret_key: Secret,
    pub session_token: Option<Secret>,
}

impl S3Credentials {
    pub fn from_env() -> Option<S3Credentials> {
        let ak = std::env::var("AWS_ACCESS_KEY_ID")
            .ok()
            .filter(|s| !s.is_empty())?;
        let sk = std::env::var("AWS_SECRET_ACCESS_KEY")
            .ok()
            .filter(|s| !s.is_empty())?;
        let st = std::env::var("AWS_SESSION_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());
        Some(S3Credentials {
            access_key: Secret::new(ak),
            secret_key: Secret::new(sk),
            session_token: st.map(Secret::new),
        })
    }

    fn env(&self) -> Vec<(&'static str, &Secret)> {
        let mut v = vec![
            ("AWS_ACCESS_KEY_ID", &self.access_key),
            ("AWS_SECRET_ACCESS_KEY", &self.secret_key),
        ];
        if let Some(t) = &self.session_token {
            v.push(("AWS_SESSION_TOKEN", t));
        }
        v
    }
}

/// One repository as seen through a runner: every Kopia flag moss uses is
/// spelled here and nowhere else.
pub struct Repository<'a> {
    ctx: &'a dyn KopiaRunner,
    config: &'a RepositoryConfig,
    password: &'a Secret,
}

fn storage_args(config: &RepositoryConfig) -> Result<Vec<String>> {
    match config.kind {
        RepositoryType::Filesystem => {
            let path = config
                .path
                .as_ref()
                .ok_or_else(|| MossError::Config("filesystem repository has no path".into()))?;
            Ok(vec![
                "filesystem".into(),
                format!("--path={}", path.display()),
            ])
        }
        RepositoryType::S3 => {
            let bucket = config
                .bucket
                .as_ref()
                .ok_or_else(|| MossError::Config("s3 repository has no bucket".into()))?;
            let mut args = vec!["s3".to_string(), format!("--bucket={bucket}")];
            if let Some(p) = config.prefix.as_deref().filter(|p| !p.is_empty()) {
                let p = p.trim_end_matches('/');
                args.push(format!("--prefix={p}/"));
            }
            if let Some(e) = &config.endpoint {
                let host = e
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .trim_end_matches('/');
                args.push(format!("--endpoint={host}"));
                if e.starts_with("http://") {
                    args.push("--disable-tls".into());
                }
            }
            if let Some(r) = config
                .region
                .as_deref()
                .filter(|r| !r.is_empty() && *r != "auto")
            {
                args.push(format!("--region={r}"));
            }
            if let Some(tls) = &config.tls {
                if tls.disable {
                    args.push("--disable-tls".into());
                }
                if tls.disable_verification {
                    args.push("--disable-tls-verification".into());
                }
                if let Some(p) = &tls.root_ca_pem_path {
                    args.push(format!("--root-ca-pem-path={}", p.display()));
                }
            }
            Ok(args)
        }
    }
}

fn check(out: KopiaOutput, context: &str, op: KopiaOp) -> Result<KopiaOutput> {
    if out.success() {
        Ok(out)
    } else {
        Err(classify_failure(&out, context, op))
    }
}

fn os_args(args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Vec<OsString> {
    args.into_iter()
        .map(|a| a.as_ref().to_os_string())
        .collect()
}

impl<'a> Repository<'a> {
    pub fn new(
        ctx: &'a dyn KopiaRunner,
        config: &'a RepositoryConfig,
        password: &'a Secret,
    ) -> Repository<'a> {
        Repository {
            ctx,
            config,
            password,
        }
    }

    pub fn config(&self) -> &RepositoryConfig {
        self.config
    }

    fn context(&self) -> String {
        let mut s = format!("Repository: {}", self.config.display_url());
        if let Some(e) = &self.config.endpoint {
            s.push_str(&format!("\nEndpoint:   {e}"));
        }
        s
    }

    /// Run a repository command with the password, no timeout.
    fn run(&self, args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Result<KopiaOutput> {
        self.run_with(args, RunOptions::default())
    }

    fn run_with(
        &self,
        args: impl IntoIterator<Item = impl AsRef<OsStr>>,
        options: RunOptions,
    ) -> Result<KopiaOutput> {
        self.ctx
            .run_with(Some(self.password), &os_args(args), &[], options)
    }

    fn connect_or_create(&self, verb: &str, s3: Option<&S3Credentials>) -> Result<()> {
        let hostname = crate::platform::hostname();
        let username = crate::platform::username();
        let mut args: Vec<String> = vec!["repository".into(), verb.into()];
        args.extend(storage_args(self.config)?);
        args.push(format!("--override-hostname={hostname}"));
        args.push(format!("--override-username={username}"));
        args.push("--description=moss profile repository".to_string());
        let env = s3.map(S3Credentials::env).unwrap_or_default();
        let out = self.ctx.run_with(
            Some(self.password),
            &os_args(&args),
            &env,
            RunOptions::connect(),
        )?;
        let op = if verb == "create" {
            KopiaOp::Create
        } else {
            KopiaOp::Connect
        };
        check(out, &self.context(), op)?;
        crate::config::paths::make_private_file(self.ctx.config_file())?;
        Ok(())
    }

    /// `kopia repository create`.
    pub fn create(&self, s3: Option<&S3Credentials>) -> Result<()> {
        self.connect_or_create("create", s3)
    }

    /// `kopia repository connect`.
    pub fn connect(&self, s3: Option<&S3Credentials>) -> Result<()> {
        self.connect_or_create("connect", s3)
    }

    /// Whether a Kopia repository already exists at the storage location.
    /// Distinguishes "exists but wrong password" (AuthFailure) from "nothing
    /// there" (Ok(false)).
    pub fn exists(&self, s3: Option<&S3Credentials>) -> Result<bool> {
        match self.connect(s3) {
            Ok(()) => Ok(true),
            Err(MossError::AuthFailure { .. }) => Ok(true),
            Err(MossError::RepositoryNotInitialised { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.ctx.config_file().is_file()
    }

    pub fn status(&self) -> Result<RepositoryStatus> {
        let out = check(
            self.run_with(["repository", "status", "--json"], RunOptions::metadata())?,
            &self.context(),
            KopiaOp::Connect,
        )?;
        // Never log `out.stdout` (spec §5).
        serde_json::from_str(&out.stdout).map_err(|e| MossError::Kopia {
            message: "Could not parse `kopia repository status --json`.".into(),
            detail: e.to_string(),
        })
    }

    /// Per-source policy: unreadable entries are recorded, not fatal (spec
    /// §18), and moss's exclusions become Kopia ignore rules (spec §10).
    ///
    /// `--clear-ignore` must run in its own invocation: Kopia applies the
    /// clear after the adds when both are given together (verified 0.23.1).
    pub fn set_source_policy(&self, path: &Path, ignore_rules: &[String]) -> Result<()> {
        let p = path.display().to_string();
        check(
            self.run(["policy", "set", &p, "--clear-ignore"])?,
            &self.context(),
            KopiaOp::Other,
        )?;
        let mut args: Vec<String> = vec![
            "policy".into(),
            "set".into(),
            p,
            "--ignore-file-errors=true".into(),
            "--ignore-dir-errors=true".into(),
            "--ignore-unknown-types=true".into(),
        ];
        for r in ignore_rules {
            args.push(format!("--add-ignore={r}"));
        }
        check(self.run(&args)?, &self.context(), KopiaOp::Other)?;
        Ok(())
    }

    /// `kopia snapshot create --json` over several paths. Returns one manifest
    /// per path, even when Kopia exits 1 (fatal errors still write the manifest).
    pub fn snapshot_create(
        &self,
        paths: &[&Path],
        tags: &[(String, String)],
    ) -> Result<Vec<SnapshotManifest>> {
        let mut args: Vec<OsString> = os_args(["snapshot", "create", "--json"]);
        for (k, v) in tags {
            args.push("--tags".into());
            args.push(format!("{k}:{v}").into());
        }
        for p in paths {
            args.push(p.as_os_str().to_os_string());
        }
        let out = self.run(&args)?;
        let manifests = parse_manifests(&out.stdout);
        if manifests.is_empty() {
            return Err(classify_failure(&out, &self.context(), KopiaOp::Snapshot));
        }
        Ok(manifests)
    }

    pub fn snapshot_list(&self, tag_filters: &[(String, String)]) -> Result<Vec<SnapshotManifest>> {
        let mut args: Vec<String> = vec![
            "snapshot".into(),
            "list".into(),
            "--all".into(),
            "--json".into(),
        ];
        for (k, v) in tag_filters {
            args.push("--tags".into());
            args.push(format!("{k}:{v}"));
        }
        let out = check(self.run(&args)?, &self.context(), KopiaOp::Other)?;
        if out.stdout.trim().is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_str(&out.stdout).map_err(|e| MossError::Kopia {
            message: "Could not parse `kopia snapshot list --json`.".into(),
            detail: e.to_string(),
        })
    }

    /// `kopia snapshot restore <id> <target>` into a moss-owned directory.
    pub fn snapshot_restore(
        &self,
        snapshot_id: &str,
        target: &Path,
        skip_owners: bool,
    ) -> Result<()> {
        let mut args: Vec<OsString> = os_args([
            "snapshot",
            "restore",
            "--write-sparse-files",
            "--no-ignore-permission-errors",
            "--write-files-atomically",
        ]);
        if skip_owners {
            args.insert(2, "--skip-owners".into());
        }
        args.push(snapshot_id.into());
        args.push(target.as_os_str().to_os_string());
        check(self.run(&args)?, &self.context(), KopiaOp::Other)?;
        Ok(())
    }

    pub fn snapshot_verify(&self, snapshot_ids: &[&str], files_percent: u8) -> Result<KopiaOutput> {
        let pct = format!("--verify-files-percent={files_percent}");
        let mut args = vec!["snapshot", "verify", &pct];
        args.extend(snapshot_ids);
        let out = self.run(&args)?;
        if out.success() {
            Ok(out)
        } else {
            Err(MossError::Integrity(format!(
                "Snapshot verification failed.\n\n{}\n\n{}",
                self.context(),
                out.stderr
                    .lines()
                    .rev()
                    .take(5)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join("\n")
            )))
        }
    }

    pub fn snapshot_expire(&self, delete: bool) -> Result<KopiaOutput> {
        let mut args = vec!["snapshot", "expire", "--all"];
        if delete {
            args.push("--delete");
        }
        check(self.run(&args)?, &self.context(), KopiaOp::Other)
    }

    pub fn maintenance_info(&self) -> Result<MaintenanceInfo> {
        let out = check(
            self.run_with(["maintenance", "info", "--json"], RunOptions::metadata())?,
            &self.context(),
            KopiaOp::Other,
        )?;
        serde_json::from_str(&out.stdout).map_err(|e| MossError::Kopia {
            message: "Could not parse `kopia maintenance info --json`.".into(),
            detail: e.to_string(),
        })
    }

    pub fn maintenance_run(&self, full: bool) -> Result<KopiaOutput> {
        let mut args = vec!["maintenance", "run", "--safety=full"];
        if full {
            args.push("--full");
        }
        check(self.run(&args)?, &self.context(), KopiaOp::Other)
    }

    /// Escape hatch: forward arbitrary arguments with moss's environment.
    pub fn passthrough(
        &self,
        args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    ) -> Result<KopiaOutput> {
        self.run(args)
    }
}

/// Kopia prints one JSON document per path, back to back (possibly with
/// whitespace). Parse them all, tolerating trailing garbage.
pub fn parse_manifests(stdout: &str) -> Vec<SnapshotManifest> {
    let mut out = Vec::new();
    let de = serde_json::Deserializer::from_str(stdout);
    for item in de.into_iter::<SnapshotManifest>() {
        match item {
            Ok(m) => out.push(m),
            Err(_) => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::kopia::testing::FixtureRunner;
    use std::path::PathBuf;

    fn fs_config() -> RepositoryConfig {
        RepositoryConfig {
            kind: RepositoryType::Filesystem,
            id: "x".into(),
            path: Some(PathBuf::from("/tmp/r")),
            bucket: None,
            prefix: None,
            endpoint: None,
            region: None,
            tls: None,
            credential_store: Default::default(),
            recovery_acknowledged_at: None,
            created_at: None,
            local: None,
        }
    }

    #[test]
    fn storage_args_for_s3_and_fs() {
        let fs = fs_config();
        assert_eq!(
            storage_args(&fs).unwrap(),
            vec!["filesystem", "--path=/tmp/r"]
        );
        let s3 = RepositoryConfig {
            kind: RepositoryType::S3,
            id: "x".into(),
            path: None,
            bucket: Some("b".into()),
            prefix: Some("rhys".into()),
            endpoint: Some("https://s3.example.com/".into()),
            region: Some("auto".into()),
            tls: None,
            credential_store: Default::default(),
            recovery_acknowledged_at: None,
            created_at: None,
            local: None,
        };
        assert_eq!(
            storage_args(&s3).unwrap(),
            vec![
                "s3",
                "--bucket=b",
                "--prefix=rhys/",
                "--endpoint=s3.example.com"
            ]
        );
        // No key flags, ever.
        assert!(
            storage_args(&s3)
                .unwrap()
                .iter()
                .all(|a| !a.contains("key"))
        );
    }

    #[test]
    fn multiple_manifests_parse() {
        let one = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/kopia/0.23.1/snapshot-create-clean.json"),
        )
        .unwrap();
        let two = format!("{one}\n{one}\n");
        assert_eq!(parse_manifests(&two).len(), 2);
        assert_eq!(parse_manifests("").len(), 0);
    }

    /// `snapshot create` parses the manifest Kopia printed even on exit 1
    /// (spec §18), sends the tags as `--tags k:v` pairs, and never a password.
    #[test]
    fn snapshot_create_parses_fixture_regardless_of_exit_code() {
        let runner = FixtureRunner::new().on_fixture(
            &["snapshot", "create"],
            "snapshot-create-fatal.json",
            1,
        );
        let cfg = fs_config();
        let pw = Secret::new("pw");
        let repo = Repository::new(&runner, &cfg, &pw);
        let tags = vec![("moss-run".to_string(), "01TEST".to_string())];
        let m = repo
            .snapshot_create(&[Path::new("/tmp/moss-fixture/src")], &tags)
            .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].fatal_errors(), Some(1));
        assert_eq!(m[0].error_samples()[0].path, "noperm");
        let calls = runner.calls();
        assert_eq!(
            calls[0],
            vec![
                "snapshot",
                "create",
                "--json",
                "--tags",
                "moss-run:01TEST",
                "/tmp/moss-fixture/src"
            ]
        );
        assert!(calls[0].iter().all(|a| !a.contains("password")));
    }

    #[test]
    fn snapshot_create_with_no_manifest_is_classified() {
        let runner = FixtureRunner::new().on(
            &["snapshot", "create"],
            KopiaOutput::synthetic(1, "", "error: lstat /gone: no such file or directory"),
        );
        let cfg = fs_config();
        let pw = Secret::new("pw");
        let repo = Repository::new(&runner, &cfg, &pw);
        let err = repo
            .snapshot_create(&[Path::new("/gone")], &[])
            .unwrap_err();
        assert!(err.to_string().contains("source path"), "{err}");
    }

    #[test]
    fn status_and_maintenance_info_parse_fixtures() {
        let runner = FixtureRunner::new()
            .on_fixture(&["repository", "status"], "repository-status.json", 0)
            .on_fixture(&["maintenance", "info"], "maintenance-info.json", 0);
        let cfg = fs_config();
        let pw = Secret::new("pw");
        let repo = Repository::new(&runner, &cfg, &pw);
        assert_eq!(
            repo.status().unwrap().client_options.hostname,
            "fixture-host"
        );
        assert_eq!(
            repo.maintenance_info().unwrap().owner,
            "fixture-user@fixture-host"
        );
        assert!(!repo.is_connected());
    }
}
