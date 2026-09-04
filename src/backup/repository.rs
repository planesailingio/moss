//! Typed repository operations over the Kopia runner.

use std::path::Path;

use crate::backup::json::{MaintenanceInfo, RepositoryStatus, SnapshotManifest};
use crate::backup::kopia::{KopiaContext, KopiaOutput, classify_failure};
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

pub struct Repository<'a> {
    pub ctx: &'a KopiaContext,
    pub config: &'a RepositoryConfig,
    pub password: &'a Secret,
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

fn check(out: KopiaOutput, context: &str) -> Result<KopiaOutput> {
    if out.success() {
        Ok(out)
    } else {
        Err(classify_failure(&out, context))
    }
}

impl<'a> Repository<'a> {
    fn context(&self) -> String {
        let mut s = format!("Repository: {}", self.config.display_url());
        if let Some(e) = &self.config.endpoint {
            s.push_str(&format!("\nEndpoint:   {e}"));
        }
        s
    }

    fn connect_or_create(&self, verb: &str, s3: Option<&S3Credentials>) -> Result<()> {
        self.ctx.prepare_dirs()?;
        let hostname = crate::platform::hostname();
        let username = crate::platform::username();
        let mut args: Vec<String> = vec!["repository".into(), verb.into()];
        args.extend(storage_args(self.config)?);
        args.push(format!("--override-hostname={hostname}"));
        args.push(format!("--override-username={username}"));
        args.push("--description=moss profile repository".to_string());
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let env = s3.map(S3Credentials::env).unwrap_or_default();
        let out = self.ctx.run_connect(self.password, &refs, &env)?;
        check(out, &self.context())?;
        crate::config::paths::make_private_file(&self.ctx.config_file)?;
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
        self.ctx.config_file.is_file()
    }

    pub fn status(&self) -> Result<RepositoryStatus> {
        let out = check(
            self.ctx
                .run(self.password, &["repository", "status", "--json"], &[])?,
            &self.context(),
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
            self.ctx
                .run(self.password, &["policy", "set", &p, "--clear-ignore"], &[])?,
            &self.context(),
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
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        check(self.ctx.run(self.password, &refs, &[])?, &self.context())?;
        Ok(())
    }

    /// `kopia snapshot create --json` over several paths. Returns one manifest
    /// per path, even when Kopia exits 1 (fatal errors still write the manifest).
    pub fn snapshot_create(
        &self,
        paths: &[&Path],
        tags: &[(String, String)],
    ) -> Result<Vec<SnapshotManifest>> {
        let mut args: Vec<String> = vec!["snapshot".into(), "create".into(), "--json".into()];
        for (k, v) in tags {
            args.push("--tags".into());
            args.push(format!("{k}:{v}"));
        }
        for p in paths {
            args.push(p.display().to_string());
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = self.ctx.run(self.password, &refs, &[])?;
        let manifests = parse_manifests(&out.stdout);
        if manifests.is_empty() {
            return Err(classify_failure(&out, &self.context()));
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
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = check(self.ctx.run(self.password, &refs, &[])?, &self.context())?;
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
        let t = target.display().to_string();
        let mut args = vec![
            "snapshot",
            "restore",
            "--write-sparse-files",
            "--no-ignore-permission-errors",
            "--write-files-atomically",
            snapshot_id,
            &t,
        ];
        if skip_owners {
            args.insert(2, "--skip-owners");
        }
        check(self.ctx.run(self.password, &args, &[])?, &self.context())?;
        Ok(())
    }

    pub fn snapshot_verify(&self, snapshot_ids: &[&str], files_percent: u8) -> Result<KopiaOutput> {
        let pct = format!("--verify-files-percent={files_percent}");
        let mut args = vec!["snapshot", "verify", &pct];
        args.extend(snapshot_ids);
        let out = self.ctx.run(self.password, &args, &[])?;
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
        check(self.ctx.run(self.password, &args, &[])?, &self.context())
    }

    pub fn maintenance_info(&self) -> Result<MaintenanceInfo> {
        let out = check(
            self.ctx
                .run(self.password, &["maintenance", "info", "--json"], &[])?,
            &self.context(),
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
        check(self.ctx.run(self.password, &args, &[])?, &self.context())
    }

    /// Escape hatch: forward arbitrary arguments with moss's environment.
    pub fn passthrough(&self, args: &[&str]) -> Result<KopiaOutput> {
        self.ctx.run(self.password, args, &[])
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
    use std::path::PathBuf;

    #[test]
    fn storage_args_for_s3_and_fs() {
        let fs = RepositoryConfig {
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
        };
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
}
