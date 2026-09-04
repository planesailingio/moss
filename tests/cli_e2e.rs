//! End-to-end CLI tests against a real Kopia and a scratch repository.
//! Skipped when `kopia` is not on PATH.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

const RECOVERY: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

struct Env {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    moss_home: PathBuf,
    repo: PathBuf,
}

fn kopia_available() -> bool {
    which::which("kopia").is_ok()
}

fn setup() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let moss_home = tmp.path().join("moss");
    let repo = tmp.path().join("repo");
    for d in [".ssh", "Documents/proj/node_modules/x", "Movies"] {
        fs::create_dir_all(home.join(d)).unwrap();
    }
    fs::write(
        home.join(".ssh/id_ed25519"),
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    fs::write(
        home.join(".ssh/config"),
        format!(
            "Host x\n  IdentityFile {}/.ssh/id_ed25519\n",
            home.display()
        ),
    )
    .unwrap();
    fs::write(home.join(".gitconfig"), "[user]\n  name = t\n").unwrap();
    fs::write(home.join("Documents/a.txt"), "hello").unwrap();
    fs::write(
        home.join("Documents/proj/node_modules/x/big"),
        vec![0u8; 100_000],
    )
    .unwrap();
    fs::write(home.join("Documents/proj/.env"), "SECRET=1").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            home.join(".ssh/id_ed25519"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    Env {
        _tmp: tmp,
        home,
        moss_home,
        repo,
    }
}

fn moss(env: &Env) -> Command {
    let mut c = Command::cargo_bin("moss").unwrap();
    c.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &env.home)
        .env("USER", "tester")
        .env("MOSS_HOME", &env.moss_home)
        .env("MOSS_HOSTNAME", "test-host")
        .env("MOSS_REPOSITORY_PASSWORD", RECOVERY)
        .env("NO_COLOR", "1");
    c
}

fn init(env: &Env) {
    moss(env)
        .args(["init", "--repository"])
        .arg(&env.repo)
        .args([
            "--credential-store",
            "env",
            "--identity",
            "e2e",
            "--non-interactive",
            "--recovery-acknowledged",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("RECOVERY SHEET"))
        .stdout(predicate::str::contains("24. art"));
}

#[test]
fn help_and_usage_exit_codes() {
    Command::cargo_bin("moss")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("moss"));
    Command::cargo_bin("moss")
        .unwrap()
        .arg("--bogus")
        .assert()
        .code(2);
    Command::cargo_bin("moss")
        .unwrap()
        .args(["init"])
        .assert()
        .code(2);
    // No --password flag anywhere.
    Command::cargo_bin("moss")
        .unwrap()
        .args(["backup", "--password", "x"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unexpected argument"));
}

#[test]
fn not_configured_is_exit_3() {
    let env = setup();
    moss(&env)
        .arg("snapshots")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("moss init"));
}

#[test]
fn full_backup_flow() {
    if !kopia_available() {
        eprintln!("kopia not on PATH; skipping");
        return;
    }
    let env = setup();
    init(&env);

    // Config was written, with discovered sources and no secrets.
    let cfg = fs::read_to_string(env.moss_home.join("config/config.yaml")).unwrap();
    assert!(cfg.contains("identity: e2e"));
    assert!(cfg.contains("id: ssh"));
    assert!(!cfg.contains("abandon"));

    moss(&env)
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("acknowledged"));

    let inspect = moss(&env).args(["inspect", "--json"]).assert().success();
    let v: serde_json::Value = serde_json::from_slice(&inspect.get_output().stdout).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert!(v["sensitive"]["SSH"].as_u64().unwrap() >= 1);
    assert_eq!(v["excluded"]["build_artifact"]["entries"], 1);

    // Backup: exclusions reach Kopia, sensitive gate satisfied by --yes, exit 0.
    let backup = moss(&env)
        .args(["backup", "--non-interactive", "--yes", "--json"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&backup.get_output().stdout).unwrap();
    assert_eq!(v["complete"], true);
    let docs = v["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["source"] == "documents")
        .unwrap();
    assert!(
        docs["size"].as_u64().unwrap() < 1000,
        "node_modules must not be uploaded: {docs}"
    );

    // Snapshots group into one complete run.
    let snaps = moss(&env).args(["snapshots", "--json"]).assert().success();
    let v: serde_json::Value = serde_json::from_slice(&snaps.get_output().stdout).unwrap();
    let runs = v["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["status"], "complete");
    assert_eq!(runs[0]["host"], "test-host");
    assert!(runs[0]["manifest_snapshot_id"].is_string());

    moss(&env)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Owner:"));
    moss(&env)
        .args(["verify", "--check-modes"])
        .assert()
        .success();

    // The password never lands on disk (spec §6, §34).
    for entry in walk(&env.moss_home) {
        let text = fs::read(&entry).unwrap_or_default();
        assert!(
            !String::from_utf8_lossy(&text).contains("abandon abandon"),
            "{}",
            entry.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let kopia_cfg = walk(&env.moss_home.join("state/kopia"))
            .into_iter()
            .find(|p| p.extension().is_some_and(|e| e == "config"))
            .unwrap();
        assert_eq!(
            fs::metadata(&kopia_cfg).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn partial_backup_exits_9_and_recovery_gate_exits_13() {
    if !kopia_available() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let env = setup();
    init(&env);
    let locked = env.home.join("Documents/locked");
    fs::create_dir(&locked).unwrap();
    fs::write(locked.join("f"), "x").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let result = moss(&env)
        .args(["backup", "--non-interactive", "--yes"])
        .assert();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    if unsafe { libc_geteuid() } == 0 {
        return;
    }
    result
        .code(9)
        .stdout(predicate::str::contains("PARTIAL"))
        .stdout(predicate::str::contains("Documents/locked"));

    // Un-acknowledge the sheet and the backup refuses with 13.
    let cfg_path = env.moss_home.join("config/config.yaml");
    let cfg = fs::read_to_string(&cfg_path).unwrap();
    let stripped: String = cfg
        .lines()
        .filter(|l| !l.contains("recovery_acknowledged_at"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&cfg_path, stripped).unwrap();
    moss(&env)
        .args(["backup", "--non-interactive", "--yes"])
        .assert()
        .code(13);
}

#[test]
fn second_machine_bootstrap_requires_recovery_code() {
    if !kopia_available() {
        return;
    }
    let env = setup();
    init(&env);
    // A second "machine": fresh MOSS_HOME, same repository, no password anywhere.
    let other = tempfile::tempdir().unwrap();
    let mut c = moss(&env);
    c.env("MOSS_HOME", other.path())
        .env_remove("MOSS_REPOSITORY_PASSWORD");
    c.args(["init", "--repository"])
        .arg(&env.repo)
        .args([
            "--credential-store",
            "env",
            "--non-interactive",
            "--recovery-acknowledged",
        ])
        .assert()
        .code(13)
        .stderr(predicate::str::contains("recovery code"));
    // With the recovery code supplied via the environment it connects.
    let mut c = moss(&env);
    c.env("MOSS_HOME", other.path());
    c.args(["init", "--repository"])
        .arg(&env.repo)
        .args([
            "--credential-store",
            "env",
            "--non-interactive",
            "--recovery-acknowledged",
        ])
        .assert()
        .success();
    let mut c = moss(&env);
    c.env("MOSS_HOME", other.path());
    c.args(["snapshots", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"runs\""));
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}
