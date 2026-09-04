//! Ask developer tools where their caches are (spec §10).
//!
//! Only binaries found on `PATH`, each with a two-second timeout. Results are
//! cached in the scan index by the caller.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCache {
    pub tool: String,
    pub path: PathBuf,
}

struct Query {
    tool: &'static str,
    args: &'static [&'static str],
}

const QUERIES: &[Query] = &[
    Query {
        tool: "pip",
        args: &["cache", "dir"],
    },
    Query {
        tool: "pip3",
        args: &["cache", "dir"],
    },
    Query {
        tool: "pnpm",
        args: &["store", "path"],
    },
    Query {
        tool: "go",
        args: &["env", "GOCACHE"],
    },
    Query {
        tool: "go",
        args: &["env", "GOMODCACHE"],
    },
    Query {
        tool: "npm",
        args: &["config", "get", "cache"],
    },
    Query {
        tool: "yarn",
        args: &["cache", "dir"],
    },
    Query {
        tool: "uv",
        args: &["cache", "dir"],
    },
];

pub const TIMEOUT: Duration = Duration::from_secs(2);

/// Query every tool that is installed. Never fails; absent or slow tools are skipped.
pub fn query_all(home: &Path) -> Vec<ToolCache> {
    let mut out = Vec::new();
    for q in QUERIES {
        let Ok(bin) = which::which(q.tool) else {
            continue;
        };
        if let Some(path) = run_with_timeout(&bin, q.args) {
            let path = PathBuf::from(path.trim());
            if path.is_absolute()
                && path.starts_with(home)
                && path.is_dir()
                && !out.iter().any(|t: &ToolCache| t.path == path)
            {
                out.push(ToolCache {
                    tool: q.tool.to_string(),
                    path,
                });
            }
        }
    }
    out
}

fn run_with_timeout(bin: &Path, args: &[&str]) -> Option<String> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env("NO_COLOR", "1")
        .spawn()
        .ok()?;
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                let mut s = String::new();
                use std::io::Read;
                child.stdout.take()?.read_to_string(&mut s).ok()?;
                return Some(s);
            }
            Ok(None) => {
                if start.elapsed() > TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    tracing::debug!(tool = %bin.display(), "cache query timed out");
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_kills_slow_tool() {
        let sh = which::which("sh");
        let Ok(sh) = sh else { return };
        let started = std::time::Instant::now();
        assert!(run_with_timeout(&sh, &["-c", "sleep 30"]).is_none());
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn query_all_never_panics() {
        let _ = query_all(Path::new("/nonexistent-home"));
    }
}
