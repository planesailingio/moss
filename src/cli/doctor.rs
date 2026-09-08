//! `moss doctor` (spec §7): every environmental precondition in one place.

use serde::Serialize;

use crate::backup::kopia;
use crate::cli::AppContext;
use crate::config::{CredentialStoreKind, paths};
use crate::credentials;
use crate::error::{ExitCode, MossError, Result};
use crate::platform::tcc::{self, FdaStatus};
use crate::scan::index::ScanIndex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Warn,
    Fail,
    Skip,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub section: &'static str,
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
}

#[derive(Debug, Serialize)]
struct Report {
    ok: bool,
    checks: Vec<Check>,
}

pub fn run(ctx: &AppContext) -> Result<ExitCode> {
    let console = ctx.console;
    let mut checks: Vec<Check> = Vec::new();
    let adapter = ctx.adapter();
    let home = adapter.home().to_path_buf();

    // Kopia
    match kopia::find_binary() {
        Ok(bin) => {
            checks.push(Check {
                section: "Kopia",
                name: "found",
                status: Status::Ok,
                detail: bin.display().to_string(),
                help: None,
            });
            match kopia::version(&bin) {
                Ok(v) => {
                    let in_range = v.in_tested_range();
                    checks.push(Check {
                        section: "Kopia",
                        name: "version",
                        status: if in_range { Status::Ok } else { Status::Fail },
                        detail: format!(
                            "{}  (tested: {})",
                            v.display(),
                            kopia::version_range_display()
                        ),
                        help: (!in_range)
                            .then(|| "Install a tested Kopia, or use --skip-version-check.".into()),
                    });
                }
                Err(e) => checks.push(Check {
                    section: "Kopia",
                    name: "version",
                    status: Status::Fail,
                    detail: e.to_string(),
                    help: None,
                }),
            }
        }
        Err(_) => checks.push(Check {
            section: "Kopia",
            name: "found",
            status: Status::Fail,
            detail: "not on PATH".into(),
            help: Some(
                "Install Kopia: https://kopia.io/docs/installation/ (brew install kopia)".into(),
            ),
        }),
    }

    // Repository
    let config = ctx.load_config_or_default()?;
    match ctx.repository_config(&config) {
        Err(MossError::NotConfigured) => checks.push(Check {
            section: "Repository",
            name: "configured",
            status: Status::Warn,
            detail: "no repository configured".into(),
            help: Some("Run `moss init --repository <path or s3://bucket/prefix>`.".into()),
        }),
        Err(e) => return Err(e),
        Ok(repo) => {
            let store = credentials::store_for(repo.credential_store);
            let cred = match credentials::resolve_password(store.as_ref(), &repo.id) {
                Ok((pw, source)) => {
                    checks.push(Check {
                        section: "Repository",
                        name: "credentials",
                        status: Status::Ok,
                        detail: match source {
                            credentials::CredentialSource::Environment => {
                                "environment (MOSS_REPOSITORY_PASSWORD)".into()
                            }
                            credentials::CredentialSource::Keyring => store.name().to_string(),
                        },
                        help: None,
                    });
                    Some(pw)
                }
                Err(e) => {
                    checks.push(Check {
                        section: "Repository",
                        name: "credentials",
                        status: Status::Fail,
                        detail: first_line(&e.to_string()),
                        help: Some(e.to_string()),
                    });
                    None
                }
            };
            if repo.credential_store == CredentialStoreKind::Keyring {
                match store.probe() {
                    Ok(()) => checks.push(Check {
                        section: "Repository",
                        name: "credential store",
                        status: Status::Ok,
                        detail: format!("{} writable and unlocked", store.name()),
                        help: None,
                    }),
                    Err(e) => checks.push(Check {
                        section: "Repository",
                        name: "credential store",
                        status: Status::Fail,
                        detail: first_line(&e.to_string()),
                        help: Some("Scheduled runs need an unlockable store; see SECURITY.md for the MOSS_REPOSITORY_PASSWORD fallback.".into()),
                    }),
                }
            }
            match (&cred, ctx.global.skip_version_check, kopia::find_binary()) {
                (Some(pw), skip, Ok(_)) => {
                    let kctx = kopia::KopiaContext::new(
                        &ctx.paths,
                        &repo.id,
                        ctx.global.verbose > 0,
                        skip,
                    )?;
                    let r = crate::backup::repository::Repository {
                        ctx: &kctx,
                        config: &repo,
                        password: pw,
                    };
                    let reachable = if r.is_connected() {
                        r.status().map(|_| ())
                    } else {
                        r.connect(None)
                    };
                    match reachable {
                        Ok(()) => checks.push(Check {
                            section: "Repository",
                            name: "reachable",
                            status: Status::Ok,
                            detail: repo.display_url(),
                            help: None,
                        }),
                        Err(e) => checks.push(Check {
                            section: "Repository",
                            name: "reachable",
                            status: Status::Fail,
                            detail: format!(
                                "{} — {}",
                                repo.display_url(),
                                first_line(&e.to_string())
                            ),
                            help: Some(e.to_string()),
                        }),
                    }
                    // Kopia config file privacy (spec §5).
                    if kctx.config_file.exists() {
                        let private =
                            paths::mode_is_private(&kctx.config_file, 0o600).unwrap_or(true);
                        checks.push(Check {
                            section: "Repository",
                            name: "kopia config",
                            status: if private { Status::Ok } else { Status::Fail },
                            detail: format!(
                                "{} ({})",
                                kctx.config_file.display(),
                                if private { "0600" } else { "too permissive" }
                            ),
                            help: (!private)
                                .then(|| "Fix with chmod 600; this file can hold S3 keys.".into()),
                        });
                    }
                }
                _ => checks.push(Check {
                    section: "Repository",
                    name: "reachable",
                    status: Status::Skip,
                    detail: "not checked (no credentials or no Kopia)".into(),
                    help: None,
                }),
            }
            match repo.recovery_acknowledged_at {
                Some(t) => checks.push(Check {
                    section: "Repository",
                    name: "recovery",
                    status: Status::Ok,
                    detail: format!("acknowledged {}", t.format("%Y-%m-%d")),
                    help: None,
                }),
                None => checks.push(Check {
                    section: "Repository",
                    name: "recovery",
                    status: Status::Fail,
                    detail: "recovery sheet not acknowledged".into(),
                    help: Some("Run `moss init` again and confirm you stored the sheet; `moss backup` refuses until then.".into()),
                }),
            }
        }
    }

    // Platform
    match tcc::full_disk_access(&home) {
        FdaStatus::Granted => checks.push(Check {
            section: "Platform",
            name: "full disk access",
            status: Status::Ok,
            detail: "granted".into(),
            help: None,
        }),
        FdaStatus::Denied { probe } => checks.push(Check {
            section: "Platform",
            name: "full disk access",
            status: Status::Fail,
            detail: format!(
                "NOT granted ({} is EPERM)",
                crate::model::home_relative(&probe, &home)
            ),
            help: Some(format!(
                "~/Library/Mail and other protected paths will be skipped.\n{}",
                tcc::FDA_HELP
            )),
        }),
        FdaStatus::NotApplicable => checks.push(Check {
            section: "Platform",
            name: "full disk access",
            status: Status::Skip,
            detail: if cfg!(target_os = "macos") {
                "no protected path present to probe".into()
            } else {
                "not applicable".into()
            },
            help: None,
        }),
    }
    #[cfg(target_os = "macos")]
    if std::env::var_os("XPC_SERVICE_NAME").is_some_and(|v| v.to_string_lossy().contains("launchd"))
        || std::env::var_os("TERM_PROGRAM").is_none() && !console.stdout_tty
    {
        checks.push(Check {
            section: "Platform",
            name: "session",
            status: Status::Warn,
            detail: "not running from a terminal; TCC grants of your terminal do not apply".into(),
            help: Some("A launchd job may capture less than an interactive run (spec §32).".into()),
        });
    }
    let dirs_ok = ctx.paths.ensure().is_ok();
    checks.push(Check {
        section: "Platform",
        name: "state directory",
        status: if dirs_ok { Status::Ok } else { Status::Fail },
        detail: ctx.paths.state_dir.display().to_string(),
        help: None,
    });

    // YubiKey
    let yk = crate::yubikey::provider();
    let keys = yk.detect().unwrap_or_default();
    checks.push(Check {
        section: "YubiKey",
        name: "status",
        status: Status::Skip,
        detail: if keys.is_empty() {
            "not configured".into()
        } else {
            format!("{} detected", keys.len())
        },
        help: None,
    });

    // Scan index
    let index = ScanIndex::load(&ctx.paths.scan_index());
    match index.refreshed_at {
        Some(t) => {
            let age = (chrono::Utc::now() - t).num_seconds();
            checks.push(Check {
                section: "Scan index",
                name: if age < 86_400 { "fresh" } else { "stale" },
                status: if age < 86_400 {
                    Status::Ok
                } else {
                    Status::Warn
                },
                detail: format!(
                    "last scanned {} ({} ago)",
                    t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M"),
                    crate::output::human::age(age)
                ),
                help: None,
            });
        }
        None => checks.push(Check {
            section: "Scan index",
            name: "absent",
            status: Status::Warn,
            detail: "no scan yet".into(),
            help: Some("Run `moss inspect`.".into()),
        }),
    }

    let ok = checks.iter().all(|c| c.status != Status::Fail);
    if console.json {
        console.json_report(&Report { ok, checks })?;
    } else {
        let mut section = "";
        for c in &checks {
            if c.section != section {
                if !section.is_empty() {
                    println!();
                }
                section = c.section;
                println!("{section}");
            }
            let mark = match c.status {
                Status::Ok => console.ok_mark(),
                Status::Warn => console.warn_mark(),
                Status::Fail => console.fail_mark(),
                Status::Skip => console.na_mark(),
            };
            println!("  {mark} {:<18} {}", c.name, c.detail);
            if matches!(c.status, Status::Fail | Status::Warn)
                && let Some(h) = &c.help
            {
                for line in h.lines() {
                    println!("      {line}");
                }
            }
        }
    }
    Ok(if ok {
        ExitCode::Success
    } else {
        ExitCode::General
    })
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
}
