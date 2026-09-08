//! `moss doctor` (spec §7): build the report from `crate::doctor`, render it,
//! return its exit code.

use crate::cli::AppContext;
use crate::doctor::{self, CheckStatus, Report};
use crate::error::{ExitCode, MossError, Result};
use crate::output::Console;

pub fn run(ctx: &AppContext) -> Result<ExitCode> {
    let report = build(ctx)?;
    if ctx.console.json {
        ctx.console.json_report(&report)?;
    } else {
        ctx.console.raw(render(&report, &ctx.console));
    }
    Ok(report.exit_code())
}

/// Every check, in display order, against this invocation's context.
fn build(ctx: &AppContext) -> Result<Report> {
    let mut report = Report::default();
    let home = ctx.adapter().home().to_path_buf();

    let kopia_bin = doctor::check_kopia(&mut report);

    let config = ctx.load_config_or_default()?;
    match ctx.repository_config(&config) {
        Err(MossError::NotConfigured) => doctor::check_not_configured(&mut report),
        Err(e) => return Err(e),
        Ok(repo) => {
            let store = ctx.store(repo.credential_store);
            let password = doctor::check_credentials(&mut report, &repo, store.as_ref());
            doctor::check_store_probe(&mut report, &repo, store.as_ref());
            match (password, kopia_bin) {
                (Some(pw), Some(_)) => {
                    let runner = ctx.kopia_runner(&repo.id)?;
                    doctor::check_reachable(&mut report, runner.as_ref(), &repo, &pw);
                    doctor::check_kopia_config_mode(&mut report, runner.config_file());
                }
                _ => doctor::check_reachable_skipped(&mut report),
            }
            doctor::check_recovery_acknowledged(&mut report, &repo);
        }
    }

    doctor::check_full_disk_access(&mut report, &home);
    doctor::check_session(&mut report, ctx.console.stdout_tty);
    doctor::check_state_dir(&mut report, &ctx.paths);
    doctor::check_yubikey(&mut report);
    doctor::check_scan_index(&mut report, &ctx.paths.scan_index(), chrono::Utc::now());
    Ok(report)
}

/// Sections with one line per check; help lines under warnings and failures.
fn render(report: &Report, console: &Console) -> String {
    let mut out = String::new();
    let mut section = "";
    for c in report.checks() {
        if c.section != section {
            if !section.is_empty() {
                out.push('\n');
            }
            section = c.section;
            out.push_str(section);
            out.push('\n');
        }
        let mark = match c.status {
            CheckStatus::Ok => console.ok_mark(),
            CheckStatus::Warn => console.warn_mark(),
            CheckStatus::Fail => console.fail_mark(),
            CheckStatus::Skip => console.na_mark(),
        };
        out.push_str(&format!("  {mark} {:<18} {}\n", c.name, c.detail));
        if matches!(c.status, CheckStatus::Fail | CheckStatus::Warn)
            && let Some(h) = &c.help
        {
            for line in h.lines() {
                out.push_str(&format!("      {line}\n"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::Check;

    #[test]
    fn render_groups_by_section_and_shows_help_for_problems() {
        let mut r = Report::default();
        r.push(Check::ok("Kopia", "found", "/usr/bin/kopia"));
        r.push(
            Check::fail("Repository", "recovery", "not acknowledged")
                .help("Run init.\nThen confirm."),
        );
        r.push(Check::ok("Repository", "reachable", "/tmp/r").help("never shown"));
        let text = render(&r, &Console::new(false, true, 0, true));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "Kopia");
        assert!(lines[1].contains("found") && lines[1].contains("/usr/bin/kopia"));
        assert_eq!(lines[2], "");
        assert_eq!(lines[3], "Repository");
        assert!(lines[4].contains("recovery"));
        assert_eq!(lines[5], "      Run init.");
        assert_eq!(lines[6], "      Then confirm.");
        assert!(lines[7].contains("reachable"));
        assert!(!text.contains("never shown"));
    }

    /// The whole doctor pipeline against injected doubles: no PATH lookup for
    /// the repository checks, no keychain, and the JSON shape is preserved.
    #[test]
    fn build_uses_injected_store_and_runner() {
        if std::env::var_os(crate::credentials::ENV_PASSWORD).is_some() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::cli::context::tests::test_context(tmp.path());
        let report = build(&ctx).unwrap();
        let by_name = |n: &str| {
            report
                .checks()
                .iter()
                .find(|c| c.name == n)
                .unwrap_or_else(|| panic!("no check {n}"))
        };
        assert_eq!(by_name("credentials").detail, "mock");
        assert_eq!(by_name("credential store").status, CheckStatus::Ok);
        // Reachability depends on whether a real Kopia is installed (the
        // Kopia section probes PATH); either way the check ran or was skipped.
        assert!(matches!(
            by_name("reachable").status,
            CheckStatus::Ok | CheckStatus::Skip
        ));
        assert_eq!(by_name("recovery").status, CheckStatus::Fail);
        assert_eq!(by_name("state directory").status, CheckStatus::Ok);
        assert_eq!(by_name("absent").section, "Scan index");
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["ok"], false);
        assert!(json["checks"].as_array().unwrap().len() >= 7);
    }
}
