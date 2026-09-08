//! `moss inspect` (spec §13): what will be backed up, what is excluded, and
//! what could not be read. Works offline; never touches the repository unless
//! `--estimate` is given.

use std::collections::BTreeMap;

use clap::Args;
use serde::Serialize;

use crate::cli::AppContext;
use crate::error::{ExitCode, Result};
use crate::model::Inclusion;
use crate::output::human;
use crate::profile::discovery;
use crate::scan::{self, ScanOptions, ScanResult};

#[derive(Debug, Args)]
pub struct InspectArgs {
    /// Force a full walk, ignoring the scan index.
    #[arg(long)]
    pub rescan: bool,
    /// Walk excluded directories to measure their size (slower).
    #[arg(long)]
    pub measure_excluded: bool,
    /// Also report the repository's current size (needs credentials and network).
    #[arg(long)]
    pub estimate: bool,
    /// Show every skipped path, not just the first 20.
    #[arg(long)]
    pub all: bool,
}

#[derive(Serialize)]
struct Report<'a> {
    profile: Profile,
    included: Vec<&'a scan::SourceStats>,
    included_by_category: BTreeMap<String, u64>,
    opt_in: Vec<OptIn>,
    sensitive: BTreeMap<String, u64>,
    excluded:
        &'a BTreeMap<crate::profile::patterns::ExclusionKind, crate::scan::walker::ExcludedStats>,
    skipped: &'a [crate::backup::manifest::Skipped],
    collisions: &'a [crate::backup::manifest::Collision],
    guardrails: Vec<scan::GuardrailWarning>,
    estimate: Estimate,
    scan_index_age_seconds: Option<i64>,
    rescanned: bool,
}

#[derive(Serialize)]
struct Profile {
    user: String,
    os: String,
    home: String,
    identity: String,
}

#[derive(Serialize)]
struct OptIn {
    id: String,
    path: String,
    reason: String,
}

#[derive(Serialize)]
struct Estimate {
    raw_bytes: u64,
    files: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_snapshots: Option<usize>,
}

pub fn run(ctx: &AppContext, args: InspectArgs) -> Result<ExitCode> {
    let console = ctx.console;
    let config = ctx.load_config_or_default()?;
    let adapter = ctx.adapter();
    let host = crate::platform::host_info(adapter);
    ctx.paths.ensure()?;

    // Prefer the sources written at init; fall back to live discovery.
    let sources = if config.sources.is_empty() {
        discovery::discover(adapter, &config)
    } else {
        config.sources.clone()
    };
    let selected = discovery::selected(&sources, &config);
    let mut index = scan::index::ScanIndex::load(&ctx.paths.scan_index());
    let rules = scan::build_rules(&config, adapter, &ctx.paths, &mut index)?;
    let result = scan::scan(
        ctx.progress_mode(),
        &ctx.paths,
        &host.home,
        &rules,
        &selected,
        &mut index,
        &ScanOptions {
            rescan: args.rescan,
            measure_excluded: args.measure_excluded,
            follow_links: config.backup.follow_symlinks,
            label: "Scanning".into(),
        },
    )?;
    let guardrails = scan::guardrails(&result, &config);

    let repository_snapshots = if args.estimate {
        let c = ctx.connect()?;
        Some(c.repository().snapshot_list(&[])?.len())
    } else {
        None
    };

    let mut by_category: BTreeMap<String, u64> = BTreeMap::new();
    for s in &result.sources {
        *by_category
            .entry(s.category.display_name().to_string())
            .or_default() += s.size;
    }
    let opt_in: Vec<OptIn> = sources
        .iter()
        .filter(|s| s.default_action == Inclusion::OptIn)
        .map(|s| OptIn {
            id: s.id.to_string(),
            path: s.home_relative(&host.home),
            reason: s.reason.clone(),
        })
        .collect();

    if console.json {
        let report = Report {
            profile: Profile {
                user: host.username.clone(),
                os: host.platform.display_name().into(),
                home: host.home.display().to_string(),
                identity: config.profile.identity.clone(),
            },
            included: result.sources.iter().collect(),
            included_by_category: by_category,
            opt_in,
            sensitive: result
                .sensitive
                .iter()
                .map(|(k, v)| (k.display_name().to_string(), *v))
                .collect(),
            excluded: &result.excluded,
            skipped: &result.skipped,
            collisions: &result.collisions,
            guardrails,
            estimate: Estimate {
                raw_bytes: result.total_size,
                files: result.total_files,
                repository_snapshots,
            },
            scan_index_age_seconds: result.index_age_seconds,
            rescanned: result.rescanned,
        };
        console.json_report(&report)?;
        return Ok(ExitCode::Success);
    }

    print_human(
        &console,
        &host,
        &config.profile.identity,
        &result,
        &by_category,
        &opt_in,
        &guardrails,
        repository_snapshots,
        args.all,
    );
    Ok(ExitCode::Success)
}

#[allow(clippy::too_many_arguments)]
fn print_human(
    console: &crate::output::Console,
    host: &crate::platform::HostInfo,
    identity: &str,
    result: &ScanResult,
    by_category: &BTreeMap<String, u64>,
    opt_in: &[OptIn],
    guardrails: &[scan::GuardrailWarning],
    repository_snapshots: Option<usize>,
    show_all: bool,
) {
    let mut out = String::new();
    out.push_str("Profile\n");
    out.push_str(&human::kv_block(&[
        ("User:".into(), host.username.clone()),
        ("OS:".into(), host.platform.display_name().into()),
        ("Home:".into(), host.home.display().to_string()),
        (
            "Identity:".into(),
            if identity.is_empty() {
                "(not set — run moss init)".into()
            } else {
                identity.into()
            },
        ),
    ]));
    out.push_str("\n\nIncluded\n");
    let mut sources: Vec<&scan::SourceStats> = result.sources.iter().collect();
    sources.sort_by_key(|s| std::cmp::Reverse(s.size));
    let rows: Vec<(String, String)> = sources
        .iter()
        .map(|s| {
            (
                s.home_relative.clone(),
                format!(
                    "{:>9}  {:>9} files{}",
                    human::bytes(s.size),
                    s.files,
                    if s.skipped > 0 {
                        format!("  ({} skipped)", s.skipped)
                    } else {
                        String::new()
                    }
                ),
            )
        })
        .collect();
    out.push_str(&human::kv_block(&rows));
    out.push_str("\n\nBy category\n");
    let mut cats: Vec<(&String, &u64)> = by_category.iter().collect();
    cats.sort_by_key(|(_, v)| std::cmp::Reverse(**v));
    out.push_str(&human::kv_block(
        &cats
            .iter()
            .map(|(k, v)| ((*k).clone(), human::bytes(**v)))
            .collect::<Vec<_>>(),
    ));
    if !result.sensitive.is_empty() {
        out.push_str("\n\nSensitive\n");
        let rows: Vec<(String, String)> = result
            .sensitive
            .iter()
            .map(|(k, v)| {
                (
                    k.display_name().to_string(),
                    human::count(*v, "file", "files"),
                )
            })
            .collect();
        out.push_str(&human::kv_block(&rows));
    }
    if !result.excluded.is_empty() {
        out.push_str("\n\nExcluded\n");
        let rows: Vec<(String, String)> = result
            .excluded
            .iter()
            .map(|(k, v)| {
                let size = if v.measured {
                    human::bytes(v.size)
                } else {
                    "(size not measured; --measure-excluded)".into()
                };
                (
                    k.display_name().to_string(),
                    format!("{:>6} entries  {size}", v.entries),
                )
            })
            .collect();
        out.push_str(&human::kv_block(&rows));
    }
    if !opt_in.is_empty() {
        out.push_str("\n\nOpt-in (not backed up unless included)\n");
        out.push_str(&human::kv_block(
            &opt_in
                .iter()
                .map(|o| (o.path.clone(), o.reason.clone()))
                .collect::<Vec<_>>(),
        ));
    }
    out.push_str("\n\nSkipped\n");
    if result.skipped.is_empty() {
        out.push_str("  (nothing — every selected path was readable)");
    } else {
        let limit = if show_all { usize::MAX } else { 20 };
        let rows: Vec<(String, String)> = result
            .skipped
            .iter()
            .take(limit)
            .map(|s| {
                (
                    s.path.clone(),
                    format!(
                        "{}{}",
                        s.reason.display(),
                        s.errno
                            .as_ref()
                            .map(|e| format!(" [{e}]"))
                            .unwrap_or_default()
                    ),
                )
            })
            .collect();
        out.push_str(&human::kv_block(&rows));
        if result.skipped.len() > limit {
            out.push_str(&format!(
                "\n  … and {} more (--all to list)",
                result.skipped.len() - limit
            ));
        }
        if result.skipped.iter().any(crate::scan::walker::is_tcc) {
            out.push_str("\n\n  Paths marked [EPERM] are blocked by macOS privacy protection, not file permissions.\n");
            for line in crate::platform::tcc::FDA_HELP.lines() {
                out.push_str(&format!("  {line}\n"));
            }
        }
    }
    if !result.collisions.is_empty() {
        out.push_str(&format!("\n\nCollisions ({} recorded; restore to a case-insensitive filesystem will need --rename-collisions)\n", result.collisions.len()));
        for c in result.collisions.iter().take(10) {
            out.push_str(&format!("  {}\n", describe_collision(c)));
        }
        if result.collisions.len() > 10 {
            out.push_str(&format!(
                "  … and {} more (--json for the full list)\n",
                result.collisions.len() - 10
            ));
        }
    }
    out.push_str("\n\nEstimated backup size\n");
    let mut rows = vec![(
        "Raw:".to_string(),
        format!(
            "{}  ({} files)",
            human::bytes(result.total_size),
            result.total_files
        ),
    )];
    if let Some(n) = repository_snapshots {
        rows.push((
            "Existing repository:".into(),
            human::count(n as u64, "snapshot", "snapshots"),
        ));
    }
    out.push_str(&human::kv_block(&rows));
    for g in guardrails {
        out.push_str(&format!(
            "\n  {} guardrail: {}",
            console.warn_mark(),
            g.message
        ));
    }
    out.push_str(&format!(
        "\n\nScan index: {}",
        match (result.rescanned, result.index_age_seconds) {
            (true, _) => "rebuilt just now".to_string(),
            (false, Some(age)) => format!("{} old before this run; refreshed", human::age(age)),
            (false, None) => "new".to_string(),
        }
    ));
    println!("{out}");
}

pub fn describe_collision(c: &crate::backup::manifest::Collision) -> String {
    use crate::backup::manifest::Collision::*;
    match c {
        Case { paths } => format!("case: {}", paths.join(" ↔ ")),
        Normalization { paths } => format!("unicode normalization: {}", paths.join(" ↔ ")),
        WindowsIllegal { path, problem } => format!("windows-illegal: {path} ({problem})"),
        PathTooLong { path, length } => {
            format!("path too long for Windows ({length} chars): {path}")
        }
    }
}
