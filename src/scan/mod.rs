//! Scanning the selected profile sources (spec §11, §13).

pub mod collisions;
pub mod index;
pub mod progress;
pub mod walker;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::backup::manifest::{Collision, Skipped};
use crate::config::{Config, MossPaths};
use crate::error::Result;
use crate::output::Console;
use crate::platform::PlatformAdapter;
use crate::profile::model::{ProfileCategory, ProfileSource, SemanticId};
use crate::profile::patterns::ExclusionKind;
use crate::profile::rules::RuleSet;
use crate::profile::sensitive::SensitiveKind;
use crate::profile::tools;
use index::ScanIndex;
use walker::{ExcludedStats, WalkOptions, walk_source};

#[derive(Debug, Clone, Serialize)]
pub struct SourceStats {
    pub id: SemanticId,
    pub path: PathBuf,
    pub home_relative: String,
    pub category: ProfileCategory,
    pub sensitive: bool,
    pub size: u64,
    pub files: u64,
    pub dirs: u64,
    pub skipped: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct ScanResult {
    pub sources: Vec<SourceStats>,
    pub excluded: BTreeMap<ExclusionKind, ExcludedStats>,
    pub skipped: Vec<Skipped>,
    pub collisions: Vec<Collision>,
    pub sensitive: BTreeMap<SensitiveKind, u64>,
    pub total_size: u64,
    pub total_files: u64,
    pub total_dirs: u64,
    pub largest_files: Vec<(PathBuf, u64)>,
    pub index_age_seconds: Option<i64>,
    pub rescanned: bool,
}

impl Serialize for ExcludedStats {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("ExcludedStats", 3)?;
        st.serialize_field("entries", &self.entries)?;
        st.serialize_field("size", &self.size)?;
        st.serialize_field("measured", &self.measured)?;
        st.end()
    }
}

impl Serialize for ExclusionKind {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            ExclusionKind::Cache => "cache",
            ExclusionKind::BuildArtifact => "build_artifact",
            ExclusionKind::Temporary => "temporary",
            ExclusionKind::CloudDrive => "cloud_drive",
            ExclusionKind::OwnState => "own_state",
            ExclusionKind::UserRule => "user_rule",
        })
    }
}

pub struct ScanOptions {
    pub rescan: bool,
    pub measure_excluded: bool,
    pub follow_links: bool,
    pub label: String,
}

/// Build the rule set for this machine: defaults, tool caches, moss's and
/// Kopia's own state, user rules.
pub fn build_rules(
    config: &Config,
    adapter: &dyn PlatformAdapter,
    paths: &MossPaths,
    index: &mut ScanIndex,
) -> Result<RuleSet> {
    let home = adapter.home();
    let now = chrono::Utc::now();
    if !index.tool_caches_fresh(now) {
        index.tool_caches = tools::query_all(&home);
        index.tool_caches_at = Some(now);
    }
    let mut extra: Vec<(PathBuf, ExclusionKind)> = Vec::new();
    for d in paths.all_dirs() {
        extra.push((d, ExclusionKind::OwnState));
    }
    for d in adapter.user_kopia_dirs() {
        extra.push((d, ExclusionKind::OwnState));
    }
    for t in &index.tool_caches {
        extra.push((t.path.clone(), ExclusionKind::Cache));
    }
    RuleSet::build(config, &home, &extra)
}

/// Scan the given sources in parallel and refresh the index.
pub fn scan(
    console: &Console,
    paths: &MossPaths,
    home: &Path,
    rules: &RuleSet,
    sources: &[&ProfileSource],
    index: &mut ScanIndex,
    opts: &ScanOptions,
) -> Result<ScanResult> {
    let now = chrono::Utc::now();
    let previous_age = index.age_seconds(now);
    let progress = progress::Progress::start(console, &opts.label, sources.len());
    let counters = progress.counters();
    let parallelism = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let per_source_threads = (parallelism / sources.len().max(1)).clamp(1, 8);
    let cached_index = if opts.rescan { None } else { Some(&*index) };

    let outputs: Vec<(usize, walker::WalkOutput)> = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        // Bound concurrent source walks by parallelism.
        let chunk = parallelism.max(1);
        let mut results = Vec::new();
        for batch in sources.chunks(chunk) {
            for (offset, src) in batch.iter().enumerate() {
                let counters = std::sync::Arc::clone(&counters);
                let idx = (results.len() + handles.len()) - handles.len() + offset;
                let _ = idx;
                handles.push(scope.spawn(move || {
                    walk_source(
                        &src.path,
                        &WalkOptions {
                            home,
                            rules,
                            index: cached_index,
                            counters: Some(counters),
                            threads: per_source_threads,
                            measure_excluded: opts.measure_excluded,
                            follow_links: opts.follow_links,
                        },
                    )
                }));
            }
            let base = results.len();
            for (i, h) in handles.drain(..).enumerate() {
                results.push((base + i, h.join().expect("walker thread panicked")));
            }
        }
        results
    });
    progress.finish();

    let mut result = ScanResult {
        index_age_seconds: previous_age,
        rescanned: opts.rescan || previous_age.is_none(),
        ..Default::default()
    };
    index.dirs.clear();
    for (i, out) in outputs {
        let src = sources[i];
        result.sources.push(SourceStats {
            id: src.id.clone(),
            path: src.path.clone(),
            home_relative: src.home_relative(home),
            category: src.category,
            sensitive: src.sensitive,
            size: out.size,
            files: out.files,
            dirs: out.dirs,
            skipped: out.skipped.len() as u64,
        });
        result.total_size += out.size;
        result.total_files += out.files;
        result.total_dirs += out.dirs;
        for (k, v) in out.excluded {
            let e = result.excluded.entry(k).or_default();
            e.entries += v.entries;
            e.size += v.size;
            e.measured = e.measured || v.measured;
        }
        result.skipped.extend(out.skipped);
        result.collisions.extend(out.collisions);
        for (k, v) in out.sensitive {
            *result.sensitive.entry(k).or_default() += v;
        }
        result.largest_files.extend(out.largest_files);
        index.dirs.extend(out.dir_stats);
    }
    result
        .largest_files
        .sort_by_key(|(_, l)| std::cmp::Reverse(*l));
    result.largest_files.truncate(10);
    result.skipped.sort_by(|a, b| a.path.cmp(&b.path));
    index.refreshed_at = Some(chrono::Utc::now());
    index.save(&paths.scan_index())?;
    Ok(result)
}

/// Guardrail evaluation (spec §10).
#[derive(Debug, Clone, Serialize)]
pub struct GuardrailWarning {
    pub message: String,
}

pub fn guardrails(result: &ScanResult, config: &Config) -> Vec<GuardrailWarning> {
    let gb = 1_000_000_000u64;
    let mut w = Vec::new();
    for s in &result.sources {
        if s.size > config.limits.max_source_size_gb * gb {
            w.push(GuardrailWarning {
                message: format!(
                    "{} is {} (limit {} GB per source)",
                    s.home_relative,
                    crate::output::human::bytes(s.size),
                    config.limits.max_source_size_gb
                ),
            });
        }
    }
    if result.total_size > config.limits.max_total_size_gb * gb {
        w.push(GuardrailWarning {
            message: format!(
                "total selection is {} (limit {} GB)",
                crate::output::human::bytes(result.total_size),
                config.limits.max_total_size_gb
            ),
        });
    }
    if result.total_files > config.limits.max_file_count {
        w.push(GuardrailWarning {
            message: format!(
                "{} files selected (limit {})",
                result.total_files, config.limits.max_file_count
            ),
        });
    }
    w
}
