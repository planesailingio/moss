//! The walk (spec §11): exclusions applied during descent, cached subtrees
//! pruned, partial failure recorded inline, parallel across sources.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use ignore::{DirEntry, WalkBuilder, WalkState};

use crate::backup::manifest::{Collision, SkipReason, Skipped};
use crate::platform::tcc::classify_io_error;
use crate::profile::model::home_relative;
use crate::profile::patterns::ExclusionKind;
use crate::profile::rules::{RuleSet, Verdict};
use crate::profile::sensitive::{self, SensitiveKind};
use crate::scan::collisions;
use crate::scan::index::{DirStats, ScanIndex, mtime_seconds};
use crate::scan::progress::Counters;

/// Everything one source walk produces.
#[derive(Debug, Default)]
pub struct WalkOutput {
    pub size: u64,
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub excluded: BTreeMap<ExclusionKind, ExcludedStats>,
    pub skipped: Vec<Skipped>,
    pub collisions: Vec<Collision>,
    pub sensitive: BTreeMap<SensitiveKind, u64>,
    /// Per-directory subtree stats for the index.
    pub dir_stats: BTreeMap<PathBuf, DirStats>,
    pub largest_files: Vec<(PathBuf, u64)>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExcludedStats {
    pub entries: u64,
    /// Bytes for excluded *files*; excluded directories are not descended, so
    /// their size is unknown unless `measure_excluded` is set.
    pub size: u64,
    pub measured: bool,
}

pub struct WalkOptions<'a> {
    pub home: &'a Path,
    pub rules: &'a RuleSet,
    pub index: Option<&'a ScanIndex>,
    pub counters: Option<Arc<Counters>>,
    pub threads: usize,
    pub measure_excluded: bool,
    pub follow_links: bool,
}

#[derive(Default)]
struct Shared {
    out: WalkOutput,
    /// Per-directory direct aggregates, rolled up into subtree stats at the end.
    direct: BTreeMap<PathBuf, (u64, u64, u64, i64)>, // size, files, dirs, mtime
}

/// Walk one source root.
pub fn walk_source(root: &Path, opts: &WalkOptions<'_>) -> WalkOutput {
    let shared = Arc::new(Mutex::new(Shared::default()));

    let root_meta = match std::fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(e) => {
            let (reason, errno) = classify_io_error(&e);
            let mut s = shared.lock().unwrap();
            s.out.skipped.push(Skipped {
                path: home_relative(root, opts.home),
                reason,
                errno,
                detail: Some(e.to_string()),
            });
            return std::mem::take(&mut s.out);
        }
    };

    // A single-file source (e.g. ~/.gitconfig).
    if root_meta.is_file() {
        let mut s = shared.lock().unwrap();
        s.out.size = root_meta.len();
        s.out.files = 1;
        if let Some(k) = sensitive::classify_path(root, opts.home) {
            *s.out.sensitive.entry(k).or_default() += 1;
        }
        if let Some(c) = &opts.counters {
            c.files.fetch_add(1, Ordering::Relaxed);
            c.bytes.fetch_add(root_meta.len(), Ordering::Relaxed);
        }
        return std::mem::take(&mut s.out);
    }

    let mut builder = WalkBuilder::new(root);
    builder
        .standard_filters(false)
        .hidden(false)
        .follow_links(opts.follow_links)
        .threads(opts.threads.max(1))
        .same_file_system(false);

    // filter_entry decides descent: exclusions and cached subtrees are pruned here.
    {
        let shared = Arc::clone(&shared);
        let rules_home = opts.home.to_path_buf();
        let index_dirs: Arc<BTreeMap<PathBuf, DirStats>> =
            Arc::new(opts.index.map(|i| i.dirs.clone()).unwrap_or_default());
        let rules: &RuleSet = opts.rules;
        // SAFETY of lifetime: WalkBuilder::filter_entry requires 'static; we
        // clone what we need. RuleSet is borrowed for the walk duration only
        // through a raw pointer wrapper because ignore's API demands 'static.
        let rules_ptr = RulesPtr(rules as *const RuleSet);
        let measure = opts.measure_excluded;
        let counters = opts.counters.clone();
        builder.filter_entry(move |entry: &DirEntry| {
            let rules = rules_ptr.get();
            let path = entry.path();
            let is_dir = entry.file_type().is_some_and(|t| t.is_dir());
            if entry.depth() == 0 {
                return true;
            }
            match rules.verdict(path, is_dir) {
                Verdict::Exclude(kind) => {
                    let (entries, size) = if is_dir && measure {
                        measure_tree(path)
                    } else if is_dir {
                        (1, 0)
                    } else {
                        (1, entry.metadata().map(|m| m.len()).unwrap_or(0))
                    };
                    let mut s = shared.lock().unwrap();
                    let e = s.out.excluded.entry(kind).or_default();
                    e.entries += entries;
                    e.size += size;
                    e.measured = measure || !is_dir;
                    false
                }
                Verdict::Include => {
                    if is_dir {
                        // Cached subtree?
                        if let Ok(meta) = entry.metadata() {
                            let mtime = mtime_seconds(&meta);
                            if let Some(cached) = index_dirs.get(path).filter(|d| d.mtime == mtime)
                            {
                                let mut s = shared.lock().unwrap();
                                s.out.dir_stats.insert(path.to_path_buf(), cached.clone());
                                // The source totals include the cached subtree.
                                s.out.size += cached.size;
                                s.out.files += cached.files;
                                s.out.dirs += cached.dirs + 1;
                                // Roll the cached subtree into the parent's direct aggregate.
                                if let Some(parent) = path.parent() {
                                    let d = s.direct.entry(parent.to_path_buf()).or_default();
                                    d.0 += cached.size;
                                    d.1 += cached.files;
                                    d.2 += cached.dirs + 1;
                                }
                                if let Some(c) = &counters {
                                    c.files.fetch_add(cached.files, Ordering::Relaxed);
                                    c.bytes.fetch_add(cached.size, Ordering::Relaxed);
                                }
                                return false;
                            }
                        }
                        // Collision check on the directory's own listing.
                        if let Ok(rd) = std::fs::read_dir(path) {
                            let names: Vec<String> = rd
                                .filter_map(|e| e.ok())
                                .map(|e| e.file_name().to_string_lossy().into_owned())
                                .collect();
                            let rel = home_relative(path, &rules_home);
                            let found = collisions::check_directory(&rel, &names);
                            if !found.is_empty() {
                                shared.lock().unwrap().out.collisions.extend(found);
                            }
                        }
                    }
                    true
                }
            }
        });
    }

    let walker = builder.build_parallel();
    let home = opts.home.to_path_buf();
    let counters = opts.counters.clone();
    walker.run(|| {
        let shared = Arc::clone(&shared);
        let home = home.clone();
        let counters = counters.clone();
        Box::new(move |result| {
            match result {
                Ok(entry) => {
                    let path = entry.path();
                    let ft = entry.file_type();
                    let meta = match entry.metadata() {
                        Ok(m) => m,
                        Err(e) => {
                            let io =
                                io_of(&e).unwrap_or_else(|| std::io::Error::other(e.to_string()));
                            record_error(&shared, &home, path, &io);
                            return WalkState::Continue;
                        }
                    };
                    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
                    let mut s = shared.lock().unwrap();
                    if ft.is_some_and(|t| t.is_dir()) {
                        let d = s.direct.entry(path.to_path_buf()).or_default();
                        d.3 = mtime_seconds(&meta);
                        if entry.depth() > 0 {
                            s.direct.entry(parent).or_default().2 += 1;
                        }
                        s.out.dirs += 1;
                        if let Some(c) = &counters {
                            c.dirs.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        let len = if ft.is_some_and(|t| t.is_symlink()) {
                            s.out.symlinks += 1;
                            0
                        } else {
                            meta.len()
                        };
                        let d = s.direct.entry(parent).or_default();
                        d.0 += len;
                        d.1 += 1;
                        s.out.size += len;
                        s.out.files += 1;
                        if let Some(k) = sensitive::classify_path(path, &home) {
                            *s.out.sensitive.entry(k).or_default() += 1;
                        }
                        let rel = home_relative(path, &home);
                        if let Some(c) = collisions::check_length(&rel) {
                            s.out.collisions.push(c);
                        }
                        if len >= 1 << 30 {
                            s.out.largest_files.push((path.to_path_buf(), len));
                        }
                        if let Some(c) = &counters {
                            c.files.fetch_add(1, Ordering::Relaxed);
                            c.bytes.fetch_add(len, Ordering::Relaxed);
                        }
                    }
                }
                Err(err) => {
                    let (path, io) = match &err {
                        ignore::Error::WithPath { path, err } => (path.clone(), io_of(err)),
                        ignore::Error::WithDepth { err, .. } => match &**err {
                            ignore::Error::WithPath { path, err } => (path.clone(), io_of(err)),
                            other => (PathBuf::new(), io_of(other)),
                        },
                        other => (PathBuf::new(), io_of(other)),
                    };
                    let e = io.unwrap_or_else(|| std::io::Error::other(err.to_string()));
                    record_error(&shared, &home, &path, &e);
                }
            }
            WalkState::Continue
        })
    });

    let mut s = shared.lock().unwrap();
    // Roll direct aggregates up into subtree stats, deepest first.
    let mut subtree: BTreeMap<PathBuf, DirStats> = std::mem::take(&mut s.out.dir_stats);
    let mut dirs: Vec<PathBuf> = s.direct.keys().cloned().collect();
    dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for dir in dirs {
        let (size, files, dcount, mtime) = s.direct[&dir];
        let mut st = DirStats {
            size,
            files,
            dirs: dcount,
            mtime,
        };
        // Cached children were already rolled into `direct` by filter_entry.
        // Children walked in this run have their subtree stats computed
        // (deepest first), so add them now.
        let walked_children: Vec<(u64, u64, u64)> = subtree
            .iter()
            .filter(|(p, _)| p.parent() == Some(dir.as_path()) && s.direct.contains_key(*p))
            .map(|(_, c)| (c.size, c.files, c.dirs))
            .collect();
        for (cs, cf, cd) in walked_children {
            st.size += cs;
            st.files += cf;
            st.dirs += cd;
        }
        subtree.insert(dir, st);
    }
    s.out.dir_stats = subtree;
    s.out.skipped.sort_by(|a, b| a.path.cmp(&b.path));
    s.out.skipped.dedup();
    s.out
        .largest_files
        .sort_by_key(|(_, l)| std::cmp::Reverse(*l));
    s.out.largest_files.truncate(10);
    if let Some(c) = &opts.counters {
        c.sources_done.fetch_add(1, Ordering::Relaxed);
    }
    std::mem::take(&mut s.out)
}

/// `WalkBuilder::filter_entry` demands a `'static + Send + Sync` closure, but
/// the rule set only needs to live for the walk. `walk_source` joins every
/// worker before returning, so the borrow is sound for the closure's lifetime.
struct RulesPtr(*const RuleSet);
impl RulesPtr {
    fn get(&self) -> &RuleSet {
        // SAFETY: see the type-level comment; the pointee is immutable and
        // outlives every use (all walker threads are joined by `walker.run`).
        unsafe { &*self.0 }
    }
}
// SAFETY: RuleSet is Send + Sync (Gitignore, PathBufs, HashMap) and is only
// read through this pointer.
unsafe impl Send for RulesPtr {}
unsafe impl Sync for RulesPtr {}

fn io_of(err: &ignore::Error) -> Option<std::io::Error> {
    err.io_error()
        .map(|e| std::io::Error::new(e.kind(), e.to_string()).into_raw(e))
}

trait IntoRaw {
    fn into_raw(self, original: &std::io::Error) -> std::io::Error;
}
impl IntoRaw for std::io::Error {
    fn into_raw(self, original: &std::io::Error) -> std::io::Error {
        match original.raw_os_error() {
            Some(code) => std::io::Error::from_raw_os_error(code),
            None => self,
        }
    }
}

fn record_error(shared: &Arc<Mutex<Shared>>, home: &Path, path: &Path, e: &std::io::Error) {
    let (reason, errno) = classify_io_error(e);
    let mut s = shared.lock().unwrap();
    s.out.skipped.push(Skipped {
        path: home_relative(path, home),
        reason,
        errno,
        detail: Some(e.to_string()),
    });
}

/// Size and entry count of an excluded tree, for `--measure-excluded`.
fn measure_tree(root: &Path) -> (u64, u64) {
    let mut entries = 0u64;
    let mut size = 0u64;
    for e in WalkBuilder::new(root)
        .standard_filters(false)
        .hidden(false)
        .follow_links(false)
        .build()
        .flatten()
    {
        entries += 1;
        if let Ok(m) = e.metadata()
            && m.is_file()
        {
            size += m.len();
        }
    }
    (entries, size)
}

/// Whether a skip reason is the TCC class (spec §8).
pub fn is_tcc(skip: &Skipped) -> bool {
    skip.reason == SkipReason::PermissionDenied
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        std::fs::create_dir_all(home.join("git/app/node_modules/pkg")).unwrap();
        std::fs::create_dir_all(home.join("git/app/src")).unwrap();
        std::fs::write(
            home.join("git/app/node_modules/pkg/index.js"),
            vec![0u8; 5000],
        )
        .unwrap();
        std::fs::write(home.join("git/app/src/main.rs"), vec![0u8; 100]).unwrap();
        std::fs::write(home.join("git/app/.env"), b"SECRET=1").unwrap();
        std::fs::write(home.join("git/app/.DS_Store"), b"x").unwrap();
        std::fs::write(home.join("git/app/Makefile"), b"all:").unwrap();
        (tmp, home)
    }

    #[test]
    fn excludes_are_pruned_and_counted() {
        let (_tmp, home) = fixture();
        let rules = RuleSet::build(&Config::default(), &home, &[]).unwrap();
        let out = walk_source(
            &home.join("git"),
            &WalkOptions {
                home: &home,
                rules: &rules,
                index: None,
                counters: None,
                threads: 2,
                measure_excluded: false,
                follow_links: false,
            },
        );
        assert_eq!(out.files, 3, "main.rs, .env, Makefile");
        assert_eq!(out.size, 100 + 8 + 4);
        assert_eq!(out.excluded[&ExclusionKind::BuildArtifact].entries, 1);
        assert_eq!(out.excluded[&ExclusionKind::Temporary].entries, 1);
        assert_eq!(out.sensitive[&SensitiveKind::DotEnv], 1);
        assert!(out.skipped.is_empty());
        let app = out.dir_stats.get(&home.join("git/app")).unwrap();
        assert_eq!(app.files, 3);
        assert_eq!(app.size, 112);
        let git = out.dir_stats.get(&home.join("git")).unwrap();
        assert_eq!(git.files, 3);
    }

    #[test]
    fn measure_excluded_sizes_excluded_trees() {
        let (_tmp, home) = fixture();
        let rules = RuleSet::build(&Config::default(), &home, &[]).unwrap();
        let out = walk_source(
            &home.join("git"),
            &WalkOptions {
                home: &home,
                rules: &rules,
                index: None,
                counters: None,
                threads: 1,
                measure_excluded: true,
                follow_links: false,
            },
        );
        let b = out.excluded[&ExclusionKind::BuildArtifact];
        assert_eq!(b.size, 5000);
        assert!(b.measured);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_directory_is_skipped_not_fatal() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, home) = fixture();
        let locked = home.join("git/locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("f"), b"x").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let rules = RuleSet::build(&Config::default(), &home, &[]).unwrap();
        let out = walk_source(
            &home.join("git"),
            &WalkOptions {
                home: &home,
                rules: &rules,
                index: None,
                counters: None,
                threads: 2,
                measure_excluded: false,
                follow_links: false,
            },
        );
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        if unsafe { libc::geteuid() } == 0 {
            return; // root reads everything
        }
        assert_eq!(out.skipped.len(), 1, "{:?}", out.skipped);
        assert_eq!(
            out.skipped[0].reason,
            SkipReason::AccessDenied,
            "mode bits are EACCES, not EPERM"
        );
        assert_eq!(out.skipped[0].errno.as_deref(), Some("EACCES"));
        assert_eq!(out.files, 3);
    }

    #[test]
    fn cached_subtrees_are_reused() {
        let (_tmp, home) = fixture();
        let rules = RuleSet::build(&Config::default(), &home, &[]).unwrap();
        let opts = |index| WalkOptions {
            home: &home,
            rules: &rules,
            index,
            counters: None,
            threads: 1,
            measure_excluded: false,
            follow_links: false,
        };
        let first = walk_source(&home.join("git"), &opts(None));
        let index = ScanIndex {
            dirs: first.dir_stats.clone(),
            ..ScanIndex::default()
        };
        let second = walk_source(&home.join("git"), &opts(Some(&index)));
        assert_eq!(second.files, first.files);
        assert_eq!(second.size, first.size);
        assert_eq!(second.dir_stats.get(&home.join("git")).unwrap().files, 3);
    }

    #[test]
    fn collisions_are_found_per_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        let d = home.join("src");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("aux.txt"), b"").unwrap();
        // A case pair can only be created on a case-sensitive filesystem; test
        // the Windows-illegal path here, the pair in collisions.rs.
        let rules = RuleSet::build(&Config::default(), &home, &[]).unwrap();
        let out = walk_source(
            &home,
            &WalkOptions {
                home: &home,
                rules: &rules,
                index: None,
                counters: None,
                threads: 1,
                measure_excluded: false,
                follow_links: false,
            },
        );
        assert!(out.collisions.iter().any(
            |c| matches!(c, Collision::WindowsIllegal { path, .. } if path.ends_with("aux.txt"))
        ));
    }
}
