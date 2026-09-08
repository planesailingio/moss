//! Stage two: place a staged source into the destination through the
//! containment layer, the conflict policy and the journal (spec §16, §17).
//!
//! Nothing in staging is followed: the walk uses `symlink_metadata` and
//! `read_dir`, symlinks are recreated as symlinks, and every write goes through
//! [`Root`]. Nothing restored is ever executed.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::backup::manifest::{Collision, Manifest, ManifestSource};
use crate::error::Result;
use crate::platform::Platform;
use crate::profile::model::home_relative;
use crate::restore::conflict::{Decision, Existing, Resolver, Staged};
use crate::restore::contain::{self, Root};
use crate::restore::journal::{Action, Journal, ResumeState};
use crate::restore::report::{CollisionFailure, ConflictCounts, Rename, SkippedEntry};

/// Everything placement needs beyond the root and the staged tree.
pub struct PlaceContext<'a> {
    pub run_id: &'a str,
    pub source_id: &'a str,
    /// The source's home-relative origin path (`~/.ssh`), used to key
    /// collision renames.
    pub source_path: &'a str,
    pub source_os: Platform,
    pub dest_os: Platform,
    /// What `~` means on this machine (display and symlink policy).
    pub dest_home: &'a Path,
    pub resolver: &'a mut Resolver,
    pub journal: &'a mut Journal,
    pub resume: Option<&'a ResumeState>,
    /// Origin-relative path → replacement final name (`--rename-collisions`).
    pub renames: &'a BTreeMap<String, String>,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub placed: u64,
    pub skipped: Vec<SkippedEntry>,
    pub conflicts: ConflictCounts,
    /// Absolute paths of regular files written (for the path report).
    pub restored_files: Vec<PathBuf>,
    pub renamed: Vec<Rename>,
}

impl Outcome {
    fn skip(&mut self, source: &str, path: String, reason: String) {
        self.skipped.push(SkippedEntry {
            source: source.to_string(),
            path,
            reason,
        });
    }
}

/// Place one staged source (a directory tree or a single file) at `dest_rel`
/// beneath `root`. `dest_rel` may be empty when the source *is* the root
/// (`user_home`, `shell`).
pub fn place_source(
    root: &Root,
    staged: &Path,
    dest_rel: &Path,
    ctx: &mut PlaceContext<'_>,
) -> Result<Outcome> {
    let mut out = Outcome::default();
    let orig = ctx.source_path.to_string();
    place_entry(root, staged, dest_rel, &orig, ctx, &mut out)?;
    Ok(out)
}

fn describe(e: &io::Error) -> String {
    if contain::is_containment_error(e) {
        format!("{e} (the snapshot would write outside the destination; not restored)")
    } else {
        e.to_string()
    }
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(meta.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn mode_of(_meta: &std::fs::Metadata) -> Option<u32> {
    None
}

fn display_for(root: &Root, dest_rel: &Path, ctx: &PlaceContext<'_>) -> (PathBuf, String) {
    let abs = root.path().join(dest_rel);
    let display = home_relative(&abs, ctx.dest_home);
    (abs, display)
}

fn place_entry(
    root: &Root,
    staged: &Path,
    dest_rel: &Path,
    orig_rel: &str,
    ctx: &mut PlaceContext<'_>,
    out: &mut Outcome,
) -> Result<()> {
    let meta = match std::fs::symlink_metadata(staged) {
        Ok(m) => m,
        Err(e) => {
            let (_, display) = display_for(root, dest_rel, ctx);
            out.skip(
                ctx.source_id,
                display,
                format!("could not read staged entry: {e}"),
            );
            return Ok(());
        }
    };
    let ft = meta.file_type();
    if ft.is_symlink() {
        place_symlink(root, staged, dest_rel, ctx, out)
    } else if ft.is_dir() {
        place_dir(root, staged, dest_rel, orig_rel, &meta, ctx, out)
    } else if ft.is_file() {
        place_file(root, staged, dest_rel, &meta, ctx, out)
    } else {
        let (_, display) = display_for(root, dest_rel, ctx);
        out.skip(
            ctx.source_id,
            display,
            "special file (socket, fifo or device) is not restored".into(),
        );
        Ok(())
    }
}

fn place_dir(
    root: &Root,
    staged: &Path,
    dest_rel: &Path,
    orig_rel: &str,
    meta: &std::fs::Metadata,
    ctx: &mut PlaceContext<'_>,
    out: &mut Outcome,
) -> Result<()> {
    let (_, display) = display_for(root, dest_rel, ctx);
    let is_root = dest_rel.as_os_str().is_empty();
    let mode = mode_of(meta);
    if !is_root {
        // Writable while children are placed; the exact mode is set after.
        let creation_mode = mode.map(|m| m | 0o700);
        if let Err(e) = root.create_dir_all(dest_rel, creation_mode) {
            out.skip(
                ctx.source_id,
                format!("{display}/"),
                format!("directory not created: {}", describe(&e)),
            );
            return Ok(());
        }
    }
    let mut entries: Vec<(std::ffi::OsString, PathBuf)> = match std::fs::read_dir(staged) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| (e.file_name(), e.path()))
            .collect(),
        Err(e) => {
            out.skip(
                ctx.source_id,
                format!("{display}/"),
                format!("could not list staged directory: {e}"),
            );
            return Ok(());
        }
    };
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, child_staged) in entries {
        let name_str = name.to_string_lossy().into_owned();
        let child_orig = format!("{orig_rel}/{name_str}");
        let dest_name: PathBuf = match ctx.renames.get(&child_orig) {
            Some(new_name) => {
                out.renamed.push(Rename {
                    from: child_orig.clone(),
                    to: format!("{orig_rel}/{new_name}"),
                });
                PathBuf::from(new_name)
            }
            None => PathBuf::from(&name),
        };
        let child_dest = dest_rel.join(dest_name);
        place_entry(root, &child_staged, &child_dest, &child_orig, ctx, out)?;
    }
    if !is_root {
        if let Some(mode) = mode
            && let Err(e) = root.set_mode(dest_rel, mode)
        {
            out.skip(
                ctx.source_id,
                format!("{display}/"),
                format!("mode {mode:o} not applied: {}", describe(&e)),
            );
        }
        if let Ok(modified) = meta.modified() {
            let _ = root.set_dir_modified(dest_rel, modified);
        }
    }
    Ok(())
}

/// Shared conflict handling for files and symlinks. Returns `None` when the
/// entry is to be skipped (already recorded), otherwise the decision taken
/// (if any) for the journal.
#[allow(clippy::too_many_arguments)]
fn resolve_existing(
    root: &Root,
    dest_rel: &Path,
    abs: &Path,
    display: &str,
    staged: &Staged<'_>,
    ctx: &mut PlaceContext<'_>,
    out: &mut Outcome,
) -> Result<Option<Option<Decision>>> {
    let existing = match root.exists(dest_rel) {
        Ok(e) => e,
        Err(e) => {
            out.skip(ctx.source_id, display.to_string(), describe(&e));
            return Ok(None);
        }
    };
    let Some(existing) = existing else {
        return Ok(Some(None));
    };
    if existing.is_dir() {
        out.skip(
            ctx.source_id,
            display.to_string(),
            "a directory already exists there".into(),
        );
        return Ok(None);
    }
    let decision = if ctx.resume.is_some_and(|r| r.is_pending(abs)) {
        // Left half-written by the interrupted run: finish it.
        Decision::Overwrite
    } else {
        let open = || root.open_for_read(dest_rel);
        ctx.resolver.decide(
            &Existing {
                display,
                meta: &existing,
                open: &open,
            },
            staged,
        )?
    };
    match decision {
        Decision::Skip => {
            out.conflicts.skipped += 1;
            out.skip(
                ctx.source_id,
                display.to_string(),
                "already exists (conflict policy: skip)".into(),
            );
            return Ok(None);
        }
        Decision::Backup => {
            let backup_rel = backup_name(root, dest_rel);
            let backup_abs = root.path().join(&backup_rel);
            let rec = ctx.journal.intend(
                ctx.run_id,
                ctx.source_id,
                abs,
                Action::BackupExisting,
                Some(decision.label()),
                Some(&backup_abs),
            )?;
            if let Err(e) = root.rename_within(dest_rel, &backup_rel) {
                ctx.journal.abandon(&rec, &e.to_string())?;
                out.skip(
                    ctx.source_id,
                    display.to_string(),
                    format!("existing file could not be moved aside: {}", describe(&e)),
                );
                return Ok(None);
            }
            ctx.journal.done(&rec)?;
            out.conflicts.backed_up += 1;
        }
        Decision::Overwrite => {
            // Remove first so the write never goes through an existing
            // symlink or a hardlinked inode.
            if let Err(e) = root.remove_file(dest_rel) {
                out.skip(
                    ctx.source_id,
                    display.to_string(),
                    format!("existing file could not be replaced: {}", describe(&e)),
                );
                return Ok(None);
            }
            out.conflicts.overwritten += 1;
        }
    }
    Ok(Some(Some(decision)))
}

fn backup_name(root: &Root, dest_rel: &Path) -> PathBuf {
    let name = dest_rel
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let parent = dest_rel.parent().unwrap_or(Path::new(""));
    let mut candidate = parent.join(format!("{name}.moss-backup-{stamp}"));
    let mut n = 1;
    while matches!(root.exists(&candidate), Ok(Some(_))) {
        candidate = parent.join(format!("{name}.moss-backup-{stamp}-{n}"));
        n += 1;
    }
    candidate
}

fn place_file(
    root: &Root,
    staged: &Path,
    dest_rel: &Path,
    meta: &std::fs::Metadata,
    ctx: &mut PlaceContext<'_>,
    out: &mut Outcome,
) -> Result<()> {
    let (abs, display) = display_for(root, dest_rel, ctx);
    if ctx.resume.is_some_and(|r| r.is_done(&abs)) {
        out.placed += 1;
        out.restored_files.push(abs);
        return Ok(());
    }
    let mode = mode_of(meta);
    let modified = meta.modified().ok();
    let staged_side = Staged {
        path: staged,
        len: meta.len(),
        mode: mode.unwrap_or(0o644),
        modified,
    };
    let Some(decision) = resolve_existing(root, dest_rel, &abs, &display, &staged_side, ctx, out)?
    else {
        return Ok(());
    };
    let rec = ctx.journal.intend(
        ctx.run_id,
        ctx.source_id,
        &abs,
        Action::Write,
        decision.map(Decision::label),
        None,
    )?;
    match copy_file(root, staged, dest_rel, mode, modified) {
        Ok(()) => {
            ctx.journal.done(&rec)?;
            out.placed += 1;
            out.restored_files.push(abs);
        }
        Err(e) => {
            // Leave nothing half-written behind, then settle the journal
            // entry so the next run does not report an interrupted restore.
            let _ = root.remove_file(dest_rel);
            ctx.journal.abandon(&rec, &e.to_string())?;
            out.skip(ctx.source_id, display, describe(&e));
        }
    }
    Ok(())
}

fn copy_file(
    root: &Root,
    staged: &Path,
    dest_rel: &Path,
    mode: Option<u32>,
    modified: Option<SystemTime>,
) -> io::Result<()> {
    let mut src = std::fs::File::open(staged)?;
    let mut dst = root.open_for_write(dest_rel, mode)?;
    io::copy(&mut src, &mut dst)?;
    // The journal marks this file done right after we return; make sure the
    // bytes are durable first, or a crash leaves a `done` for an empty file.
    dst.sync_data()?;
    if let Some(m) = modified {
        let _ = dst.set_modified(m);
    }
    Ok(())
}

fn place_symlink(
    root: &Root,
    staged: &Path,
    dest_rel: &Path,
    ctx: &mut PlaceContext<'_>,
    out: &mut Outcome,
) -> Result<()> {
    let (abs, display) = display_for(root, dest_rel, ctx);
    if ctx.resume.is_some_and(|r| r.is_done(&abs)) {
        out.placed += 1;
        return Ok(());
    }
    let target = match std::fs::read_link(staged) {
        Ok(t) => t,
        Err(e) => {
            out.skip(
                ctx.source_id,
                display,
                format!("could not read symlink: {e}"),
            );
            return Ok(());
        }
    };
    if ctx.source_os != ctx.dest_os && target.is_absolute() && !target.starts_with(ctx.dest_home) {
        out.skip(
            ctx.source_id,
            display,
            format!(
                "symlink not supported here: target {} is outside this home and came from {}",
                target.display(),
                ctx.source_os.display_name()
            ),
        );
        return Ok(());
    }
    let staged_side = Staged {
        path: staged,
        len: 0,
        mode: 0o777,
        modified: None,
    };
    let Some(decision) = resolve_existing(root, dest_rel, &abs, &display, &staged_side, ctx, out)?
    else {
        return Ok(());
    };
    let rec = ctx.journal.intend(
        ctx.run_id,
        ctx.source_id,
        &abs,
        Action::Symlink,
        decision.map(Decision::label),
        None,
    )?;
    match root.symlink(dest_rel, &target) {
        Ok(()) => {
            ctx.journal.done(&rec)?;
            out.placed += 1;
        }
        Err(e) => {
            ctx.journal.abandon(&rec, &e.to_string())?;
            let reason = if contain::is_privilege_error(&e) {
                format!(
                    "symlink not supported here: creating symlinks needs Developer Mode or elevation (target {})",
                    target.display()
                )
            } else {
                format!("symlink not created: {}", describe(&e))
            };
            out.skip(ctx.source_id, display, reason);
        }
    }
    Ok(())
}

/// The outcome of checking a source's recorded collisions against the
/// destination filesystem.
#[derive(Debug, Default)]
pub struct CollisionCheck {
    pub blocked: Vec<CollisionFailure>,
    /// Origin-relative path → new final name.
    pub renames: BTreeMap<String, String>,
}

fn under_source(path: &str, source_path: &str) -> bool {
    if source_path == "~" {
        return path.starts_with("~/") || path == "~";
    }
    path == source_path
        || path
            .strip_prefix(source_path)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Spec §12: a recorded case or normalization collision under this source
/// fails loudly when the destination folds that property, unless renaming
/// was explicitly requested. `probe` is `(case_insensitive, normalization_insensitive)`.
pub fn check_collisions(
    manifest: &Manifest,
    source: &ManifestSource,
    probe: (bool, bool),
    rename: bool,
) -> CollisionCheck {
    let mut check = CollisionCheck::default();
    for c in &manifest.collisions {
        let (kind, paths, folds) = match c {
            Collision::Case { paths } => ("case", paths, probe.0),
            Collision::Normalization { paths } => ("normalization", paths, probe.1),
            _ => continue,
        };
        if !folds {
            continue;
        }
        let mut relevant: Vec<String> = paths
            .iter()
            .filter(|p| under_source(p, &source.path))
            .cloned()
            .collect();
        if relevant.len() < 2 {
            continue;
        }
        relevant.sort();
        if rename {
            for (i, p) in relevant.iter().enumerate() {
                let name = p.rsplit('/').next().unwrap_or(p);
                check.renames.insert(p.clone(), format!("{name}.{}", i + 1));
            }
        } else {
            check.blocked.push(CollisionFailure {
                source: source.id.to_string(),
                kind: kind.into(),
                paths: relevant,
            });
        }
    }
    check
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::config::ConflictPolicy;
    use crate::profile::model::ProfileCategory;
    use crate::restore::journal;
    use crate::restore::test_support::{sample_manifest, source};
    use std::os::unix::fs::PermissionsExt;

    struct Fx {
        tmp: tempfile::TempDir,
        home: PathBuf,
        staged: PathBuf,
        journal_path: PathBuf,
    }

    fn fixture() -> Fx {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let staged = tmp.path().join("staging/ssh");
        std::fs::create_dir_all(staged.join("sub")).unwrap();
        std::fs::write(staged.join("id_ed25519"), b"KEY").unwrap();
        std::fs::set_permissions(
            staged.join("id_ed25519"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::write(staged.join("config"), b"Host x\n").unwrap();
        std::fs::set_permissions(
            staged.join("config"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        std::fs::write(staged.join("sub/inner"), b"inner").unwrap();
        std::fs::set_permissions(staged.join("sub"), std::fs::Permissions::from_mode(0o500))
            .unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink("config", staged.join("rel_link")).unwrap();
        std::os::unix::fs::symlink("/Users/other/.ssh/config", staged.join("abs_link")).unwrap();
        Fx {
            journal_path: tmp.path().join("journal"),
            tmp,
            home,
            staged,
        }
    }

    fn run(
        fx: &Fx,
        policy: ConflictPolicy,
        source_os: Platform,
        resume: Option<&ResumeState>,
        renames: &BTreeMap<String, String>,
    ) -> Outcome {
        let root = Root::open(&fx.home).unwrap();
        let mut resolver = Resolver::with_prompt(policy, |_| Ok("s".into()), |_| {});
        let mut journal = Journal::open(&fx.journal_path).unwrap();
        let mut ctx = PlaceContext {
            run_id: "01TEST",
            source_id: "ssh",
            source_path: "~/.ssh",
            source_os,
            dest_os: Platform::current(),
            dest_home: &fx.home,
            resolver: &mut resolver,
            journal: &mut journal,
            resume,
            renames,
        };
        place_source(&root, &fx.staged, Path::new(".ssh"), &mut ctx).unwrap()
    }

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn places_tree_with_exact_modes_and_symlink_policy() {
        let fx = fixture();
        // Cross-OS: the absolute link outside this home is skipped. Pick a
        // source OS that differs from the host so the check fires everywhere.
        let other_os = if Platform::current() == Platform::Linux {
            Platform::MacOs
        } else {
            Platform::Linux
        };
        let out = run(&fx, ConflictPolicy::Skip, other_os, None, &BTreeMap::new());
        assert_eq!(out.placed, 4, "{out:?}"); // 3 files + relative link
        assert_eq!(out.skipped.len(), 1);
        assert!(out.skipped[0].reason.contains("symlink not supported here"));
        assert_eq!(out.skipped[0].path, "~/.ssh/abs_link");
        let ssh = fx.home.join(".ssh");
        assert_eq!(mode(&ssh), 0o700);
        assert_eq!(mode(&ssh.join("id_ed25519")), 0o600);
        assert_eq!(mode(&ssh.join("config")), 0o644);
        assert_eq!(mode(&ssh.join("sub")), 0o500);
        assert_eq!(std::fs::read(ssh.join("sub/inner")).unwrap(), b"inner");
        assert_eq!(
            std::fs::read_link(ssh.join("rel_link")).unwrap(),
            PathBuf::from("config")
        );
        assert!(!ssh.join("abs_link").exists());
        assert_eq!(out.restored_files.len(), 3);
        // Every journal intention is done.
        let records = journal::load(&fx.journal_path).unwrap();
        assert!(journal::incomplete(&records).is_none());
        assert_eq!(
            records
                .iter()
                .filter(|r| r.state == journal::State::Done)
                .count(),
            4
        );
        // Same OS: the absolute link is recreated verbatim.
        std::fs::set_permissions(ssh.join("sub"), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&ssh).unwrap();
        let out = run(
            &fx,
            ConflictPolicy::Skip,
            Platform::current(),
            None,
            &BTreeMap::new(),
        );
        assert_eq!(out.placed, 5);
        assert_eq!(
            std::fs::read_link(ssh.join("abs_link")).unwrap(),
            PathBuf::from("/Users/other/.ssh/config")
        );
        std::fs::set_permissions(ssh.join("sub"), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn conflict_policies() {
        let fx = fixture();
        let ssh = fx.home.join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("config"), b"mine").unwrap();
        // Skip keeps the existing file and reports it.
        let out = run(
            &fx,
            ConflictPolicy::Skip,
            Platform::current(),
            None,
            &BTreeMap::new(),
        );
        assert_eq!(out.conflicts.skipped, 1);
        assert_eq!(std::fs::read(ssh.join("config")).unwrap(), b"mine");
        assert!(out.skipped.iter().any(|s| s.path == "~/.ssh/config"));
        // Backup moves it aside. Start from a directory holding only the
        // conflicting file, since the Skip run above placed the rest.
        std::fs::set_permissions(ssh.join("sub"), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&ssh).unwrap();
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("config"), b"mine").unwrap();
        let out = run(
            &fx,
            ConflictPolicy::Backup,
            Platform::current(),
            None,
            &BTreeMap::new(),
        );
        assert_eq!(out.conflicts.backed_up, 1);
        assert_eq!(std::fs::read(ssh.join("config")).unwrap(), b"Host x\n");
        let backups: Vec<_> = std::fs::read_dir(&ssh)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("config.moss-backup-")
            })
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(std::fs::read(backups[0].path()).unwrap(), b"mine");
        // Overwrite replaces, including a symlink sitting at the destination.
        std::fs::remove_file(ssh.join("config")).unwrap();
        let outside = fx.tmp.path().join("outside");
        std::fs::write(&outside, b"victim").unwrap();
        std::os::unix::fs::symlink(&outside, ssh.join("config")).unwrap();
        let out = run(
            &fx,
            ConflictPolicy::Overwrite,
            Platform::current(),
            None,
            &BTreeMap::new(),
        );
        assert!(out.conflicts.overwritten >= 1);
        assert!(
            std::fs::symlink_metadata(ssh.join("config"))
                .unwrap()
                .is_file()
        );
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"victim",
            "symlink target untouched"
        );
        // Interactive without a terminal is exit 13.
        std::fs::set_permissions(ssh.join("sub"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = Root::open(&fx.home).unwrap();
        let console = crate::output::Console::for_tests();
        let mut resolver = Resolver::new(ConflictPolicy::Interactive, &console);
        let mut journal = Journal::open(&fx.journal_path).unwrap();
        let renames = BTreeMap::new();
        let mut ctx = PlaceContext {
            run_id: "01TEST",
            source_id: "ssh",
            source_path: "~/.ssh",
            source_os: Platform::current(),
            dest_os: Platform::current(),
            dest_home: &fx.home,
            resolver: &mut resolver,
            journal: &mut journal,
            resume: None,
            renames: &renames,
        };
        let err = place_source(&root, &fx.staged, Path::new(".ssh"), &mut ctx).unwrap_err();
        assert_eq!(err.exit_code().code(), 13);
    }

    #[test]
    fn resume_skips_done_and_overwrites_pending() {
        let fx = fixture();
        let ssh = fx.home.join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("config"), b"done-earlier").unwrap();
        std::fs::write(ssh.join("id_ed25519"), b"half").unwrap();
        let mut resume = ResumeState::default();
        resume.done.insert(ssh.join("config"));
        resume.pending.insert(ssh.join("id_ed25519"));
        let out = run(
            &fx,
            ConflictPolicy::Skip,
            Platform::current(),
            Some(&resume),
            &BTreeMap::new(),
        );
        assert_eq!(std::fs::read(ssh.join("config")).unwrap(), b"done-earlier");
        assert_eq!(std::fs::read(ssh.join("id_ed25519")).unwrap(), b"KEY");
        assert_eq!(out.conflicts.skipped, 0);
        std::fs::set_permissions(ssh.join("sub"), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn pre_existing_destination_symlink_is_refused() {
        let fx = fixture();
        let outside = fx.tmp.path().join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, fx.home.join(".ssh")).unwrap();
        let out = run(
            &fx,
            ConflictPolicy::Overwrite,
            Platform::current(),
            None,
            &BTreeMap::new(),
        );
        assert_eq!(out.placed, 0);
        assert_eq!(out.skipped.len(), 1);
        assert!(
            out.skipped[0].reason.contains("outside the destination"),
            "{:?}",
            out.skipped
        );
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
    }

    #[test]
    fn collision_renames_apply_during_placement() {
        let fx = fixture();
        std::fs::write(fx.staged.join("Makefile"), b"A").unwrap();
        let mut m = sample_manifest();
        m.collisions.push(Collision::Case {
            paths: vec!["~/.ssh/Makefile".into(), "~/.ssh/makefile".into()],
        });
        m.collisions.push(Collision::Case {
            paths: vec!["~/Documents/A".into(), "~/Documents/a".into()],
        });
        let ssh = source("ssh", ProfileCategory::Credentials, "~/.ssh");
        let blocked = check_collisions(&m, &ssh, (true, true), false);
        assert_eq!(blocked.blocked.len(), 1);
        assert_eq!(blocked.blocked[0].paths.len(), 2);
        assert!(
            check_collisions(&m, &ssh, (false, false), false)
                .blocked
                .is_empty()
        );
        let renamed = check_collisions(&m, &ssh, (true, false), true);
        assert!(renamed.blocked.is_empty());
        assert_eq!(
            renamed.renames.get("~/.ssh/Makefile").unwrap(),
            "Makefile.1"
        );
        assert_eq!(
            renamed.renames.get("~/.ssh/makefile").unwrap(),
            "makefile.2"
        );
        let out = run(
            &fx,
            ConflictPolicy::Skip,
            Platform::current(),
            None,
            &renamed.renames,
        );
        assert!(fx.home.join(".ssh/Makefile.1").exists());
        assert_eq!(out.renamed.len(), 1);
        assert_eq!(out.renamed[0].to, "~/.ssh/Makefile.1");
        std::fs::set_permissions(
            fx.home.join(".ssh/sub"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        // A home-wide source matches everything.
        let home = source("user_home", ProfileCategory::PersonalData, "~");
        assert_eq!(
            check_collisions(&m, &home, (true, true), false)
                .blocked
                .len(),
            2
        );
    }
}
