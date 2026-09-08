//! Unix containment: a root directory descriptor plus `*at` calls on a parent
//! descriptor that was itself opened beneath the root.
//!
//! The parent directory is opened by `openat2(RESOLVE_IN_ROOT | NO_SYMLINKS)`
//! on Linux and by the component walk below (`O_NOFOLLOW | O_DIRECTORY` per
//! component) everywhere else, including macOS, whose `O_RESOLVE_BENEATH`
//! follows in-root symlinks and so cannot honour the "never through a symlink"
//! contract. The final component is then acted on
//! with `O_NOFOLLOW` / `AT_SYMLINK_NOFOLLOW` so a symlink there is never
//! followed. Nothing re-resolves a path string after that.
//!
//! Every call goes through `rustix`, which owns the descriptors (`OwnedFd`)
//! and reports typed `Errno`s, so this module has no `unsafe` and never reads
//! `errno` by hand. Components have already been validated by
//! `super::validate_rel` (no NUL, no `..`), so they are passed as `&OsStr`.

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawMode, Stat};
use rustix::io::Errno;

use super::{EntryKind, Metadata, refused};

pub struct RootInner {
    fd: OwnedFd,
}

/// Join validated components with `/` for a single `openat2` call.
#[cfg(target_os = "linux")]
pub fn join_comps(comps: &[OsString]) -> io::Result<CString> {
    let mut bytes = Vec::new();
    for (i, c) in comps.iter().enumerate() {
        if i > 0 {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(c.as_bytes());
    }
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

/// Translate the errno a containment primitive uses for "this would leave the
/// root" into a typed refusal.
pub fn map_escape(e: Errno, full: &Path, reason: &str) -> io::Error {
    match e {
        Errno::LOOP | Errno::MLINK => refused(full, reason),
        _ => e.into(),
    }
}

/// Permission bits (`0o7777` at most) as a `Mode`; the file-type bits are
/// masked off. `RawMode` is `u16` on macOS and `u32` on Linux.
fn mode_bits(mode: u32) -> Mode {
    Mode::from_raw_mode(mode as RawMode)
}

/// Open one directory component beneath `dir`, never following a symlink.
pub fn open_component(dir: BorrowedFd<'_>, name: &OsStr, full: &Path) -> io::Result<OwnedFd> {
    match rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(fd),
        Err(e) => {
            // Linux reports a symlink under O_NOFOLLOW | O_DIRECTORY as ELOOP;
            // macOS reports ENOTDIR. ENOTDIR is also what a plain file gives,
            // so look (without following) before calling it a refusal.
            // Nothing has been acted on at this point, so the extra lstat is
            // not a race.
            if e == Errno::NOTDIR && lstat_at(dir, name)?.is_some_and(|m| m.is_symlink()) {
                return Err(refused(full, "a path component is a symbolic link"));
            }
            Err(map_escape(e, full, "a path component is a symbolic link"))
        }
    }
}

/// The generic component-by-component walk. Rejects any symlinked component
/// (`ELOOP` from `O_NOFOLLOW | O_DIRECTORY`). The Linux fallback and the
/// primitive on every other Unix.
pub fn walk(root: BorrowedFd<'_>, comps: &[OsString], full: &Path) -> io::Result<OwnedFd> {
    let mut cur = root.try_clone_to_owned()?;
    for c in comps {
        cur = open_component(cur.as_fd(), c, full)?;
    }
    Ok(cur)
}

/// Open the directory at `comps` beneath `root` with the best primitive the
/// platform has.
pub fn open_dir_beneath(
    root: BorrowedFd<'_>,
    comps: &[OsString],
    full: &Path,
) -> io::Result<OwnedFd> {
    if comps.is_empty() {
        return root.try_clone_to_owned();
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(result) = super::linux::open_dir_beneath(root, comps, full) {
            return result;
        }
    }
    walk(root, comps, full)
}

fn split_last<'a>(comps: &'a [OsString], full: &Path) -> io::Result<(&'a [OsString], &'a OsStr)> {
    match comps.split_last() {
        Some((name, parents)) => Ok((parents, name)),
        None => Err(refused(full, "the destination root itself is not a target")),
    }
}

/// Open the final component with `O_NOFOLLOW`, so a symlink there is refused
/// rather than followed.
fn open_at(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    flags: OFlags,
    mode: Mode,
    full: &Path,
) -> io::Result<File> {
    rustix::fs::openat(
        parent,
        name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        mode,
    )
    .map(File::from)
    .map_err(|e| map_escape(e, full, "the destination is a symbolic link"))
}

pub fn fchmod(file: &File, mode: u32) -> io::Result<()> {
    Ok(rustix::fs::fchmod(file, mode_bits(mode))?)
}

fn lstat_at(parent: BorrowedFd<'_>, name: &OsStr) -> io::Result<Option<Metadata>> {
    match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => Ok(Some(metadata_from_stat(&st))),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn metadata_from_stat(st: &Stat) -> Metadata {
    // `rustix::fs::Stat` mirrors the platform's own struct, so these fields
    // differ in width and signedness between macOS and Linux (`st_mode` is
    // u16 vs u32, `st_mtime_nsec` is i64 vs u64); each cast is needed on one
    // platform and flagged as redundant on the other.
    #[allow(clippy::unnecessary_cast)]
    let (mode, secs, nanos, len) = (
        st.st_mode as u32,
        st.st_mtime as i64,
        st.st_mtime_nsec as u32,
        st.st_size as u64,
    );
    let kind = match FileType::from_raw_mode(st.st_mode as RawMode) {
        FileType::RegularFile => EntryKind::File,
        FileType::Directory => EntryKind::Dir,
        FileType::Symlink => EntryKind::Symlink,
        _ => EntryKind::Other,
    };
    let modified = if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::new(secs as u64, nanos))
    } else {
        UNIX_EPOCH.checked_sub(Duration::new(secs.unsigned_abs(), 0))
    };
    Metadata {
        kind,
        len,
        mode: mode & 0o7777,
        modified,
    }
}

impl RootInner {
    pub fn open(path: &Path) -> io::Result<RootInner> {
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(RootInner { fd })
    }

    fn parent<'a>(&self, comps: &'a [OsString], full: &Path) -> io::Result<(OwnedFd, &'a OsStr)> {
        let (parents, name) = split_last(comps, full)?;
        let dir = open_dir_beneath(self.fd.as_fd(), parents, full)?;
        Ok((dir, name))
    }

    pub fn create_dir_all(
        &self,
        comps: &[OsString],
        mode: Option<u32>,
        full: &Path,
    ) -> io::Result<()> {
        for depth in 1..=comps.len() {
            let parents = &comps[..depth - 1];
            let name = comps[depth - 1].as_os_str();
            let dir = open_dir_beneath(self.fd.as_fd(), parents, full)?;
            match rustix::fs::mkdirat(&dir, name, Mode::RWXU) {
                Ok(()) => {}
                Err(Errno::EXIST) => match lstat_at(dir.as_fd(), name)? {
                    Some(m) if m.is_dir() => {}
                    Some(m) if m.is_symlink() => {
                        if depth == comps.len() {
                            return Err(refused(full, "the destination is a symbolic link"));
                        }
                        // An intermediate symlink: the next `open_dir_beneath`
                        // decides whether it stays inside the root.
                    }
                    Some(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::NotADirectory,
                            format!("{} exists and is not a directory", full.display()),
                        ));
                    }
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("{} vanished while creating it", full.display()),
                        ));
                    }
                },
                Err(e) => return Err(e.into()),
            }
        }
        if let Some(mode) = mode
            && !comps.is_empty()
        {
            self.set_mode(comps, mode, full)?;
        }
        Ok(())
    }

    pub fn open_for_write(
        &self,
        comps: &[OsString],
        mode: Option<u32>,
        full: &Path,
    ) -> io::Result<File> {
        let (dir, name) = self.parent(comps, full)?;
        let create_mode = mode.unwrap_or(0o600);
        let file = open_at(
            dir.as_fd(),
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC,
            mode_bits(create_mode),
            full,
        )?;
        if let Some(mode) = mode {
            fchmod(&file, mode)?;
        }
        Ok(file)
    }

    pub fn open_for_read(&self, comps: &[OsString], full: &Path) -> io::Result<File> {
        let (dir, name) = self.parent(comps, full)?;
        open_at(dir.as_fd(), name, OFlags::RDONLY, Mode::empty(), full)
    }

    pub fn symlink(&self, comps: &[OsString], target: &Path, full: &Path) -> io::Result<()> {
        let (dir, name) = self.parent(comps, full)?;
        Ok(rustix::fs::symlinkat(target, &dir, name)?)
    }

    pub fn exists(&self, comps: &[OsString], full: &Path) -> io::Result<Option<Metadata>> {
        let (dir, name) = match self.parent(comps, full) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound && !super::is_containment_error(&e) => {
                return Ok(None);
            }
            Err(e) if e.kind() == io::ErrorKind::NotADirectory => return Ok(None),
            Err(e) => return Err(e),
        };
        lstat_at(dir.as_fd(), name)
    }

    pub fn rename(
        &self,
        from: &[OsString],
        to: &[OsString],
        from_full: &Path,
        to_full: &Path,
    ) -> io::Result<()> {
        let (from_dir, from_name) = self.parent(from, from_full)?;
        let (to_dir, to_name) = self.parent(to, to_full)?;
        Ok(rustix::fs::renameat(
            &from_dir, from_name, &to_dir, to_name,
        )?)
    }

    pub fn remove_file(&self, comps: &[OsString], full: &Path) -> io::Result<()> {
        let (dir, name) = self.parent(comps, full)?;
        // No `AT_REMOVEDIR`: this is unlink, never rmdir.
        Ok(rustix::fs::unlinkat(&dir, name, AtFlags::empty())?)
    }

    pub fn set_mode(&self, comps: &[OsString], mode: u32, full: &Path) -> io::Result<()> {
        let (dir, name) = self.parent(comps, full)?;
        // The chmod below never follows a link, so this is a courtesy check
        // rather than a containment decision: chmod on a link's own bits is
        // pointless and callers want to know.
        if lstat_at(dir.as_fd(), name)?.is_some_and(|m| m.is_symlink()) {
            return Err(refused(full, "the destination is a symbolic link"));
        }
        match rustix::fs::chmodat(&dir, name, mode_bits(mode), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(()) => Ok(()),
            // Linux's fchmodat(2) has no flags argument, so rustix reports
            // AT_SYMLINK_NOFOLLOW there as unsupported (as older glibc does):
            // open the entry itself with O_NOFOLLOW (refusing a symlink) and
            // fchmod the descriptor instead.
            Err(e) if e == Errno::NOTSUP || e == Errno::OPNOTSUPP => {
                let file = match open_at(dir.as_fd(), name, OFlags::RDONLY, Mode::empty(), full) {
                    Ok(f) => f,
                    Err(e)
                        if e.kind() == io::ErrorKind::PermissionDenied
                            && !super::is_containment_error(&e) =>
                    {
                        open_at(dir.as_fd(), name, OFlags::WRONLY, Mode::empty(), full)?
                    }
                    Err(e) => return Err(e),
                };
                fchmod(&file, mode)
            }
            Err(e) => Err(map_escape(e, full, "the destination is a symbolic link")),
        }
    }

    pub fn set_dir_modified(
        &self,
        comps: &[OsString],
        when: SystemTime,
        full: &Path,
    ) -> io::Result<()> {
        let dir = open_dir_beneath(self.fd.as_fd(), comps, full)?;
        let file = File::from(dir);
        file.set_modified(when)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generic walk is the fallback on Linux and the primitive on other
    /// Unixes; make sure it refuses symlinked components on every host.
    #[test]
    fn walk_refuses_symlinked_components() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("real/sub")).unwrap();
        std::fs::create_dir_all(tmp.path().join("outside")).unwrap();
        std::os::unix::fs::symlink("../outside", root.join("link")).unwrap();
        std::os::unix::fs::symlink("real", root.join("inner")).unwrap();
        let inner = RootInner::open(&root).unwrap();
        let comps = |s: &str| -> Vec<OsString> { s.split('/').map(OsString::from).collect() };
        assert!(walk(inner.fd.as_fd(), &comps("real/sub"), &root).is_ok());
        let err = walk(inner.fd.as_fd(), &comps("link/x"), &root).unwrap_err();
        assert!(super::super::is_containment_error(&err), "{err:?}");
        // Even an internal symlink is rejected by the strict walk.
        let err = walk(inner.fd.as_fd(), &comps("inner"), &root).unwrap_err();
        assert!(super::super::is_containment_error(&err), "{err:?}");
        let err = walk(inner.fd.as_fd(), &comps("missing"), &root).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
