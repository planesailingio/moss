//! Unix containment: a root directory descriptor plus `*at` calls on a parent
//! descriptor that was itself opened beneath the root.
//!
//! The parent directory is opened by the platform primitive
//! (`openat2(RESOLVE_IN_ROOT)` on Linux, `openat(O_RESOLVE_BENEATH)` on macOS,
//! the component walk below elsewhere). The final component is then acted on
//! with `O_NOFOLLOW` / `AT_SYMLINK_NOFOLLOW` so a symlink there is never
//! followed. Nothing re-resolves a path string after that.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{EntryKind, Metadata, refused};

pub struct RootInner {
    fd: OwnedFd,
}

pub fn cstr(s: &OsStr) -> io::Result<CString> {
    CString::new(s.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

/// Join validated components with `/` for a single `openat` call.
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
pub fn map_escape(e: io::Error, full: &Path, reason: &str) -> io::Error {
    match e.raw_os_error() {
        Some(libc::ELOOP) | Some(libc::EMLINK) => refused(full, reason),
        #[cfg(target_os = "macos")]
        Some(libc::ENOTCAPABLE) => refused(full, reason),
        _ => e,
    }
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// Open one directory component beneath `dir`, never following a symlink.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn open_component(dir: BorrowedFd<'_>, name: &CStr, full: &Path) -> io::Result<OwnedFd> {
    // SAFETY: `name` is a valid C string and `dir` an open descriptor.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = last_error();
        // Linux reports a symlink under O_NOFOLLOW | O_DIRECTORY as ELOOP;
        // macOS reports ENOTDIR. ENOTDIR is also what a plain file gives, so
        // look (without following) before calling it a refusal. Nothing has
        // been acted on at this point, so the extra lstat is not a race.
        if e.raw_os_error() == Some(libc::ENOTDIR)
            && lstat_at(dir, name)?.is_some_and(|m| m.is_symlink())
        {
            return Err(refused(full, "a path component is a symbolic link"));
        }
        return Err(map_escape(e, full, "a path component is a symbolic link"));
    }
    // SAFETY: fd is a freshly opened descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The generic component-by-component walk. Rejects any symlinked component
/// (`ELOOP` from `O_NOFOLLOW | O_DIRECTORY`). The Linux fallback and the
/// primitive on other Unixes; exercised by tests everywhere.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn walk(root: BorrowedFd<'_>, comps: &[OsString], full: &Path) -> io::Result<OwnedFd> {
    let mut cur = root.try_clone_to_owned()?;
    for c in comps {
        cur = open_component(cur.as_fd(), &cstr(c)?, full)?;
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
        walk(root, comps, full)
    }
    #[cfg(target_os = "macos")]
    {
        super::macos::open_dir_beneath(root, comps, full)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        walk(root, comps, full)
    }
}

fn split_last<'a>(comps: &'a [OsString], full: &Path) -> io::Result<(&'a [OsString], CString)> {
    match comps.split_last() {
        Some((name, parents)) => Ok((parents, cstr(name)?)),
        None => Err(refused(full, "the destination root itself is not a target")),
    }
}

fn open_at(
    parent: BorrowedFd<'_>,
    name: &CStr,
    flags: libc::c_int,
    mode: u32,
    full: &Path,
) -> io::Result<File> {
    // SAFETY: valid descriptor and C string; mode is a plain integer.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(map_escape(
            last_error(),
            full,
            "the destination is a symbolic link",
        ));
    }
    // SAFETY: freshly opened descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub fn fchmod(file: &File, mode: u32) -> io::Result<()> {
    // SAFETY: plain fchmod on an open descriptor.
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } < 0 {
        return Err(last_error());
    }
    Ok(())
}

fn lstat_at(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<Option<Metadata>> {
    // SAFETY: stat is plain-old-data; fstatat fills it in on success.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc < 0 {
        let e = last_error();
        return if e.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(e)
        };
    }
    Ok(Some(metadata_from_stat(&st)))
}

pub fn metadata_from_stat(st: &libc::stat) -> Metadata {
    let mode = st.st_mode as u32;
    let kind = match mode & (libc::S_IFMT as u32) {
        m if m == libc::S_IFREG as u32 => EntryKind::File,
        m if m == libc::S_IFDIR as u32 => EntryKind::Dir,
        m if m == libc::S_IFLNK as u32 => EntryKind::Symlink,
        _ => EntryKind::Other,
    };
    let secs = st.st_mtime;
    let nanos = st.st_mtime_nsec as u32;
    let modified = if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::new(secs as u64, nanos))
    } else {
        UNIX_EPOCH.checked_sub(Duration::new(secs.unsigned_abs(), 0))
    };
    Metadata {
        kind,
        len: st.st_size as u64,
        mode: mode & 0o7777,
        modified,
    }
}

impl RootInner {
    pub fn open(path: &Path) -> io::Result<RootInner> {
        let c = cstr(path.as_os_str())?;
        // SAFETY: valid C string; flags are constants.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(last_error());
        }
        // SAFETY: freshly opened descriptor.
        Ok(RootInner {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    fn parent(&self, comps: &[OsString], full: &Path) -> io::Result<(OwnedFd, CString)> {
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
            let name = cstr(&comps[depth - 1])?;
            let dir = open_dir_beneath(self.fd.as_fd(), parents, full)?;
            // SAFETY: valid descriptor and C string.
            let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) };
            if rc < 0 {
                let e = last_error();
                if e.kind() != io::ErrorKind::AlreadyExists {
                    return Err(e);
                }
                match lstat_at(dir.as_fd(), &name)? {
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
                }
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
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            create_mode,
            full,
        )?;
        if let Some(mode) = mode {
            fchmod(&file, mode)?;
        }
        Ok(file)
    }

    pub fn open_for_read(&self, comps: &[OsString], full: &Path) -> io::Result<File> {
        let (dir, name) = self.parent(comps, full)?;
        open_at(dir.as_fd(), &name, libc::O_RDONLY, 0, full)
    }

    pub fn symlink(&self, comps: &[OsString], target: &Path, full: &Path) -> io::Result<()> {
        let (dir, name) = self.parent(comps, full)?;
        let target = cstr(target.as_os_str())?;
        // SAFETY: valid C strings and descriptor.
        if unsafe { libc::symlinkat(target.as_ptr(), dir.as_raw_fd(), name.as_ptr()) } < 0 {
            return Err(last_error());
        }
        Ok(())
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
        lstat_at(dir.as_fd(), &name)
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
        // SAFETY: valid descriptors and C strings.
        let rc = unsafe {
            libc::renameat(
                from_dir.as_raw_fd(),
                from_name.as_ptr(),
                to_dir.as_raw_fd(),
                to_name.as_ptr(),
            )
        };
        if rc < 0 {
            return Err(last_error());
        }
        Ok(())
    }

    pub fn remove_file(&self, comps: &[OsString], full: &Path) -> io::Result<()> {
        let (dir, name) = self.parent(comps, full)?;
        // SAFETY: valid descriptor and C string; flags 0 = unlink, not rmdir.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } < 0 {
            return Err(last_error());
        }
        Ok(())
    }

    pub fn set_mode(&self, comps: &[OsString], mode: u32, full: &Path) -> io::Result<()> {
        let (dir, name) = self.parent(comps, full)?;
        // The chmod below never follows a link, so this is a courtesy check
        // rather than a containment decision: chmod on a link's own bits is
        // pointless and callers want to know.
        if lstat_at(dir.as_fd(), &name)?.is_some_and(|m| m.is_symlink()) {
            return Err(refused(full, "the destination is a symbolic link"));
        }
        // SAFETY: valid descriptor and C string.
        let rc = unsafe {
            libc::fchmodat(
                dir.as_raw_fd(),
                name.as_ptr(),
                mode as libc::mode_t,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let e = last_error();
        match e.raw_os_error() {
            // Older glibc cannot chmod without following; open the entry
            // itself with O_NOFOLLOW (refusing a symlink) and fchmod the fd.
            Some(libc::ENOTSUP) | Some(libc::EOPNOTSUPP) => {
                let file = match open_at(dir.as_fd(), &name, libc::O_RDONLY, 0, full) {
                    Ok(f) => f,
                    Err(e)
                        if e.kind() == io::ErrorKind::PermissionDenied
                            && !super::is_containment_error(&e) =>
                    {
                        open_at(dir.as_fd(), &name, libc::O_WRONLY, 0, full)?
                    }
                    Err(e) => return Err(e),
                };
                fchmod(&file, mode)
            }
            _ => Err(map_escape(e, full, "the destination is a symbolic link")),
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
