//! Linux containment: `openat2(2)` with `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS
//! | RESOLVE_NO_SYMLINKS` (spec §16): nothing escapes the root *and* no
//! component is ever a symlink, matching the component walk exactly. `openat2` has no glibc wrapper; `rustix` issues the raw syscall.
//! Kernels before 5.6 return `ENOSYS` (some seccomp profiles `EINVAL`); the
//! caller then falls back to the component-wise `O_NOFOLLOW | O_DIRECTORY`
//! walk in `unix.rs`. The fallback decision is cached for the process.

use std::ffi::OsString;
use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use rustix::fs::{Mode, OFlags, ResolveFlags};

use super::refused;
use super::unix::join_comps;

static UNSUPPORTED: AtomicBool = AtomicBool::new(false);

/// `None` means "openat2 is unavailable here; use the walk".
pub fn open_dir_beneath(
    root: BorrowedFd<'_>,
    comps: &[OsString],
    full: &Path,
) -> Option<io::Result<OwnedFd>> {
    if UNSUPPORTED.load(Ordering::Relaxed) {
        return None;
    }
    let rel = match join_comps(comps) {
        Ok(r) => r,
        Err(e) => return Some(Err(e)),
    };
    // RESOLVE_IN_ROOT can transiently fail with EAGAIN when the tree is being
    // renamed underneath us; retry a few times before giving up.
    for _ in 0..8 {
        match rustix::fs::openat2(
            root,
            rel.as_c_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        ) {
            Ok(fd) => return Some(Ok(fd)),
            Err(rustix::io::Errno::NOSYS) | Err(rustix::io::Errno::INVAL) => {
                UNSUPPORTED.store(true, Ordering::Relaxed);
                return None;
            }
            Err(rustix::io::Errno::AGAIN) => continue,
            Err(rustix::io::Errno::LOOP) | Err(rustix::io::Errno::XDEV) => {
                return Some(Err(refused(
                    full,
                    "the path resolves outside the destination",
                )));
            }
            Err(e) => return Some(Err(io::Error::from(e))),
        }
    }
    Some(Err(refused(
        full,
        "the path kept changing while it was being resolved",
    )))
}
