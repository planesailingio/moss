//! macOS containment: `openat` with `O_RESOLVE_BENEATH` (spec §16).
//!
//! The `libc` crate does not define `O_RESOLVE_BENEATH` for Apple targets (it
//! defines a FreeBSD constant of the same name with a different value), so the
//! value from `man 2 open` is defined here and `libc::O_RESOLVE_BENEATH` must
//! never be used. A resolution that would leave the root fails with
//! `ENOTCAPABLE`; a symlink loop fails with `ELOOP`; both are refusals.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::Path;

use super::unix::{join_comps, map_escape};

/// From `man 2 open` on macOS; verified on macOS 26 (spec §16).
pub const O_RESOLVE_BENEATH: libc::c_int = 0x1000;

pub fn open_dir_beneath(
    root: BorrowedFd<'_>,
    comps: &[OsString],
    full: &Path,
) -> io::Result<OwnedFd> {
    let rel = join_comps(comps)?;
    // SAFETY: valid descriptor and C string; flags are constants.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            rel.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | O_RESOLVE_BENEATH,
        )
    };
    if fd < 0 {
        return Err(map_escape(
            io::Error::last_os_error(),
            full,
            "the path resolves outside the destination",
        ));
    }
    // SAFETY: freshly opened descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_is_the_apple_value_not_freebsds() {
        assert_eq!(O_RESOLVE_BENEATH, 0x1000);
        assert_ne!(O_RESOLVE_BENEATH, 0x0080_0000);
    }
}
