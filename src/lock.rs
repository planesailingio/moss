//! The moss-level lock (spec §18): one `backup`/`restore`/`upload` at a time.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{MossError, Result};

#[derive(Debug)]
pub struct Lock {
    file: File,
    path: PathBuf,
}

impl Lock {
    /// Acquire, or fail with `AlreadyRunning` naming the holder.
    pub fn acquire(path: &Path) -> Result<Lock> {
        if let Some(parent) = path.parent() {
            crate::config::paths::create_private_dir(parent)?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        match try_lock(&file) {
            Ok(true) => {}
            Ok(false) => {
                let (pid, started) = read_holder(&mut file);
                if pid != 0 && !process_alive(pid) {
                    // Stale lock from a killed process whose OS lock somehow
                    // persisted (should not happen; advisory locks die with the
                    // process). Retry once.
                    lock_blocking(&file)?;
                } else {
                    return Err(MossError::AlreadyRunning {
                        pid,
                        started,
                        path: path.to_path_buf(),
                    });
                }
            }
            Err(e) => return Err(e.into()),
        }
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        writeln!(
            file,
            "{}\n{}",
            std::process::id(),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        )?;
        file.sync_all()?;
        crate::config::paths::make_private_file(path)?;
        Ok(Lock {
            file,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.file.set_len(0);
        let _ = unlock(&self.file);
    }
}

/// Try to take the lock without blocking. `Ok(false)` means another handle
/// holds it.
#[cfg(not(windows))]
fn try_lock(file: &File) -> io::Result<bool> {
    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
}

#[cfg(not(windows))]
fn lock_blocking(file: &File) -> io::Result<()> {
    file.lock()
}

#[cfg(not(windows))]
fn unlock(file: &File) -> io::Result<()> {
    file.unlock()
}

// On Windows a `LockFileEx` range is mandatory: other handles cannot even
// read the locked bytes, so contenders could never learn the holder's pid.
// Lock a single byte far past any content instead, leaving the holder record
// itself readable.
#[cfg(windows)]
const LOCK_OFFSET_HIGH: u32 = 0x4000_0000;

#[cfg(windows)]
fn lock_windows(file: &File, flags: u32) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::LockFileEx;
    use windows_sys::Win32::System::IO::OVERLAPPED;
    // SAFETY: OVERLAPPED is plain data; the handle is valid for `file`'s
    // lifetime and the call is synchronous for a non-overlapped handle.
    unsafe {
        let mut ov: OVERLAPPED = std::mem::zeroed();
        ov.Anonymous.Anonymous.Offset = 0;
        ov.Anonymous.Anonymous.OffsetHigh = LOCK_OFFSET_HIGH;
        if LockFileEx(file.as_raw_handle(), flags, 0, 1, 0, &mut ov) == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn try_lock(file: &File) -> io::Result<bool> {
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    match lock_windows(file, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY) {
        Ok(()) => Ok(true),
        Err(e) if e.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn lock_blocking(file: &File) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::LOCKFILE_EXCLUSIVE_LOCK;
    lock_windows(file, LOCKFILE_EXCLUSIVE_LOCK)
}

#[cfg(windows)]
fn unlock(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    use windows_sys::Win32::System::IO::OVERLAPPED;
    // SAFETY: as in `lock_windows`.
    unsafe {
        let mut ov: OVERLAPPED = std::mem::zeroed();
        ov.Anonymous.Anonymous.Offset = 0;
        ov.Anonymous.Anonymous.OffsetHigh = LOCK_OFFSET_HIGH;
        if UnlockFileEx(file.as_raw_handle(), 0, 1, 0, &mut ov) == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn read_holder(file: &mut File) -> (u32, String) {
    let mut text = String::new();
    let _ = file.seek(SeekFrom::Start(0));
    let _ = file.read_to_string(&mut text);
    let mut lines = text.lines();
    let pid = lines
        .next()
        .and_then(|l| l.trim().parse().ok())
        .unwrap_or(0);
    let started = lines.next().unwrap_or("unknown").trim().to_string();
    (pid, started)
}

#[cfg(unix)]
pub fn process_alive(pid: u32) -> bool {
    // SAFETY: kill(2) with signal 0 only checks for existence.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
pub fn process_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: plain Win32 calls with a valid pid; handle is closed on all paths.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(h, &mut code) != 0;
        CloseHandle(h);
        ok && code == STILL_ACTIVE as u32
    }
}

#[cfg(not(any(unix, windows)))]
pub fn process_alive(_pid: u32) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_fails_with_holder_info() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("lock");
        let first = Lock::acquire(&path).unwrap();
        // A second handle in the same process still contends on the OS lock.
        let err = Lock::acquire(&path).unwrap_err();
        match err {
            MossError::AlreadyRunning { pid, .. } => assert_eq!(pid, std::process::id()),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(err.exit_code().code(), 10);
        drop(first);
        let _again = Lock::acquire(&path).unwrap();
    }

    #[test]
    fn current_process_is_alive() {
        assert!(process_alive(std::process::id()));
    }
}
