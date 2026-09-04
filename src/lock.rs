//! The moss-level lock (spec §18): one `backup`/`restore`/`upload` at a time.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
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
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                let (pid, started) = read_holder(&mut file);
                if pid != 0 && !process_alive(pid) {
                    // Stale lock from a killed process whose OS lock somehow
                    // persisted (should not happen; advisory locks die with the
                    // process). Retry once.
                    file.lock()?;
                } else {
                    return Err(MossError::AlreadyRunning {
                        pid,
                        started,
                        path: path.to_path_buf(),
                    });
                }
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
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
        let _ = self.file.unlock();
    }
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
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 || *libc::__error() == libc::EPERM }
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
