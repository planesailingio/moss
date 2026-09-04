//! Windows containment: manual component-by-component traversal (spec §16).
//!
//! Windows has no per-open containment. Each component is opened with
//! `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS` so a reparse
//! point (symlink or junction) is opened *itself* rather than followed, its
//! attributes are read from the handle, and the handle's volume serial number
//! is compared with the root's. Containment is never decided by string prefix.
//! Paths handed to the OS are `\\?\`-prefixed so Win32 normalisation (trailing
//! dots and spaces, `MAX_PATH`) does not apply (spec §12).

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT,
};

use super::{EntryKind, Metadata, refused};

pub struct RootInner {
    dir: File,
    /// Canonical `\\?\` path of the root.
    path: PathBuf,
    volume_serial: u64,
}

fn verbatim(path: &Path) -> io::Result<PathBuf> {
    let canonical = std::fs::canonicalize(path)?;
    Ok(canonical)
}

fn open_reparse_aware(path: &Path, write: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    if write {
        opts.write(true).create(true);
    }
    opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
    opts.open(path)
}

fn attributes(file: &File) -> io::Result<(u32, u64, u64)> {
    let info = winapi_util::file::information(file)?;
    Ok((
        info.file_attributes() as u32,
        info.volume_serial_number(),
        info.file_index(),
    ))
}

impl RootInner {
    pub fn open(path: &Path) -> io::Result<RootInner> {
        let path = verbatim(path)?;
        let dir = open_reparse_aware(&path, false)?;
        let (attrs, serial, _) = attributes(&dir)?;
        if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{} is not a directory", path.display()),
            ));
        }
        Ok(RootInner {
            dir,
            path,
            volume_serial: serial,
        })
    }

    /// Walk `comps` beneath the root, verifying each component against the
    /// handle it was opened with. Returns the verified absolute path of the
    /// last component's directory.
    fn dir_beneath(&self, comps: &[OsString], full: &Path) -> io::Result<PathBuf> {
        let mut cur = self.path.clone();
        let (_, root_serial, root_index) = attributes(&self.dir)?;
        let mut expected_parent = root_index;
        for c in comps {
            cur.push(c);
            let handle = open_reparse_aware(&cur, false)?;
            let (attrs, serial, index) = attributes(&handle)?;
            if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(refused(
                    full,
                    "a path component is a symbolic link or junction",
                ));
            }
            if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("{} is not a directory", cur.display()),
                ));
            }
            if serial != root_serial || serial != self.volume_serial {
                return Err(refused(full, "the path crosses onto another volume"));
            }
            // The child must not be the parent (or the root) itself.
            if index == expected_parent {
                return Err(refused(full, "the path loops back on itself"));
            }
            expected_parent = index;
        }
        Ok(cur)
    }

    fn parent(&self, comps: &[OsString], full: &Path) -> io::Result<(PathBuf, PathBuf)> {
        let (name, parents) = comps
            .split_last()
            .ok_or_else(|| refused(full, "the destination root itself is not a target"))?;
        let dir = self.dir_beneath(parents, full)?;
        Ok((dir.clone(), dir.join(name)))
    }

    pub fn create_dir_all(
        &self,
        comps: &[OsString],
        _mode: Option<u32>,
        full: &Path,
    ) -> io::Result<()> {
        for depth in 1..=comps.len() {
            let dir = self.dir_beneath(&comps[..depth - 1], full)?;
            let target = dir.join(&comps[depth - 1]);
            match std::fs::create_dir(&target) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    let meta = std::fs::symlink_metadata(&target)?;
                    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                        if depth == comps.len() {
                            return Err(refused(full, "the destination is a symbolic link"));
                        }
                    } else if !meta.is_dir() {
                        return Err(io::Error::new(
                            io::ErrorKind::NotADirectory,
                            format!("{} exists and is not a directory", target.display()),
                        ));
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub fn open_for_write(
        &self,
        comps: &[OsString],
        _mode: Option<u32>,
        full: &Path,
    ) -> io::Result<File> {
        let (_, path) = self.parent(comps, full)?;
        // Open without truncation first so a reparse point is never damaged,
        // check what we opened, then truncate.
        let file = open_reparse_aware(&path, true)?;
        let (attrs, serial, _) = attributes(&file)?;
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(refused(full, "the destination is a symbolic link"));
        }
        if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                format!("{} is a directory", full.display()),
            ));
        }
        if serial != self.volume_serial {
            return Err(refused(full, "the path crosses onto another volume"));
        }
        file.set_len(0)?;
        Ok(file)
    }

    pub fn open_for_read(&self, comps: &[OsString], full: &Path) -> io::Result<File> {
        let (_, path) = self.parent(comps, full)?;
        let file = open_reparse_aware(&path, false)?;
        let (attrs, _, _) = attributes(&file)?;
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(refused(full, "the destination is a symbolic link"));
        }
        Ok(file)
    }

    pub fn symlink(&self, comps: &[OsString], target: &Path, full: &Path) -> io::Result<()> {
        let (dir, path) = self.parent(comps, full)?;
        // Decide file vs directory link from what the target is *within the
        // destination*, defaulting to a file link.
        let resolved = if target.is_absolute() {
            target.to_path_buf()
        } else {
            dir.join(target)
        };
        let is_dir = std::fs::metadata(&resolved)
            .map(|m| m.is_dir())
            .unwrap_or(false);
        if is_dir {
            std::os::windows::fs::symlink_dir(target, &path)
        } else {
            std::os::windows::fs::symlink_file(target, &path)
        }
    }

    pub fn exists(&self, comps: &[OsString], full: &Path) -> io::Result<Option<Metadata>> {
        let (_, path) = match self.parent(comps, full) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound && !super::is_containment_error(&e) => {
                return Ok(None);
            }
            Err(e) if e.kind() == io::ErrorKind::NotADirectory => return Ok(None),
            Err(e) => return Err(e),
        };
        match std::fs::symlink_metadata(&path) {
            Ok(m) => Ok(Some(metadata_from_std(&m))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn rename(
        &self,
        from: &[OsString],
        to: &[OsString],
        from_full: &Path,
        to_full: &Path,
    ) -> io::Result<()> {
        let (_, from_path) = self.parent(from, from_full)?;
        let (_, to_path) = self.parent(to, to_full)?;
        std::fs::rename(from_path, to_path)
    }

    pub fn remove_file(&self, comps: &[OsString], full: &Path) -> io::Result<()> {
        let (_, path) = self.parent(comps, full)?;
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            && meta.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0
        {
            // A directory symlink or junction is removed as a directory entry,
            // which removes the link and not its target.
            return std::fs::remove_dir(&path);
        }
        std::fs::remove_file(&path)
    }

    pub fn set_mode(&self, comps: &[OsString], _mode: u32, full: &Path) -> io::Result<()> {
        // Windows has no Unix mode bits; validating the path is all we can do.
        let _ = self.parent(comps, full)?;
        Ok(())
    }

    pub fn set_dir_modified(
        &self,
        comps: &[OsString],
        when: SystemTime,
        full: &Path,
    ) -> io::Result<()> {
        let dir = self.dir_beneath(comps, full)?;
        let handle = open_reparse_aware(&dir, true)?;
        handle.set_modified(when)
    }
}

fn metadata_from_std(m: &std::fs::Metadata) -> Metadata {
    let attrs = m.file_attributes();
    let kind = if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        EntryKind::Symlink
    } else if m.is_dir() {
        EntryKind::Dir
    } else if m.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    };
    Metadata {
        kind,
        len: m.len(),
        mode: if kind == EntryKind::Dir { 0o755 } else { 0o644 },
        modified: m.modified().ok(),
    }
}
