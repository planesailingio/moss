//! Windows containment: a handle-relative walk (spec §16).
//!
//! Windows has no per-open containment primitive, so this module builds one
//! from `NtCreateFile` *relative* opens. Every path component is opened
//! relative to the handle of its verified parent (`OBJECT_ATTRIBUTES::
//! RootDirectory`) with `FILE_OPEN_REPARSE_POINT`, so a symlink or junction is
//! opened itself and never followed. The handle that comes back is inspected
//! (not a reparse point, on the root's volume, not its own parent) and then
//! becomes the parent for the next component. Every operation — create, open,
//! stat, rename (`FileRenameInformation` with a `RootDirectory` handle),
//! delete (`FileDispositionInformationEx`) — acts on such a handle. No path
//! string is re-resolved after validation, so a junction swapped in between
//! check and use cannot redirect a write (TOCTOU, spec §16). Containment is
//! never decided by string prefix.
//!
//! Any reparse point, whatever its tag (symlink, junction, mount point, cloud
//! placeholder), is treated as a link: refused where a link would be and
//! reported as [`EntryKind::Symlink`] by `exists`. That is deliberately
//! conservative.
//!
//! **The one residual window: symlink creation.** Win32 creates symlinks only
//! by path. [`RootInner::symlink`] derives the parent directory's path from
//! the verified parent *handle* (`GetFinalPathNameByHandleW`), creates the link
//! there, and immediately re-opens the new name relative to the parent handle
//! to confirm a reparse point now sits beneath it; if not, the created entry is
//! removed and the write refused. Between the path lookup and the creation a
//! swapped parent directory could make the link land in another directory the
//! user can write to. Nothing else in this module touches a path.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::offset_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_DELETE,
    FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_INFORMATION,
    FILE_DISPOSITION_INFORMATION_EX, FILE_DISPOSITION_POSIX_SEMANTICS, FILE_INFORMATION_CLASS,
    FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION,
    FILE_SYNCHRONOUS_IO_NONALERT, FileDispositionInformation, FileDispositionInformationEx,
    FileRenameInformation, NtCreateFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    HANDLE, NTSTATUS, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FileIdInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, SYNCHRONIZE, VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::{EntryKind, Metadata, refused};

/// Enough access to use a directory handle as `RootDirectory` and stat it.
const DIR_ACCESS: u32 = FILE_READ_ATTRIBUTES | SYNCHRONIZE;
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

/// A file's identity on its volume: the 128-bit id from `FileIdInfo` (ReFS
/// needs the width; NTFS zero-pads its 64-bit id), or the 64-bit index from
/// `GetFileInformationByHandle` when the filesystem cannot answer the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId([u8; 16]);

struct Stat {
    attrs: u32,
    len: u64,
    modified: Option<SystemTime>,
    serial: u64,
    id: FileId,
}

impl Stat {
    fn is_reparse_point(&self) -> bool {
        self.attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    fn is_dir(&self) -> bool {
        self.attrs & FILE_ATTRIBUTE_DIRECTORY != 0
    }
}

pub struct RootInner {
    dir: OwnedHandle,
    volume_serial: u64,
    root_id: FileId,
}

/// `FILETIME` is 100 ns ticks since 1601-01-01; zero means "not recorded".
fn filetime_to_system(ticks: u64) -> Option<SystemTime> {
    const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;
    const TICKS_PER_SEC: u64 = 10_000_000;
    if ticks == 0 {
        return None;
    }
    let to_duration = |t: u64| Duration::new(t / TICKS_PER_SEC, ((t % TICKS_PER_SEC) * 100) as u32);
    if ticks >= UNIX_EPOCH_TICKS {
        UNIX_EPOCH.checked_add(to_duration(ticks - UNIX_EPOCH_TICKS))
    } else {
        UNIX_EPOCH.checked_sub(to_duration(UNIX_EPOCH_TICKS - ticks))
    }
}

/// Attributes, size, mtime and identity of an open handle.
fn stat(h: BorrowedHandle<'_>) -> io::Result<Stat> {
    let raw: HANDLE = h.as_raw_handle();
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `raw` is an open handle and `info` a plain-old-data out-param.
    if unsafe { GetFileInformationByHandle(raw, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut id_info = FILE_ID_INFO::default();
    // SAFETY: open handle; the buffer is exactly the size the class expects.
    let has_id = unsafe {
        GetFileInformationByHandleEx(
            raw,
            FileIdInfo,
            (&raw mut id_info).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } != 0;
    let (serial, id) = if has_id {
        (
            id_info.VolumeSerialNumber,
            FileId(id_info.FileId.Identifier),
        )
    } else {
        let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&index.to_le_bytes());
        (u64::from(info.dwVolumeSerialNumber), FileId(bytes))
    };
    let mtime = (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
        | u64::from(info.ftLastWriteTime.dwLowDateTime);
    Ok(Stat {
        attrs: info.dwFileAttributes,
        len: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        modified: filetime_to_system(mtime),
        serial,
        id,
    })
}

fn nt_error(status: NTSTATUS) -> io::Error {
    // SAFETY: a pure table lookup.
    let code = unsafe { RtlNtStatusToDosError(status) };
    io::Error::from_raw_os_error(code as i32)
}

/// A single validated name as UTF-16. The NT parser would happily descend a
/// `\` inside a "component", so the separators are refused here too, on top
/// of `validate_rel`.
fn wide_name(name: &OsStr) -> io::Result<Vec<u16>> {
    let wide: Vec<u16> = name.encode_wide().collect();
    if wide.is_empty() || wide.len() * 2 > usize::from(u16::MAX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path component is empty or too long",
        ));
    }
    if wide
        .iter()
        .any(|&c| c == 0 || c == u16::from(b'\\') || c == u16::from(b'/'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path component contains a separator or NUL",
        ));
    }
    Ok(wide)
}

/// One `NtCreateFile` of `name` relative to `parent`. The name is a single
/// component; a reparse point is always opened itself (`FILE_OPEN_REPARSE_
/// POINT`), never followed. An empty `name` re-opens `parent` itself with the
/// requested access (the NT "reopen by handle" idiom).
fn nt_open(
    parent: BorrowedHandle<'_>,
    name: &mut [u16],
    access: u32,
    disposition: u32,
    options: u32,
) -> io::Result<OwnedHandle> {
    let object_name = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: name.as_mut_ptr(),
    };
    let attrs = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle: HANDLE = ptr::null_mut();
    let mut iosb = IO_STATUS_BLOCK::default();
    // SAFETY: every pointer refers to a live local for the duration of the
    // call; `parent` is an open handle; the name buffer outlives `object_name`.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attrs,
            &mut iosb,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            SHARE_ALL,
            disposition,
            options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(nt_error(status));
    }
    // SAFETY: a freshly created handle that nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// Open the single component `name` beneath `parent`.
fn open_child(
    parent: BorrowedHandle<'_>,
    name: &OsStr,
    access: u32,
    disposition: u32,
    options: u32,
) -> io::Result<OwnedHandle> {
    let mut wide = wide_name(name)?;
    nt_open(parent, &mut wide, access, disposition, options)
}

/// Re-open the file behind `handle` with different access, by handle alone.
fn reopen(handle: BorrowedHandle<'_>, access: u32) -> io::Result<OwnedHandle> {
    nt_open(handle, &mut [], access, FILE_OPEN, 0)
}

fn set_info(
    h: BorrowedHandle<'_>,
    class: FILE_INFORMATION_CLASS,
    data: *const core::ffi::c_void,
    len: u32,
) -> Result<(), NTSTATUS> {
    let mut iosb = IO_STATUS_BLOCK::default();
    // SAFETY: open handle; `data` points at `len` readable bytes laid out as
    // `class` requires (the callers build the buffers).
    let status = unsafe { NtSetInformationFile(h.as_raw_handle(), &mut iosb, data, len, class) };
    if status < 0 { Err(status) } else { Ok(()) }
}

/// The `\\?\`-form path of an open handle (used only for symlink creation).
fn final_path(h: BorrowedHandle<'_>) -> io::Result<PathBuf> {
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: open handle; the buffer length is passed alongside it.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                h.as_raw_handle(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                VOLUME_NAME_DOS,
            )
        } as usize;
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if n < buf.len() {
            buf.truncate(n);
            return Ok(PathBuf::from(OsString::from_wide(&buf)));
        }
        // `n` is the required size including the terminator.
        buf.resize(n + 1, 0);
    }
}

fn metadata_from_handle(h: BorrowedHandle<'_>) -> io::Result<Metadata> {
    let st = stat(h)?;
    let kind = if st.is_reparse_point() {
        EntryKind::Symlink
    } else if st.is_dir() {
        EntryKind::Dir
    } else {
        EntryKind::File
    };
    Ok(Metadata {
        kind,
        len: st.len,
        mode: if kind == EntryKind::Dir { 0o755 } else { 0o644 },
        modified: st.modified,
    })
}

impl RootInner {
    pub fn open(path: &Path) -> io::Result<RootInner> {
        // The root path is trusted (spec §16): open it by name, following a
        // symlinked or junctioned home, and work from the handle after that.
        let file = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        let dir = OwnedHandle::from(file);
        let st = stat(dir.as_handle())?;
        if !st.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{} is not a directory", path.display()),
            ));
        }
        Ok(RootInner {
            dir,
            volume_serial: st.serial,
            root_id: st.id,
        })
    }

    /// The containment decision for a directory handle just opened beneath
    /// `parent_id`: no reparse point, same volume as the root, no loop.
    fn verify_dir(&self, st: &Stat, parent_id: FileId, full: &Path, link: &str) -> io::Result<()> {
        if st.is_reparse_point() {
            return Err(refused(full, link));
        }
        if !st.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("a component of {} is not a directory", full.display()),
            ));
        }
        if st.serial != self.volume_serial {
            return Err(refused(full, "the path crosses onto another volume"));
        }
        if st.id == parent_id || st.id == self.root_id {
            return Err(refused(full, "the path loops back on itself"));
        }
        Ok(())
    }

    /// Walk `comps` handle to handle starting at `start`, returning the final
    /// directory handle and its identity. Never returns a path.
    fn walk(
        &self,
        start: BorrowedHandle<'_>,
        start_id: FileId,
        comps: &[OsString],
        full: &Path,
    ) -> io::Result<(OwnedHandle, FileId)> {
        let mut cur = start.try_clone_to_owned()?;
        let mut cur_id = start_id;
        for c in comps {
            let child = open_child(cur.as_handle(), c, DIR_ACCESS, FILE_OPEN, 0)?;
            let st = stat(child.as_handle())?;
            self.verify_dir(
                &st,
                cur_id,
                full,
                "a path component is a symbolic link or junction",
            )?;
            cur = child;
            cur_id = st.id;
        }
        Ok((cur, cur_id))
    }

    /// The directory at `comps` beneath the root.
    fn dir_beneath(&self, comps: &[OsString], full: &Path) -> io::Result<OwnedHandle> {
        self.walk(self.dir.as_handle(), self.root_id, comps, full)
            .map(|(handle, _)| handle)
    }

    /// The verified parent directory of the last component, and that name.
    fn parent<'a>(
        &self,
        comps: &'a [OsString],
        full: &Path,
    ) -> io::Result<(OwnedHandle, &'a OsStr)> {
        let (name, parents) = comps
            .split_last()
            .ok_or_else(|| refused(full, "the destination root itself is not a target"))?;
        Ok((self.dir_beneath(parents, full)?, name))
    }

    pub fn create_dir_all(
        &self,
        comps: &[OsString],
        _mode: Option<u32>,
        full: &Path,
    ) -> io::Result<()> {
        let mut cur = self.dir.try_clone()?;
        let mut cur_id = self.root_id;
        for (i, name) in comps.iter().enumerate() {
            let last = i + 1 == comps.len();
            let child = match open_child(
                cur.as_handle(),
                name,
                DIR_ACCESS,
                FILE_CREATE,
                FILE_DIRECTORY_FILE,
            ) {
                Ok(h) => h,
                // Something is already there: look at it (itself, never
                // through it) before deciding.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    open_child(cur.as_handle(), name, DIR_ACCESS, FILE_OPEN, 0)?
                }
                Err(e) => return Err(e),
            };
            let st = stat(child.as_handle())?;
            if st.is_reparse_point() {
                return Err(refused(
                    full,
                    if last {
                        "the destination is a symbolic link"
                    } else {
                        "a path component is a symbolic link or junction"
                    },
                ));
            }
            if !st.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("{} exists and is not a directory", full.display()),
                ));
            }
            self.verify_dir(&st, cur_id, full, "the destination is a symbolic link")?;
            cur = child;
            cur_id = st.id;
        }
        Ok(())
    }

    pub fn open_for_write(
        &self,
        comps: &[OsString],
        _mode: Option<u32>,
        full: &Path,
    ) -> io::Result<File> {
        let (dir, name) = self.parent(comps, full)?;
        // Open (creating if absent) without truncating, so a reparse point or
        // directory found there is never damaged; inspect, then truncate.
        let handle = open_child(
            dir.as_handle(),
            name,
            FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES,
            FILE_OPEN_IF,
            0,
        )?;
        let st = stat(handle.as_handle())?;
        if st.is_reparse_point() {
            return Err(refused(full, "the destination is a symbolic link"));
        }
        if st.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                format!("{} is a directory", full.display()),
            ));
        }
        if st.serial != self.volume_serial {
            return Err(refused(full, "the path crosses onto another volume"));
        }
        let file = File::from(handle);
        file.set_len(0)?;
        Ok(file)
    }

    pub fn open_for_read(&self, comps: &[OsString], full: &Path) -> io::Result<File> {
        let (dir, name) = self.parent(comps, full)?;
        let handle = open_child(dir.as_handle(), name, FILE_GENERIC_READ, FILE_OPEN, 0)?;
        let st = stat(handle.as_handle())?;
        if st.is_reparse_point() {
            return Err(refused(full, "the destination is a symbolic link"));
        }
        if st.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                format!("{} is a directory", full.display()),
            ));
        }
        Ok(File::from(handle))
    }

    /// Whether `target`, taken relative to the link's own directory, names a
    /// plain directory inside the root — decided by the same handle-relative
    /// walk as everything else, never by resolving the attacker-supplied
    /// string with a path API. Absolute targets, `..`, links and anything
    /// missing or unreadable all mean "file symlink".
    fn target_is_dir_within(&self, dir: BorrowedHandle<'_>, target: &Path) -> bool {
        let Ok(comps) = super::validate_rel(target, true) else {
            return false;
        };
        let Ok(st) = stat(dir) else {
            return false;
        };
        comps.is_empty() || self.walk(dir, st.id, &comps, target).is_ok()
    }

    pub fn symlink(&self, comps: &[OsString], target: &Path, full: &Path) -> io::Result<()> {
        let (dir, name) = self.parent(comps, full)?;
        // Decide "already exists" beneath the verified parent, not by path.
        match open_child(dir.as_handle(), name, FILE_READ_ATTRIBUTES, FILE_OPEN, 0) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} already exists", full.display()),
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let as_dir = self.target_is_dir_within(dir.as_handle(), target);
        // Win32 creates symlinks only by path: derive it from the verified
        // handle, create, then verify through the handle (see module docs).
        let link_path = final_path(dir.as_handle())?.join(name);
        if as_dir {
            std::os::windows::fs::symlink_dir(target, &link_path)?;
        } else {
            std::os::windows::fs::symlink_file(target, &link_path)?;
        }
        let landed = open_child(dir.as_handle(), name, FILE_READ_ATTRIBUTES, FILE_OPEN, 0)
            .and_then(|h| stat(h.as_handle()))
            .is_ok_and(|st| st.is_reparse_point());
        if !landed {
            let _ = if as_dir {
                std::fs::remove_dir(&link_path)
            } else {
                std::fs::remove_file(&link_path)
            };
            return Err(refused(
                full,
                "the symbolic link did not land beneath the destination",
            ));
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
        match open_child(dir.as_handle(), name, FILE_READ_ATTRIBUTES, FILE_OPEN, 0) {
            Ok(h) => Ok(Some(metadata_from_handle(h.as_handle())?)),
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
        let (from_dir, from_name) = self.parent(from, from_full)?;
        let (to_dir, to_name) = self.parent(to, to_full)?;
        let src = open_child(from_dir.as_handle(), from_name, DELETE, FILE_OPEN, 0)?;
        let name = wide_name(to_name)?;
        // FILE_RENAME_INFORMATION is a header followed in place by the name.
        // `RootDirectory` is the verified destination parent, so the new name
        // is a single component relative to that handle. ReplaceIfExists is
        // left false: a rename never clobbers.
        let name_offset = offset_of!(FILE_RENAME_INFORMATION, FileName);
        let len = (name_offset + name.len() * 2).max(size_of::<FILE_RENAME_INFORMATION>());
        let mut buf = vec![0u64; len.div_ceil(8)];
        let info = buf.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        // SAFETY: the buffer is 8-aligned and at least `len` bytes, which
        // covers the header and the name written at the FileName offset; all-
        // zero is a valid FILE_RENAME_INFORMATION (ReplaceIfExists = false).
        unsafe {
            (&raw mut (*info).RootDirectory).write(to_dir.as_raw_handle());
            (&raw mut (*info).FileNameLength).write((name.len() * 2) as u32);
            ptr::copy_nonoverlapping(
                name.as_ptr(),
                info.cast::<u8>().add(name_offset).cast::<u16>(),
                name.len(),
            );
        }
        set_info(
            src.as_handle(),
            FileRenameInformation,
            info.cast(),
            len as u32,
        )
        .map_err(nt_error)
    }

    pub fn remove_file(&self, comps: &[OsString], full: &Path) -> io::Result<()> {
        let (dir, name) = self.parent(comps, full)?;
        let handle = open_child(
            dir.as_handle(),
            name,
            DELETE | FILE_READ_ATTRIBUTES,
            FILE_OPEN,
            0,
        )?;
        let st = stat(handle.as_handle())?;
        if st.is_dir() && !st.is_reparse_point() {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                format!("{} is a directory", full.display()),
            ));
        }
        // The handle was opened on the entry itself (FILE_OPEN_REPARSE_POINT),
        // so deleting through it removes a symlink or junction, never what it
        // points to. Prefer POSIX semantics (the name goes at once), then the
        // plain Ex form, then the legacy class for filesystems without either.
        let unsupported = |s: NTSTATUS| {
            matches!(
                s,
                STATUS_INVALID_INFO_CLASS
                    | STATUS_INVALID_PARAMETER
                    | STATUS_NOT_SUPPORTED
                    | STATUS_INVALID_DEVICE_REQUEST
            )
        };
        let base = FILE_DISPOSITION_DELETE | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE;
        for flags in [base | FILE_DISPOSITION_POSIX_SEMANTICS, base] {
            let ex = FILE_DISPOSITION_INFORMATION_EX { Flags: flags };
            match set_info(
                handle.as_handle(),
                FileDispositionInformationEx,
                (&raw const ex).cast(),
                size_of::<FILE_DISPOSITION_INFORMATION_EX>() as u32,
            ) {
                Ok(()) => return Ok(()),
                Err(s) if unsupported(s) => continue,
                Err(s) => return Err(nt_error(s)),
            }
        }
        let legacy = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
        set_info(
            handle.as_handle(),
            FileDispositionInformation,
            (&raw const legacy).cast(),
            size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
        )
        .map_err(nt_error)
    }

    pub fn set_mode(&self, comps: &[OsString], _mode: u32, full: &Path) -> io::Result<()> {
        // Windows has no Unix mode bits. Validate the path and, as on Unix,
        // tell the caller when the entry is a link rather than a file.
        let (dir, name) = self.parent(comps, full)?;
        let handle = open_child(dir.as_handle(), name, FILE_READ_ATTRIBUTES, FILE_OPEN, 0)?;
        if stat(handle.as_handle())?.is_reparse_point() {
            return Err(refused(full, "the destination is a symbolic link"));
        }
        Ok(())
    }

    pub fn set_dir_modified(
        &self,
        comps: &[OsString],
        when: SystemTime,
        full: &Path,
    ) -> io::Result<()> {
        let dir = self.dir_beneath(comps, full)?;
        // The walk opens directories read-only; re-open this one by handle
        // (not by path) with the access needed to set its timestamps.
        let writable = reopen(
            dir.as_handle(),
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
        )?;
        File::from(writable).set_modified(when)
    }
}
