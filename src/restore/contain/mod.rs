//! Containment primitives (spec §16).
//!
//! Restore writes attacker-influenceable data with the user's full privileges,
//! so every write goes through a [`Root`]: a directory handle opened once, with
//! each relative path validated *and opened in one operation* by the platform's
//! real containment primitive — `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS)`
//! on Linux, a component-wise `O_NOFOLLOW` walk on other Unixes, a
//! handle-relative `NtCreateFile` walk on Windows. Every implementation refuses
//! a symlink (or junction) at *any* component. The descriptor or handle that
//! comes back is what gets written; no path string is re-resolved afterwards
//! (TOCTOU, spec §16). The single exception is Windows symlink *creation*,
//! which Win32 offers only by path and which `windows.rs` re-verifies through
//! the parent handle immediately afterwards.
//!
//! `O_NOFOLLOW` guards only the final component and is used for exactly that.

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as imp;
#[cfg(windows)]
use windows as imp;

/// What a containment check found at a relative path (an `lstat`, never
/// following a final-component symlink).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub kind: EntryKind,
    pub len: u64,
    /// Permission bits (Unix); a conventional 0644/0755 on Windows.
    pub mode: u32,
    pub modified: Option<SystemTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

impl Metadata {
    pub fn is_dir(&self) -> bool {
        self.kind == EntryKind::Dir
    }
    pub fn is_symlink(&self) -> bool {
        self.kind == EntryKind::Symlink
    }
}

/// A containment refusal: the path would resolve outside the root, through a
/// symlink, or is not a name moss is willing to create.
#[derive(Debug)]
pub struct Refused {
    pub path: PathBuf,
    pub reason: String,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "refused to write {}: {}",
            self.path.display(),
            self.reason
        )
    }
}

impl Error for Refused {}

pub(crate) fn refused(path: &Path, reason: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        Refused {
            path: path.to_path_buf(),
            reason: reason.into(),
        },
    )
}

/// Whether an error is a containment refusal rather than an ordinary I/O failure.
pub fn is_containment_error(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<Refused>())
}

/// Validate a relative path into its plain components. Rejects absolute
/// paths, `..`, NUL, and (when `windows_names`) names Windows cannot store.
/// `.` components are dropped. An empty result means "the root itself".
pub fn validate_rel(rel: &Path, windows_names: bool) -> io::Result<Vec<OsString>> {
    let mut out = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(name) => {
                let s = name.to_string_lossy();
                if s.is_empty() {
                    return Err(refused(rel, "empty path component"));
                }
                if name.as_encoded_bytes().contains(&0) {
                    return Err(refused(rel, "path contains a NUL byte"));
                }
                if windows_names && let Some(problem) = crate::scan::collisions::windows_problem(&s)
                {
                    return Err(refused(
                        rel,
                        format!("name {s:?} is not valid here: {problem}"),
                    ));
                }
                out.push(name.to_os_string());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(refused(rel, "path contains `..`"));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(refused(rel, "path is absolute"));
            }
        }
    }
    Ok(out)
}

/// A destination directory that every write is contained within.
pub struct Root {
    inner: imp::RootInner,
    path: PathBuf,
    windows_names: bool,
}

impl fmt::Debug for Root {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Root").field("path", &self.path).finish()
    }
}

impl Root {
    /// Open an existing directory as the containment root. The root path
    /// itself is trusted (it comes from the platform adapter or `--to`); the
    /// relative paths given to the methods below are not.
    pub fn open(path: &Path) -> io::Result<Root> {
        Ok(Root {
            inner: imp::RootInner::open(path)?,
            path: path.to_path_buf(),
            windows_names: cfg!(windows),
        })
    }

    /// The directory this root was opened on (for messages only).
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn comps(&self, rel: &Path) -> io::Result<Vec<OsString>> {
        validate_rel(rel, self.windows_names)
    }

    fn full(&self, rel: &Path) -> PathBuf {
        self.path.join(rel)
    }

    /// `mkdir -p`. When `mode` is given the final directory ends up with
    /// exactly that mode. Refuses if the final component is a symlink.
    pub fn create_dir_all(&self, rel: &Path, mode: Option<u32>) -> io::Result<()> {
        let comps = self.comps(rel)?;
        self.inner.create_dir_all(&comps, mode, &self.full(rel))
    }

    /// Create or truncate a regular file for writing, never through a symlink
    /// at any component. `mode` is applied exactly.
    pub fn open_for_write(&self, rel: &Path, mode: Option<u32>) -> io::Result<File> {
        let comps = self.comps(rel)?;
        self.inner.open_for_write(&comps, mode, &self.full(rel))
    }

    /// Open an existing regular file for reading (final component not followed).
    pub fn open_for_read(&self, rel: &Path) -> io::Result<File> {
        let comps = self.comps(rel)?;
        self.inner.open_for_read(&comps, &self.full(rel))
    }

    /// Create a symlink at `rel` pointing at `target` (stored verbatim; never
    /// followed).
    pub fn symlink(&self, rel: &Path, target: &Path) -> io::Result<()> {
        let comps = self.comps(rel)?;
        self.inner.symlink(&comps, target, &self.full(rel))
    }

    /// `lstat` beneath the root. `Ok(None)` when nothing exists there
    /// (including when an intermediate directory is missing).
    pub fn exists(&self, rel: &Path) -> io::Result<Option<Metadata>> {
        let comps = self.comps(rel)?;
        self.inner.exists(&comps, &self.full(rel))
    }

    /// Rename within the root (used for the `backup` conflict policy).
    pub fn rename_within(&self, from_rel: &Path, to_rel: &Path) -> io::Result<()> {
        let from = self.comps(from_rel)?;
        let to = self.comps(to_rel)?;
        self.inner
            .rename(&from, &to, &self.full(from_rel), &self.full(to_rel))
    }

    /// Remove a file or symlink (never a directory, never a symlink's target).
    pub fn remove_file(&self, rel: &Path) -> io::Result<()> {
        let comps = self.comps(rel)?;
        self.inner.remove_file(&comps, &self.full(rel))
    }

    /// Set permission bits on a file or directory (no-op on Windows).
    pub fn set_mode(&self, rel: &Path, mode: u32) -> io::Result<()> {
        let comps = self.comps(rel)?;
        self.inner.set_mode(&comps, mode, &self.full(rel))
    }

    /// Set the modification time of a directory beneath the root.
    pub fn set_dir_modified(&self, rel: &Path, when: SystemTime) -> io::Result<()> {
        let comps = self.comps(rel)?;
        self.inner.set_dir_modified(&comps, when, &self.full(rel))
    }
}

/// Windows `ERROR_PRIVILEGE_NOT_HELD` (1314): symlink creation needs
/// Developer Mode or elevation (spec §17).
pub fn is_privilege_error(e: &io::Error) -> bool {
    cfg!(windows) && e.raw_os_error() == Some(1314)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_escapes_and_bad_names() {
        assert!(is_containment_error(
            &validate_rel(Path::new("../x"), false).unwrap_err()
        ));
        assert!(is_containment_error(
            &validate_rel(Path::new("a/../../x"), false).unwrap_err()
        ));
        assert!(is_containment_error(
            &validate_rel(Path::new("/etc/passwd"), false).unwrap_err()
        ));
        assert_eq!(
            validate_rel(Path::new("./a/./b"), false).unwrap(),
            vec![OsString::from("a"), OsString::from("b")]
        );
        assert!(validate_rel(Path::new(""), false).unwrap().is_empty());
        // Windows-only name rules apply only when asked for.
        assert!(validate_rel(Path::new("aux.txt"), false).is_ok());
        let err = validate_rel(Path::new("dir/aux.txt"), true).unwrap_err();
        assert!(is_containment_error(&err));
        assert!(err.to_string().contains("AUX"), "{err}");
        assert!(validate_rel(Path::new("notes:draft"), true).is_err());
    }

    #[cfg(unix)]
    mod unix_tests {
        use super::super::*;
        use std::io::{Read, Write};
        use std::os::unix::fs::PermissionsExt;

        struct Fixture {
            _tmp: tempfile::TempDir,
            root: PathBuf,
            outside: PathBuf,
        }

        /// root/
        ///   link      -> ../outside          (relative escape)
        ///   abs       -> /etc                (absolute escape)
        ///   chain     -> hop                 (symlink chain climbing out)
        ///   hop       -> ../../..
        ///   existing  -> ../outside/target   (final-component symlink)
        ///   inner/    (a real directory)
        fn fixture() -> Fixture {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("root");
            let outside = tmp.path().join("outside");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::create_dir_all(root.join("inner")).unwrap();
            std::os::unix::fs::symlink("../outside", root.join("link")).unwrap();
            std::os::unix::fs::symlink("/etc", root.join("abs")).unwrap();
            std::os::unix::fs::symlink("hop", root.join("chain")).unwrap();
            std::os::unix::fs::symlink("../../..", root.join("hop")).unwrap();
            std::os::unix::fs::symlink("../outside/target", root.join("existing")).unwrap();
            Fixture {
                _tmp: tmp,
                root,
                outside,
            }
        }

        /// Every Unix implementation refuses a symlinked component outright
        /// (Linux via `RESOLVE_NO_SYMLINKS`, the rest via `O_NOFOLLOW`).
        fn assert_refused(result: io::Result<impl std::fmt::Debug>, what: &str) {
            match result {
                Ok(v) => panic!("{what}: expected refusal, got {v:?}"),
                Err(e) => assert!(is_containment_error(&e), "{what}: unexpected error {e:?}"),
            }
        }

        #[test]
        fn escapes_are_refused() {
            let f = fixture();
            let root = Root::open(&f.root).unwrap();
            assert_refused(root.open_for_write(Path::new("link/x"), None), "link/x");
            assert_refused(root.open_for_write(Path::new("abs/x"), None), "abs/x");
            assert_refused(root.open_for_write(Path::new("chain/x"), None), "chain/x");
            assert_refused(root.create_dir_all(Path::new("link/sub"), None), "link/sub");
            assert_refused(
                root.create_dir_all(Path::new("chain/sub"), None),
                "chain/sub",
            );
            assert_refused(root.open_for_write(Path::new("../x"), None), "../x");
            assert_refused(root.open_for_write(Path::new("/tmp/x"), None), "/tmp/x");
            // Writing through a pre-existing final-component symlink.
            let err = root
                .open_for_write(Path::new("existing"), Some(0o600))
                .unwrap_err();
            assert!(is_containment_error(&err), "{err:?}");
            assert!(!f.outside.join("target").exists());
            assert!(!f.outside.join("x").exists());
            assert!(!f.outside.join("sub").exists());
            assert!(!Path::new("/etc/x").exists());
            // Symlink at a final component cannot be replaced by a directory.
            assert!(is_containment_error(
                &root
                    .create_dir_all(Path::new("existing"), None)
                    .unwrap_err()
            ));
        }

        #[test]
        fn contained_writes_work_with_exact_modes() {
            let f = fixture();
            let root = Root::open(&f.root).unwrap();
            root.create_dir_all(Path::new("a/b"), Some(0o700)).unwrap();
            let mut file = root
                .open_for_write(Path::new("a/b/c.txt"), Some(0o600))
                .unwrap();
            file.write_all(b"hello").unwrap();
            drop(file);
            let dir_mode = std::fs::metadata(f.root.join("a/b"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            let file_mode = std::fs::metadata(f.root.join("a/b/c.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o600);
            // Exists / metadata.
            let meta = root.exists(Path::new("a/b/c.txt")).unwrap().unwrap();
            assert_eq!(meta.kind, EntryKind::File);
            assert_eq!(meta.len, 5);
            assert_eq!(meta.mode & 0o777, 0o600);
            assert!(root.exists(Path::new("a/b/missing")).unwrap().is_none());
            assert!(root.exists(Path::new("nope/at/all")).unwrap().is_none());
            assert_eq!(
                root.exists(Path::new("link")).unwrap().unwrap().kind,
                EntryKind::Symlink
            );
            assert!(root.exists(Path::new("a")).unwrap().unwrap().is_dir());
            // Internal paths with `.` are fine; a rename stays inside.
            root.rename_within(Path::new("a/b/c.txt"), Path::new("a/b/d.txt"))
                .unwrap();
            let mut text = String::new();
            root.open_for_read(Path::new("./a/b/d.txt"))
                .unwrap()
                .read_to_string(&mut text)
                .unwrap();
            assert_eq!(text, "hello");
            root.set_mode(Path::new("a/b/d.txt"), 0o640).unwrap();
            assert_eq!(
                root.exists(Path::new("a/b/d.txt")).unwrap().unwrap().mode & 0o777,
                0o640
            );
            // Symlinks are created as symlinks and removed as links.
            root.symlink(Path::new("a/lnk"), Path::new("/nowhere/at/all"))
                .unwrap();
            assert_eq!(
                std::fs::read_link(f.root.join("a/lnk")).unwrap(),
                PathBuf::from("/nowhere/at/all")
            );
            root.remove_file(Path::new("a/lnk")).unwrap();
            assert!(root.exists(Path::new("a/lnk")).unwrap().is_none());
            // Overwriting through an existing symlink is refused even for
            // set_mode and open_for_read.
            assert!(is_containment_error(
                &root.set_mode(Path::new("existing"), 0o600).unwrap_err()
            ));
            assert!(is_containment_error(
                &root.open_for_read(Path::new("existing")).unwrap_err()
            ));
            // A directory mtime can be set.
            root.set_dir_modified(
                Path::new("a"),
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000),
            )
            .unwrap();
        }

        #[test]
        fn create_dir_all_is_idempotent_and_refuses_files() {
            let f = fixture();
            let root = Root::open(&f.root).unwrap();
            root.create_dir_all(Path::new("inner"), None).unwrap();
            root.create_dir_all(Path::new("inner/x/y"), Some(0o750))
                .unwrap();
            root.create_dir_all(Path::new("inner/x/y"), Some(0o750))
                .unwrap();
            root.open_for_write(Path::new("inner/file"), Some(0o644))
                .unwrap();
            let err = root
                .create_dir_all(Path::new("inner/file/sub"), None)
                .unwrap_err();
            assert!(!is_containment_error(&err));
        }
    }

    #[cfg(windows)]
    mod windows_tests {
        use super::super::*;
        use std::io::{Read, Write};
        use std::process::Command;

        struct Fixture {
            _tmp: tempfile::TempDir,
            root: PathBuf,
            outside: PathBuf,
            /// Directory symlinks could be created (needs Developer Mode or
            /// elevation; GitHub's runners have it, a plain dev box may not).
            dir_symlinks: bool,
            /// File symlinks could be created (same privilege).
            file_symlinks: bool,
        }

        /// root/
        ///   junc      -> ../outside          (junction; needs no privilege)
        ///   dlink     -> ../outside          (directory symlink)
        ///   existing  -> ../outside/target   (file symlink at a final component)
        ///   inner/    (a real directory)
        /// outside/
        ///   target    (a real file the links point at)
        fn fixture() -> Fixture {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("root");
            let outside = tmp.path().join("outside");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::create_dir_all(root.join("inner")).unwrap();
            std::fs::write(outside.join("target"), b"victim").unwrap();
            let status = Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(root.join("junc"))
                .arg(&outside)
                .status()
                .unwrap();
            assert!(status.success(), "mklink /J failed: {status}");
            let dir_symlinks = match std::os::windows::fs::symlink_dir(&outside, root.join("dlink"))
            {
                Ok(()) => true,
                Err(e) if is_privilege_error(&e) => false,
                Err(e) => panic!("symlink_dir: {e}"),
            };
            let file_symlinks = match std::os::windows::fs::symlink_file(
                outside.join("target"),
                root.join("existing"),
            ) {
                Ok(()) => true,
                Err(e) if is_privilege_error(&e) => false,
                Err(e) => panic!("symlink_file: {e}"),
            };
            Fixture {
                _tmp: tmp,
                root,
                outside,
                dir_symlinks,
                file_symlinks,
            }
        }

        fn assert_refused(result: io::Result<impl std::fmt::Debug>, what: &str) {
            match result {
                Ok(v) => panic!("{what}: expected refusal, got {v:?}"),
                Err(e) => assert!(is_containment_error(&e), "{what}: unexpected error {e:?}"),
            }
        }

        /// Every operation through a junction or directory symlink is refused
        /// at that component, and nothing appears on the other side.
        fn assert_link_refused(root: &Root, f: &Fixture, link: &str) {
            let p = |s: &str| PathBuf::from(format!("{link}/{s}"));
            assert_refused(root.open_for_write(&p("x"), None), "write through link");
            assert_refused(root.create_dir_all(&p("sub"), None), "mkdir through link");
            assert_refused(
                root.create_dir_all(&p("sub/deeper"), None),
                "mkdir -p through link",
            );
            assert_refused(root.open_for_read(&p("target")), "read through link");
            assert_refused(root.exists(&p("target")), "exists through link");
            assert_refused(root.remove_file(&p("target")), "remove through link");
            assert_refused(root.set_mode(&p("target"), 0o600), "set_mode through link");
            assert_refused(
                root.set_dir_modified(Path::new(link), SystemTime::UNIX_EPOCH),
                "set_dir_modified on link",
            );
            assert_refused(
                root.rename_within(&p("target"), Path::new("inner/stolen")),
                "rename out of link",
            );
            assert_refused(
                root.rename_within(Path::new("inner/mine"), &p("planted")),
                "rename into link",
            );
            // The link itself is a reparse point at the final component.
            assert_refused(root.create_dir_all(Path::new(link), None), "mkdir on link");
            assert_refused(root.open_for_write(Path::new(link), None), "write on link");
            assert!(!f.outside.join("x").exists());
            assert!(!f.outside.join("sub").exists());
            assert!(!f.outside.join("planted").exists());
            assert!(!f.root.join("inner/stolen").exists());
            assert_eq!(std::fs::read(f.outside.join("target")).unwrap(), b"victim");
        }

        #[test]
        fn escapes_are_refused() {
            let f = fixture();
            let root = Root::open(&f.root).unwrap();
            root.open_for_write(Path::new("inner/mine"), None).unwrap();
            assert_link_refused(&root, &f, "junc");
            if f.dir_symlinks {
                assert_link_refused(&root, &f, "dlink");
            }
            assert_refused(root.open_for_write(Path::new("../x"), None), "../x");
            assert_refused(root.open_for_write(Path::new("C:\\x"), None), "C:\\x");
            assert_refused(root.open_for_write(Path::new("\\x"), None), "\\x");
            if f.file_symlinks {
                // Writing through a pre-existing final-component symlink.
                let err = root
                    .open_for_write(Path::new("existing"), Some(0o600))
                    .unwrap_err();
                assert!(is_containment_error(&err), "{err:?}");
                assert_eq!(std::fs::read(f.outside.join("target")).unwrap(), b"victim");
                assert!(is_containment_error(
                    &root
                        .create_dir_all(Path::new("existing"), None)
                        .unwrap_err()
                ));
                assert!(is_containment_error(
                    &root
                        .create_dir_all(Path::new("existing/sub"), None)
                        .unwrap_err()
                ));
                assert!(is_containment_error(
                    &root.open_for_read(Path::new("existing")).unwrap_err()
                ));
                assert!(is_containment_error(
                    &root.set_mode(Path::new("existing"), 0o600).unwrap_err()
                ));
                assert_eq!(
                    root.exists(Path::new("existing")).unwrap().unwrap().kind,
                    EntryKind::Symlink
                );
            }
            assert!(f.root.join("inner/mine").exists());
        }

        #[test]
        fn contained_writes_work() {
            let f = fixture();
            let root = Root::open(&f.root).unwrap();
            root.create_dir_all(Path::new("a/b"), Some(0o700)).unwrap();
            let mut file = root
                .open_for_write(Path::new("a/b/c.txt"), Some(0o600))
                .unwrap();
            file.write_all(b"hello").unwrap();
            drop(file);
            assert_eq!(std::fs::read(f.root.join("a/b/c.txt")).unwrap(), b"hello");
            // Exists / metadata.
            let meta = root.exists(Path::new("a/b/c.txt")).unwrap().unwrap();
            assert_eq!(meta.kind, EntryKind::File);
            assert_eq!(meta.len, 5);
            assert!(meta.modified.is_some());
            assert!(root.exists(Path::new("a/b/missing")).unwrap().is_none());
            assert!(root.exists(Path::new("nope/at/all")).unwrap().is_none());
            assert!(root.exists(Path::new("a/b/c.txt/under")).unwrap().is_none());
            assert_eq!(
                root.exists(Path::new("junc")).unwrap().unwrap().kind,
                EntryKind::Symlink
            );
            if f.dir_symlinks {
                assert_eq!(
                    root.exists(Path::new("dlink")).unwrap().unwrap().kind,
                    EntryKind::Symlink
                );
            }
            assert!(root.exists(Path::new("a")).unwrap().unwrap().is_dir());
            assert!(root.exists(Path::new("inner")).unwrap().unwrap().is_dir());
            // Internal paths with `.` are fine; a rename stays inside.
            root.rename_within(Path::new("a/b/c.txt"), Path::new("a/b/d.txt"))
                .unwrap();
            assert!(root.exists(Path::new("a/b/c.txt")).unwrap().is_none());
            let mut text = String::new();
            root.open_for_read(Path::new("./a/b/d.txt"))
                .unwrap()
                .read_to_string(&mut text)
                .unwrap();
            assert_eq!(text, "hello");
            // A rename across directories inside the root works too, and a
            // rename never replaces an existing entry.
            root.rename_within(Path::new("a/b/d.txt"), Path::new("inner/d.txt"))
                .unwrap();
            assert_eq!(std::fs::read(f.root.join("inner/d.txt")).unwrap(), b"hello");
            root.open_for_write(Path::new("a/e.txt"), None).unwrap();
            let err = root
                .rename_within(Path::new("inner/d.txt"), Path::new("a/e.txt"))
                .unwrap_err();
            assert!(!is_containment_error(&err), "{err:?}");
            assert_eq!(std::fs::read(f.root.join("inner/d.txt")).unwrap(), b"hello");
            root.set_mode(Path::new("inner/d.txt"), 0o640).unwrap();
            // Re-opening for write truncates.
            root.open_for_write(Path::new("inner/d.txt"), None)
                .unwrap()
                .write_all(b"hi")
                .unwrap();
            assert_eq!(std::fs::read(f.root.join("inner/d.txt")).unwrap(), b"hi");
            // Directories are not files.
            let err = root.open_for_write(Path::new("a"), None).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::IsADirectory);
            let err = root.remove_file(Path::new("a")).unwrap_err();
            assert!(!is_containment_error(&err), "{err:?}");
            assert!(f.root.join("a").is_dir());
            root.remove_file(Path::new("inner/d.txt")).unwrap();
            assert!(root.exists(Path::new("inner/d.txt")).unwrap().is_none());
            // A directory mtime can be set through the handle.
            let when = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
            root.set_dir_modified(Path::new("a"), when).unwrap();
            assert_eq!(
                std::fs::metadata(f.root.join("a"))
                    .unwrap()
                    .modified()
                    .unwrap(),
                when
            );
            if f.file_symlinks {
                // Symlinks are created as symlinks (never following the
                // target) and removed as links.
                root.symlink(Path::new("a/lnk"), Path::new("C:\\nowhere\\at\\all"))
                    .unwrap();
                assert_eq!(
                    std::fs::read_link(f.root.join("a/lnk")).unwrap(),
                    PathBuf::from("C:\\nowhere\\at\\all")
                );
                assert_eq!(
                    root.exists(Path::new("a/lnk")).unwrap().unwrap().kind,
                    EntryKind::Symlink
                );
                let err = root
                    .symlink(Path::new("a/lnk"), Path::new("elsewhere"))
                    .unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
                root.remove_file(Path::new("a/lnk")).unwrap();
                assert!(root.exists(Path::new("a/lnk")).unwrap().is_none());
                // A relative target naming a directory inside the root gets a
                // directory link; the link is removed as a link.
                root.symlink(Path::new("a/tob"), Path::new("b")).unwrap();
                let ft = std::fs::symlink_metadata(f.root.join("a/tob"))
                    .unwrap()
                    .file_type();
                assert!(ft.is_symlink());
                assert!(std::fs::metadata(f.root.join("a/tob")).unwrap().is_dir());
                root.remove_file(Path::new("a/tob")).unwrap();
                assert!(root.exists(Path::new("a/tob")).unwrap().is_none());
                assert!(f.root.join("a/b").is_dir());
                // A target that escapes never gets a directory link decision
                // by resolving it: `..` means a file link.
                root.symlink(Path::new("a/up"), Path::new("..\\..\\outside"))
                    .unwrap();
                assert!(
                    !std::fs::symlink_metadata(f.root.join("a/up"))
                        .unwrap()
                        .file_type()
                        .is_dir()
                );
            }
        }

        #[test]
        fn create_dir_all_is_idempotent_and_refuses_files() {
            let f = fixture();
            let root = Root::open(&f.root).unwrap();
            root.create_dir_all(Path::new("inner"), None).unwrap();
            root.create_dir_all(Path::new("inner/x/y"), Some(0o750))
                .unwrap();
            root.create_dir_all(Path::new("inner/x/y"), Some(0o750))
                .unwrap();
            assert!(f.root.join("inner/x/y").is_dir());
            root.open_for_write(Path::new("inner/file"), Some(0o644))
                .unwrap();
            let err = root
                .create_dir_all(Path::new("inner/file/sub"), None)
                .unwrap_err();
            assert!(!is_containment_error(&err), "{err:?}");
            let err = root
                .create_dir_all(Path::new("inner/file"), None)
                .unwrap_err();
            assert!(!is_containment_error(&err), "{err:?}");
            // The root itself is never a write target.
            assert_refused(root.open_for_write(Path::new(""), None), "root");
            assert_refused(root.remove_file(Path::new(".")), "root");
        }

        #[test]
        fn remove_file_on_a_link_removes_the_link_not_the_target() {
            let f = fixture();
            let root = Root::open(&f.root).unwrap();
            root.remove_file(Path::new("junc")).unwrap();
            assert!(std::fs::symlink_metadata(f.root.join("junc")).is_err());
            assert!(root.exists(Path::new("junc")).unwrap().is_none());
            assert_eq!(std::fs::read(f.outside.join("target")).unwrap(), b"victim");
            if f.dir_symlinks {
                root.remove_file(Path::new("dlink")).unwrap();
                assert!(std::fs::symlink_metadata(f.root.join("dlink")).is_err());
            }
            if f.file_symlinks {
                root.remove_file(Path::new("existing")).unwrap();
                assert!(std::fs::symlink_metadata(f.root.join("existing")).is_err());
            }
            assert_eq!(std::fs::read(f.outside.join("target")).unwrap(), b"victim");
            assert!(f.outside.is_dir());
        }
    }
}
