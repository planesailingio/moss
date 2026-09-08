//! The restore journal (spec §18): each intended write is recorded and
//! fsynced *before* the file is touched, and marked done afterwards, so an
//! interrupted restore can be resumed or rolled back on the next run.
//!
//! Format: newline-delimited JSON at `<state>/restore-journal.json`. A file
//! has two records over its life (`intended`, then `done` or `abandoned`); the
//! reader folds them by destination path. Paths are stored losslessly (see
//! [`path_codec`]): two distinct non-UTF-8 names must never alias.

use std::collections::{BTreeMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{MossError, Result};
use crate::restore::contain::Root;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Write,
    Symlink,
    Mkdir,
    BackupExisting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Intended,
    Done,
    /// The intention was given up (write failed, destination cleaned up). Not
    /// pending, so no resume; not done, so a resumed run writes it again.
    Abandoned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub run_id: String,
    pub source_id: String,
    /// Absolute destination path.
    #[serde(with = "path_codec")]
    pub dest_path: PathBuf,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    pub state: State,
    /// For `backup_existing`: where the original was moved to.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "path_codec::opt"
    )]
    pub backup_path: Option<PathBuf>,
    pub at: chrono::DateTime<chrono::Utc>,
}

/// Lossless path (de)serialisation: a UTF-8 path is a plain JSON string; any
/// other path is `{"bytes": [...]}` on Unix or `{"wide": [...]}` on Windows,
/// rebuilt with the platform's safe constructor. A journal written on the
/// other family is rejected rather than guessed at.
mod path_codec {
    use std::path::{Path, PathBuf};

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Utf8(String),
        Bytes { bytes: Vec<u8> },
        Wide { wide: Vec<u16> },
    }

    fn to_repr(p: &Path) -> Repr {
        if let Some(s) = p.to_str() {
            return Repr::Utf8(s.to_string());
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Repr::Bytes {
                bytes: p.as_os_str().as_bytes().to_vec(),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            Repr::Wide {
                wide: p.as_os_str().encode_wide().collect(),
            }
        }
    }

    fn from_repr<E: serde::de::Error>(r: Repr) -> Result<PathBuf, E> {
        match r {
            Repr::Utf8(s) => Ok(PathBuf::from(s)),
            #[cfg(unix)]
            Repr::Bytes { bytes } => {
                use std::os::unix::ffi::OsStringExt;
                Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
            }
            #[cfg(windows)]
            Repr::Wide { wide } => {
                use std::os::windows::ffi::OsStringExt;
                Ok(PathBuf::from(std::ffi::OsString::from_wide(&wide)))
            }
            #[allow(unreachable_patterns)]
            other => Err(E::custom(format!(
                "journal path was written on another OS family ({})",
                match other {
                    Repr::Bytes { .. } => "unix bytes",
                    Repr::Wide { .. } => "windows wide",
                    Repr::Utf8(_) => "utf8",
                }
            ))),
        }
    }

    pub fn serialize<S: Serializer>(p: &Path, s: S) -> Result<S::Ok, S::Error> {
        to_repr(p).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PathBuf, D::Error> {
        from_repr(Repr::deserialize(d)?)
    }

    pub mod opt {
        use std::path::{Path, PathBuf};

        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(p: &Option<PathBuf>, s: S) -> Result<S::Ok, S::Error> {
            p.as_deref().map(super::to_repr).serialize(s)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<PathBuf>, D::Error> {
            Option::<super::Repr>::deserialize(d)?
                .map(super::from_repr)
                .transpose()
        }

        #[allow(dead_code)]
        fn _assert_path_is_used(_: &Path) {}
    }
}

/// An open, append-only journal.
pub struct Journal {
    file: File,
    path: PathBuf,
}

impl Journal {
    pub fn open(path: &Path) -> Result<Journal> {
        if let Some(parent) = path.parent() {
            crate::config::paths::create_private_dir(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        crate::config::paths::make_private_file(path)?;
        Ok(Journal {
            file,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn record(&mut self, r: &Record) -> Result<()> {
        let mut line = serde_json::to_string(r)?;
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.sync_data()?;
        Ok(())
    }

    /// Record an intention. Returns the record so `done` can close it.
    pub fn intend(
        &mut self,
        run_id: &str,
        source_id: &str,
        dest_path: &Path,
        action: Action,
        decision: Option<&str>,
        backup_path: Option<&Path>,
    ) -> Result<Record> {
        let r = Record {
            run_id: run_id.to_string(),
            source_id: source_id.to_string(),
            dest_path: dest_path.to_path_buf(),
            action,
            decision: decision.map(str::to_string),
            state: State::Intended,
            backup_path: backup_path.map(Path::to_path_buf),
            at: chrono::Utc::now(),
        };
        self.record(&r)?;
        Ok(r)
    }

    pub fn done(&mut self, intended: &Record) -> Result<()> {
        self.settle(intended, State::Done, None)
    }

    /// Settle an intention that will not be completed: the destination has
    /// been cleaned up, so the next run must neither offer to resume it nor
    /// count it as placed.
    pub fn abandon(&mut self, intended: &Record, reason: &str) -> Result<()> {
        self.settle(
            intended,
            State::Abandoned,
            Some(format!("abandoned: {reason}")),
        )
    }

    fn settle(&mut self, intended: &Record, state: State, decision: Option<String>) -> Result<()> {
        let r = Record {
            state,
            decision: decision.or_else(|| intended.decision.clone()),
            at: chrono::Utc::now(),
            ..intended.clone()
        };
        self.record(&r)
    }

    /// Remove the journal after a clean completion.
    pub fn finish(self) -> Result<()> {
        drop(self.file);
        remove(&self.path)
    }
}

pub fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Read every record. A missing file is an empty journal; a truncated *last*
/// line (crash mid-write) is ignored. Damage anywhere else is an integrity
/// failure: skipping a record would hide a `done` from rollback, which would
/// then delete a completed file.
pub fn load(path: &Path) -> Result<Vec<Record>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let lines: Vec<String> = BufReader::new(file)
        .lines()
        .collect::<std::io::Result<_>>()?;
    let mut out = Vec::new();
    let last = lines.len().saturating_sub(1);
    for (i, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Record>(line) {
            Ok(r) => out.push(r),
            Err(_) if i == last => break,
            Err(e) => {
                return Err(MossError::Integrity(format!(
                    "restore journal {} is damaged at line {}: {e}. Inspect it before deciding whether to remove it; --resume and --rollback refuse to guess.",
                    path.display(),
                    i + 1
                )));
            }
        }
    }
    Ok(out)
}

/// What an interrupted restore left behind.
#[derive(Debug, Clone, Default)]
pub struct Incomplete {
    pub run_id: String,
    /// Writes and symlinks that were intended but never marked done.
    pub pending: Vec<Record>,
    /// Originals moved aside (`backup_existing` done) keyed by destination.
    pub backups: BTreeMap<PathBuf, Record>,
    /// Destinations whose write completed.
    pub done: HashSet<PathBuf>,
}

impl Incomplete {
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

/// Fold records into the incomplete set. `None` when nothing is pending.
pub fn incomplete(records: &[Record]) -> Option<Incomplete> {
    if records.is_empty() {
        return None;
    }
    let mut state: BTreeMap<(PathBuf, Action), Record> = BTreeMap::new();
    let mut backups = BTreeMap::new();
    let mut run_id = String::new();
    for r in records {
        if run_id.is_empty() {
            run_id = r.run_id.clone();
        }
        if r.action == Action::BackupExisting {
            if r.state == State::Done {
                backups.insert(r.dest_path.clone(), r.clone());
            }
            continue;
        }
        state.insert((r.dest_path.clone(), r.action), r.clone());
    }
    let mut pending = Vec::new();
    let mut done = HashSet::new();
    for ((dest, _), r) in state {
        match r.state {
            State::Intended => pending.push(r),
            State::Done => {
                done.insert(dest);
            }
            State::Abandoned => {}
        }
    }
    if pending.is_empty() {
        return None;
    }
    Some(Incomplete {
        run_id,
        pending,
        backups,
        done,
    })
}

/// State carried into a `--resume` run.
#[derive(Debug, Clone, Default)]
pub struct ResumeState {
    pub done: HashSet<PathBuf>,
    pub pending: HashSet<PathBuf>,
}

impl ResumeState {
    pub fn from_incomplete(inc: &Incomplete) -> ResumeState {
        ResumeState {
            done: inc.done.clone(),
            pending: inc.pending.iter().map(|r| r.dest_path.clone()).collect(),
        }
    }

    pub fn is_done(&self, dest: &Path) -> bool {
        self.done.contains(dest)
    }

    pub fn is_pending(&self, dest: &Path) -> bool {
        self.pending.contains(dest)
    }
}

#[derive(Debug, Default, Serialize)]
pub struct RollbackSummary {
    pub removed: Vec<String>,
    pub restored_backups: Vec<String>,
    pub failed: Vec<(String, String)>,
}

/// Undo an interrupted restore: remove files that were intended but not
/// completed, and put back any original that was moved aside for them.
/// Everything goes through the containment layer on the file's parent.
pub fn rollback(inc: &Incomplete) -> RollbackSummary {
    let mut summary = RollbackSummary::default();
    for r in &inc.pending {
        let dest = &r.dest_path;
        let shown = dest.display().to_string();
        let (Some(parent), Some(name)) = (dest.parent(), dest.file_name()) else {
            summary.failed.push((shown, "not a file path".into()));
            continue;
        };
        let name = Path::new(name);
        let root = match Root::open(parent) {
            Ok(root) => root,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                summary.failed.push((shown, e.to_string()));
                continue;
            }
        };
        match root.exists(name) {
            Ok(Some(m)) if !m.is_dir() => match root.remove_file(name) {
                Ok(()) => summary.removed.push(shown.clone()),
                Err(e) => summary.failed.push((shown.clone(), e.to_string())),
            },
            Ok(_) => {}
            Err(e) => summary.failed.push((shown.clone(), e.to_string())),
        }
        if let Some(backup) = inc.backups.get(dest)
            && let Some(backup_path) = &backup.backup_path
            && let Some(backup_name) = backup_path.file_name()
        {
            match root.rename_within(Path::new(backup_name), name) {
                Ok(()) => summary.restored_backups.push(shown.clone()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => summary.failed.push((
                    backup_path.display().to_string(),
                    format!("could not restore original: {e}"),
                )),
            }
        }
    }
    summary
}

/// A human summary of what is pending, for the "interrupted restore" notice.
pub fn describe_pending(inc: &Incomplete) -> String {
    let mut lines = vec![format!(
        "An earlier restore of snapshot {} was interrupted. {} left unfinished:",
        inc.run_id,
        crate::output::human::count(inc.pending.len() as u64, "entry was", "entries were")
    )];
    for r in inc.pending.iter().take(20) {
        let what = match r.action {
            Action::Write => "file",
            Action::Symlink => "symlink",
            Action::Mkdir => "directory",
            Action::BackupExisting => "backup",
        };
        lines.push(format!("  {:<8} {}", what, r.dest_path.display()));
    }
    if inc.pending.len() > 20 {
        lines.push(format!("  … and {} more", inc.pending.len() - 20));
    }
    lines.push(String::new());
    lines.push(
        "Re-run with --resume to continue where it stopped, or --rollback to remove the unfinished files and put back any originals."
            .into(),
    );
    lines.join("\n")
}

/// Convert a `MossError`-free I/O failure into the journal's error type.
pub fn io_err(e: std::io::Error) -> MossError {
    MossError::Io(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_and_fold() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state/restore-journal.json");
        let mut j = Journal::open(&path).unwrap();
        let a = j
            .intend(
                "R1",
                "ssh",
                Path::new("/h/.ssh/a"),
                Action::Write,
                None,
                None,
            )
            .unwrap();
        j.done(&a).unwrap();
        let _b = j
            .intend(
                "R1",
                "ssh",
                Path::new("/h/.ssh/b"),
                Action::Write,
                Some("overwrite"),
                None,
            )
            .unwrap();
        drop(j);
        let records = load(&path).unwrap();
        assert_eq!(records.len(), 3);
        let inc = incomplete(&records).unwrap();
        assert_eq!(inc.run_id, "R1");
        assert_eq!(inc.pending.len(), 1);
        assert_eq!(inc.pending[0].dest_path, Path::new("/h/.ssh/b"));
        assert!(inc.done.contains(Path::new("/h/.ssh/a")));
        let resume = ResumeState::from_incomplete(&inc);
        assert!(resume.is_done(Path::new("/h/.ssh/a")));
        assert!(resume.is_pending(Path::new("/h/.ssh/b")));
        // A truncated trailing line is tolerated.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"run_id\": \"R1\", \"sour").unwrap();
        assert_eq!(load(&path).unwrap().len(), 3);
        assert!(load(&tmp.path().join("missing")).unwrap().is_empty());
        assert!(incomplete(&[]).is_none());
        remove(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn rollback_removes_pending_and_restores_backups() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let dest = home.join(".ssh/config");
        let backup = home.join(".ssh/config.moss-backup-1");
        std::fs::write(&backup, b"original").unwrap();
        std::fs::write(&dest, b"partial").unwrap();
        let other = home.join(".ssh/other");
        std::fs::write(&other, b"partial").unwrap();
        let path = tmp.path().join("journal");
        let mut j = Journal::open(&path).unwrap();
        let b = j
            .intend(
                "R1",
                "ssh",
                &dest,
                Action::BackupExisting,
                Some("backup"),
                Some(&backup),
            )
            .unwrap();
        j.done(&b).unwrap();
        j.intend("R1", "ssh", &dest, Action::Write, Some("backup"), None)
            .unwrap();
        j.intend("R1", "ssh", &other, Action::Write, None, None)
            .unwrap();
        let done = j
            .intend(
                "R1",
                "ssh",
                &home.join(".ssh/kept"),
                Action::Write,
                None,
                None,
            )
            .unwrap();
        j.done(&done).unwrap();
        std::fs::write(home.join(".ssh/kept"), b"kept").unwrap();
        drop(j);
        let inc = incomplete(&load(&path).unwrap()).unwrap();
        assert_eq!(inc.pending.len(), 2);
        let text = describe_pending(&inc);
        assert!(text.contains("interrupted"));
        assert!(text.contains("--resume"));
        let summary = rollback(&inc);
        assert!(summary.failed.is_empty(), "{:?}", summary.failed);
        assert_eq!(summary.removed.len(), 2);
        assert_eq!(summary.restored_backups, vec![dest.display().to_string()]);
        assert_eq!(std::fs::read(&dest).unwrap(), b"original");
        assert!(!backup.exists());
        assert!(!other.exists());
        assert!(home.join(".ssh/kept").exists());
    }

    #[test]
    fn abandoned_is_neither_pending_nor_done() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("journal");
        let mut j = Journal::open(&path).unwrap();
        let a = j
            .intend(
                "R1",
                "ssh",
                Path::new("/h/.ssh/a"),
                Action::Write,
                None,
                None,
            )
            .unwrap();
        j.abandon(&a, "disk full").unwrap();
        let b = j
            .intend(
                "R1",
                "ssh",
                Path::new("/h/.ssh/b"),
                Action::Write,
                None,
                None,
            )
            .unwrap();
        drop(j);
        let records = load(&path).unwrap();
        assert_eq!(records[1].state, State::Abandoned);
        assert_eq!(records[1].decision.as_deref(), Some("abandoned: disk full"));
        let inc = incomplete(&records).unwrap();
        assert_eq!(inc.pending, vec![b]);
        assert!(!inc.done.contains(Path::new("/h/.ssh/a")));
        let resume = ResumeState::from_incomplete(&inc);
        assert!(!resume.is_done(Path::new("/h/.ssh/a")));
        assert!(!resume.is_pending(Path::new("/h/.ssh/a")));
    }

    #[test]
    fn damage_before_the_last_line_is_an_integrity_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("journal");
        let mut j = Journal::open(&path).unwrap();
        let a = j
            .intend(
                "R1",
                "ssh",
                Path::new("/h/.ssh/a"),
                Action::Write,
                None,
                None,
            )
            .unwrap();
        j.done(&a).unwrap();
        drop(j);
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.insert_str(0, "{\"garbage\": tru\n");
        std::fs::write(&path, text).unwrap();
        let err = load(&path).unwrap_err();
        assert_eq!(err.exit_code().code(), 8, "{err}");
        assert!(err.to_string().contains("line 1"), "{err}");
    }

    #[test]
    fn non_utf8_paths_round_trip_without_aliasing() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().join("journal");
            let mut j = Journal::open(&path).unwrap();
            let p1 = PathBuf::from(std::ffi::OsStr::from_bytes(b"/h/\xff\xfe"));
            let p2 = PathBuf::from(std::ffi::OsStr::from_bytes(b"/h/\xfe\xff"));
            assert_eq!(
                p1.display().to_string(),
                p2.display().to_string(),
                "lossy forms alias"
            );
            let a = j.intend("R1", "x", &p1, Action::Write, None, None).unwrap();
            j.done(&a).unwrap();
            j.intend("R1", "x", &p2, Action::Write, None, None).unwrap();
            drop(j);
            let inc = incomplete(&load(&path).unwrap()).unwrap();
            assert!(inc.done.contains(&p1));
            assert_eq!(inc.pending[0].dest_path, p2);
            let resume = ResumeState::from_incomplete(&inc);
            assert!(resume.is_done(&p1));
            assert!(!resume.is_done(&p2));
        }
    }
}
