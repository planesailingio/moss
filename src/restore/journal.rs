//! The restore journal (spec §18): each intended write is recorded and
//! fsynced *before* the file is touched, and marked done afterwards, so an
//! interrupted restore can be resumed or rolled back on the next run.
//!
//! Format: newline-delimited JSON at `<state>/restore-journal.json`. A file
//! has two records over its life (`intended`, then `done`); the reader folds
//! them by destination path.

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub run_id: String,
    pub source_id: String,
    /// Absolute destination path as written (display form).
    pub dest_path: String,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    pub state: State,
    /// For `backup_existing`: where the original was moved to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<String>,
    pub at: chrono::DateTime<chrono::Utc>,
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
            dest_path: dest_path.display().to_string(),
            action,
            decision: decision.map(str::to_string),
            state: State::Intended,
            backup_path: backup_path.map(|p| p.display().to_string()),
            at: chrono::Utc::now(),
        };
        self.record(&r)?;
        Ok(r)
    }

    pub fn done(&mut self, intended: &Record) -> Result<()> {
        let r = Record {
            state: State::Done,
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

/// Read every record. A missing file is an empty journal; a truncated last
/// line (crash mid-write) is ignored.
pub fn load(path: &Path) -> Result<Vec<Record>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Record>(&line) {
            Ok(r) => out.push(r),
            Err(_) => break,
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
    pub backups: BTreeMap<String, Record>,
    /// Destinations whose write completed.
    pub done: HashSet<String>,
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
    let mut state: BTreeMap<(String, Action), Record> = BTreeMap::new();
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
    pub done: HashSet<String>,
    pub pending: HashSet<String>,
}

impl ResumeState {
    pub fn from_incomplete(inc: &Incomplete) -> ResumeState {
        ResumeState {
            done: inc.done.clone(),
            pending: inc.pending.iter().map(|r| r.dest_path.clone()).collect(),
        }
    }

    pub fn is_done(&self, dest: &Path) -> bool {
        self.done.contains(&dest.display().to_string())
    }

    pub fn is_pending(&self, dest: &Path) -> bool {
        self.pending.contains(&dest.display().to_string())
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
        let dest = PathBuf::from(&r.dest_path);
        let (Some(parent), Some(name)) = (dest.parent(), dest.file_name()) else {
            summary
                .failed
                .push((r.dest_path.clone(), "not a file path".into()));
            continue;
        };
        let name = Path::new(name);
        let root = match Root::open(parent) {
            Ok(root) => root,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                summary.failed.push((r.dest_path.clone(), e.to_string()));
                continue;
            }
        };
        match root.exists(name) {
            Ok(Some(m)) if !m.is_dir() => match root.remove_file(name) {
                Ok(()) => summary.removed.push(r.dest_path.clone()),
                Err(e) => summary.failed.push((r.dest_path.clone(), e.to_string())),
            },
            Ok(_) => {}
            Err(e) => summary.failed.push((r.dest_path.clone(), e.to_string())),
        }
        if let Some(backup) = inc.backups.get(&r.dest_path)
            && let Some(backup_path) = &backup.backup_path
            && let Some(backup_name) = Path::new(backup_path).file_name()
        {
            match root.rename_within(Path::new(backup_name), name) {
                Ok(()) => summary.restored_backups.push(r.dest_path.clone()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => summary.failed.push((
                    backup_path.clone(),
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
        lines.push(format!("  {:<8} {}", what, r.dest_path));
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
        assert_eq!(inc.pending[0].dest_path, "/h/.ssh/b");
        assert!(inc.done.contains("/h/.ssh/a"));
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
}
