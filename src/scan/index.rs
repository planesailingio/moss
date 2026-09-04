//! The scan index (spec §11): per-directory size, count and mtime so repeat
//! scans can reuse unchanged subtrees.
//!
//! Limitation (by design, spec §11): a directory's mtime changes only when its
//! direct children are added or removed, so a file modified in place deep in a
//! cached subtree is not noticed until `--rescan`. `inspect` reports the index
//! age so the user can judge.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::profile::tools::ToolCache;

pub const INDEX_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirStats {
    pub size: u64,
    pub files: u64,
    pub dirs: u64,
    /// Seconds since the epoch of the directory's own mtime.
    pub mtime: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanIndex {
    pub schema_version: u32,
    pub refreshed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Subtree totals keyed by absolute directory path.
    #[serde(default)]
    pub dirs: BTreeMap<PathBuf, DirStats>,
    #[serde(default)]
    pub tool_caches: Vec<ToolCache>,
    #[serde(default)]
    pub tool_caches_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for ScanIndex {
    fn default() -> Self {
        ScanIndex {
            schema_version: INDEX_SCHEMA_VERSION,
            refreshed_at: None,
            dirs: BTreeMap::new(),
            tool_caches: Vec::new(),
            tool_caches_at: None,
        }
    }
}

impl ScanIndex {
    pub fn load(path: &Path) -> ScanIndex {
        match std::fs::read_to_string(path) {
            Ok(text) => match serde_json::from_str::<ScanIndex>(&text) {
                Ok(i) if i.schema_version == INDEX_SCHEMA_VERSION => i,
                _ => ScanIndex::default(),
            },
            Err(_) => ScanIndex::default(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            crate::config::paths::create_private_dir(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(self)?)?;
        crate::config::paths::make_private_file(&tmp)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn age_seconds(&self, now: chrono::DateTime<chrono::Utc>) -> Option<i64> {
        self.refreshed_at.map(|t| (now - t).num_seconds())
    }

    /// Cached subtree stats if the directory's mtime is unchanged.
    pub fn cached(&self, dir: &Path, mtime: i64) -> Option<&DirStats> {
        self.dirs.get(dir).filter(|d| d.mtime == mtime)
    }

    /// Tool cache answers are reused for a day.
    pub fn tool_caches_fresh(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.tool_caches_at
            .is_some_and(|t| (now - t).num_hours() < 24)
    }
}

pub fn mtime_seconds(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|m| m.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_and_cache_lookup() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("state/index.json");
        let mut idx = ScanIndex::default();
        idx.dirs.insert(
            PathBuf::from("/h/a"),
            DirStats {
                size: 10,
                files: 2,
                dirs: 1,
                mtime: 100,
            },
        );
        idx.refreshed_at = Some(chrono::Utc::now());
        idx.save(&p).unwrap();
        let back = ScanIndex::load(&p);
        assert_eq!(back.dirs, idx.dirs);
        assert!(back.cached(Path::new("/h/a"), 100).is_some());
        assert!(back.cached(Path::new("/h/a"), 101).is_none());
        assert!(back.age_seconds(chrono::Utc::now()).unwrap() < 5);
        assert_eq!(ScanIndex::load(Path::new("/nonexistent")).dirs.len(), 0);
    }
}
