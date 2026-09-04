//! Restore (spec §15–§17): two-stage — Kopia restores into a moss-owned
//! staging directory, then moss places each entry with containment, conflict
//! handling and a journal.

pub mod conflict;
pub mod contain;
pub mod journal;
pub mod place;
pub mod report;
pub mod select;
pub mod translate;
