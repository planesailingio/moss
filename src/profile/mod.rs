//! Profile discovery: the product (spec §8–§10, §14).
//!
//! `locations.rs` is the one table of built-in sources; `discovery.rs` reads
//! it on this machine; `rules.rs`, `patterns.rs`, `tools.rs` and
//! `sensitive.rs` decide what inside a source is backed up.

pub mod discovery;
pub mod locations;
pub mod patterns;
pub mod rules;
pub mod sensitive;
pub mod tools;
