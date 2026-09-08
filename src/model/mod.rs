//! Pure data shared by every layer: the operating-system enum, the semantic
//! profile model, and the scan-output leaf types the manifest records.
//!
//! Nothing here does I/O or depends on another moss module, so `platform`,
//! `profile`, `scan`, `backup`, `restore` and `cli` can all sit above it
//! without cycles (see ARCHITECTURE.md, "Module layering").

mod platform;
mod profile;
mod skip;

pub use platform::Platform;
pub use profile::{
    Inclusion, Portability, ProfileCategory, ProfileSource, SemanticId, expand_tilde, home_relative,
};
pub use skip::{Collision, SkipReason, Skipped};
