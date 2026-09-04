//! (stub)
use crate::cli::AppContext;
use crate::error::{ExitCode, MossError, Result};
use clap::Args;
#[derive(Debug, Args)]
pub struct SnapshotsArgs {}
pub fn run(_ctx: &AppContext, _a: SnapshotsArgs) -> Result<ExitCode> {
    Err(MossError::Usage("not implemented".into()))
}
