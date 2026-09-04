//! (stub)
use crate::cli::AppContext;
use crate::error::{ExitCode, MossError, Result};
use clap::Args;
#[derive(Debug, Args)]
pub struct BackupArgs {}
pub fn run(_ctx: &AppContext, _a: BackupArgs) -> Result<ExitCode> {
    Err(MossError::Usage("not implemented".into()))
}
