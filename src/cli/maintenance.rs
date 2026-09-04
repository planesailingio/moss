//! (stub)
use crate::cli::AppContext;
use crate::error::{ExitCode, MossError, Result};
use clap::Args;
#[derive(Debug, Args)]
pub struct VerifyArgs {}
#[derive(Debug, Args)]
pub struct PruneArgs {}
#[derive(Debug, Args)]
pub struct MaintenanceArgs {}
pub fn status(_ctx: &AppContext) -> Result<ExitCode> {
    Err(MossError::Usage("not implemented".into()))
}
pub fn verify(_ctx: &AppContext, _a: VerifyArgs) -> Result<ExitCode> {
    Err(MossError::Usage("not implemented".into()))
}
pub fn prune(_ctx: &AppContext, _a: PruneArgs) -> Result<ExitCode> {
    Err(MossError::Usage("not implemented".into()))
}
pub fn run(_ctx: &AppContext, _a: MaintenanceArgs) -> Result<ExitCode> {
    Err(MossError::Usage("not implemented".into()))
}
