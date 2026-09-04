//! (stub)
use crate::cli::AppContext;
use crate::error::{ExitCode, MossError, Result};
use clap::Args;
#[derive(Debug, Args)]
pub struct ConfigArgs {}
#[derive(Debug, Args)]
pub struct IncludeArgs {}
#[derive(Debug, Args)]
pub struct ExcludeArgs {}
#[derive(Debug, Args)]
pub struct RecoveryArgs {}
#[derive(Debug, Args)]
pub struct YubikeyArgs {}
#[derive(Debug, Args)]
pub struct KopiaArgs {
    pub args: Vec<String>,
}
pub fn config(_ctx: &AppContext, _a: ConfigArgs) -> Result<ExitCode> {
    Err(MossError::Usage("not implemented".into()))
}
pub fn include(_ctx: &AppContext, _a: IncludeArgs) -> Result<ExitCode> {
    Err(MossError::Usage("not implemented".into()))
}
pub fn exclude(_ctx: &AppContext, _a: ExcludeArgs) -> Result<ExitCode> {
    Err(MossError::Usage("not implemented".into()))
}
pub fn recovery(_ctx: &AppContext, _a: RecoveryArgs) -> Result<ExitCode> {
    Err(MossError::Usage("not implemented".into()))
}
pub fn yubikey(_ctx: &AppContext, _a: YubikeyArgs) -> Result<ExitCode> {
    Err(MossError::Usage("not implemented".into()))
}
pub fn kopia(_ctx: &AppContext, _a: KopiaArgs) -> Result<ExitCode> {
    Err(MossError::Usage("not implemented".into()))
}
