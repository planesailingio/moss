//! (stub)
use crate::cli::AppContext;
use crate::error::{ExitCode, MossError, Result};
pub fn run(_ctx: &AppContext) -> Result<ExitCode> {
    Err(MossError::Usage("not implemented".into()))
}
