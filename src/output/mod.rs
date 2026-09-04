//! Human and JSON output (spec §26, §32).
//!
//! TTY detection, `NO_COLOR`, `--quiet` and `--json` are decided once here.

use std::io::{IsTerminal, Write};

use owo_colors::{OwoColorize, Stream};
use serde::Serialize;

pub mod human;

/// JSON schema version carried by every machine-readable report (spec §26).
pub const JSON_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Console {
    pub json: bool,
    pub quiet: bool,
    pub verbose: u8,
    pub non_interactive: bool,
    pub stdout_tty: bool,
    pub stderr_tty: bool,
    pub color: bool,
}

impl Console {
    pub fn new(json: bool, quiet: bool, verbose: u8, non_interactive: bool) -> Console {
        let stdout_tty = std::io::stdout().is_terminal();
        let stderr_tty = std::io::stderr().is_terminal();
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        Console {
            json,
            quiet,
            verbose,
            non_interactive,
            stdout_tty,
            stderr_tty,
            color: stdout_tty && !no_color && !json,
        }
    }

    pub fn for_tests() -> Console {
        Console {
            json: false,
            quiet: false,
            verbose: 0,
            non_interactive: true,
            stdout_tty: false,
            stderr_tty: false,
            color: false,
        }
    }

    /// Prompts are possible only on an interactive terminal (spec §32).
    pub fn can_prompt(&self) -> bool {
        !self.non_interactive && self.stdout_tty && std::io::stdin().is_terminal()
    }

    /// Print a human line (suppressed by --json and --quiet).
    pub fn line(&self, text: impl AsRef<str>) {
        if self.json || self.quiet {
            return;
        }
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{}", text.as_ref());
    }

    /// Print regardless of --quiet (but not under --json): warnings.
    pub fn warn(&self, text: impl AsRef<str>) {
        if self.json {
            return;
        }
        let mut err = std::io::stderr().lock();
        let text = text.as_ref();
        if self.color && self.stderr_tty {
            let _ = writeln!(
                err,
                "{}",
                text.if_supports_color(Stream::Stderr, |t| t.yellow())
            );
        } else {
            let _ = writeln!(err, "{text}");
        }
    }

    /// Print an error message (always, even under --json it goes to stderr).
    pub fn error(&self, text: impl AsRef<str>) {
        let mut err = std::io::stderr().lock();
        let _ = writeln!(err, "{}", text.as_ref());
    }

    pub fn debug(&self, text: impl AsRef<str>) {
        if self.verbose > 0 && !self.json {
            let mut err = std::io::stderr().lock();
            let _ = writeln!(err, "{}", text.as_ref());
        }
    }

    /// Emit a JSON report with `schema_version`.
    pub fn json_report<T: Serialize>(&self, report: &T) -> std::io::Result<()> {
        let value = with_schema(report);
        let mut out = std::io::stdout().lock();
        serde_json::to_writer_pretty(&mut out, &value)?;
        writeln!(out)
    }

    pub fn ok_mark(&self) -> &'static str {
        if self.color {
            "\u{1b}[32m✓\u{1b}[0m"
        } else {
            "✓"
        }
    }

    pub fn fail_mark(&self) -> &'static str {
        if self.color {
            "\u{1b}[31m✗\u{1b}[0m"
        } else {
            "✗"
        }
    }

    pub fn warn_mark(&self) -> &'static str {
        if self.color {
            "\u{1b}[33m!\u{1b}[0m"
        } else {
            "!"
        }
    }

    pub fn na_mark(&self) -> &'static str {
        "–"
    }
}

/// Wrap a report with `schema_version` at the top level.
pub fn with_schema<T: Serialize>(report: &T) -> serde_json::Value {
    let mut value = serde_json::to_value(report).unwrap_or(serde_json::Value::Null);
    if let serde_json::Value::Object(map) = &mut value {
        let mut ordered = serde_json::Map::new();
        ordered.insert(
            "schema_version".to_string(),
            serde_json::Value::from(JSON_SCHEMA_VERSION),
        );
        for (k, v) in map.iter() {
            ordered.insert(k.clone(), v.clone());
        }
        value = serde_json::Value::Object(ordered);
    }
    value
}

/// Ask a yes/no question. Returns `Err(InteractionRequired)` when no prompt is possible.
pub fn confirm(console: &Console, question: &str, default_yes: bool) -> crate::error::Result<bool> {
    if !console.can_prompt() {
        return Err(crate::error::MossError::InteractionRequired(format!(
            "A confirmation is required: {question}"
        )));
    }
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "{question} {suffix} ");
    let _ = out.flush();
    drop(out);
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(match answer.as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        _ => false,
    })
}

/// Read a line of input (not echoed differently; for non-secret answers).
pub fn prompt_line(console: &Console, question: &str) -> crate::error::Result<String> {
    if !console.can_prompt() {
        return Err(crate::error::MossError::InteractionRequired(format!(
            "Input is required: {question}"
        )));
    }
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "{question} ");
    let _ = out.flush();
    drop(out);
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_first() {
        #[derive(Serialize)]
        struct R {
            a: u32,
        }
        let v = with_schema(&R { a: 1 });
        let text = serde_json::to_string(&v).unwrap();
        assert!(text.starts_with("{\"schema_version\":1"));
        assert_eq!(v["a"], 1);
    }

    #[test]
    fn non_interactive_confirm_fails_with_13() {
        let c = Console::for_tests();
        let err = confirm(&c, "Continue?", false).unwrap_err();
        assert_eq!(err.exit_code().code(), 13);
    }
}
