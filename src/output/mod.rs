//! Human and JSON output (spec §26, §32).
//!
//! TTY detection, `NO_COLOR`, `--quiet` and `--json` are decided once here.
//! The console owns its two writers, so every command renders through it and
//! tests can capture exactly what a user would see.

use std::io::{IsTerminal, Write};
use std::sync::{Arc, Mutex};

use owo_colors::{OwoColorize, Stream};
use serde::Serialize;

pub mod human;

/// JSON schema version carried by every machine-readable report (spec §26).
pub const JSON_SCHEMA_VERSION: u32 = 1;

type Writer = Arc<Mutex<Box<dyn Write + Send>>>;

#[derive(Clone)]
pub struct Console {
    pub json: bool,
    pub quiet: bool,
    pub verbose: u8,
    pub non_interactive: bool,
    pub stdout_tty: bool,
    pub stderr_tty: bool,
    pub color: bool,
    out: Writer,
    err: Writer,
}

impl std::fmt::Debug for Console {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Console")
            .field("json", &self.json)
            .field("quiet", &self.quiet)
            .field("verbose", &self.verbose)
            .field("non_interactive", &self.non_interactive)
            .finish_non_exhaustive()
    }
}

/// A `Write` over a shared buffer, for capturing output in tests.
#[derive(Clone, Default)]
pub struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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
            out: Arc::new(Mutex::new(Box::new(std::io::stdout()))),
            err: Arc::new(Mutex::new(Box::new(std::io::stderr()))),
        }
    }

    /// A non-interactive console whose output goes nowhere.
    pub fn for_tests() -> Console {
        Console::capturing().0
    }

    /// A non-interactive console whose stdout and stderr are captured.
    pub fn capturing() -> (Console, Captured, Captured) {
        let out = Captured::default();
        let err = Captured::default();
        let console = Console {
            json: false,
            quiet: false,
            verbose: 0,
            non_interactive: true,
            stdout_tty: false,
            stderr_tty: false,
            color: false,
            out: Arc::new(Mutex::new(Box::new(out.clone()))),
            err: Arc::new(Mutex::new(Box::new(err.clone()))),
        };
        (console, out, err)
    }

    /// Prompts are possible only on an interactive terminal, and never in
    /// `--json` mode, which is machine mode (spec §32).
    pub fn can_prompt(&self) -> bool {
        !self.non_interactive && !self.json && self.stdout_tty && std::io::stdin().is_terminal()
    }

    fn write_out(&self, text: &str, newline: bool) {
        let mut out = self.out.lock().unwrap();
        let _ = out.write_all(text.as_bytes());
        if newline {
            let _ = out.write_all(b"\n");
        }
        let _ = out.flush();
    }

    fn write_err(&self, text: &str, newline: bool) {
        let mut err = self.err.lock().unwrap();
        let _ = err.write_all(text.as_bytes());
        if newline {
            let _ = err.write_all(b"\n");
        }
        let _ = err.flush();
    }

    /// Print an informational line (suppressed by --json and --quiet).
    pub fn line(&self, text: impl AsRef<str>) {
        if self.json || self.quiet {
            return;
        }
        self.write_out(text.as_ref(), true);
    }

    /// Print a command's result (suppressed by --json only: `--quiet` hides
    /// chatter, not the answer).
    pub fn result(&self, text: impl AsRef<str>) {
        if self.json {
            return;
        }
        self.write_out(text.as_ref(), true);
    }

    /// Write verbatim to stdout, regardless of flags (pass-through output).
    pub fn raw(&self, text: impl AsRef<str>) {
        self.write_out(text.as_ref(), false);
    }

    /// Write verbatim to stderr, regardless of flags.
    pub fn raw_err(&self, text: impl AsRef<str>) {
        self.write_err(text.as_ref(), false);
    }

    /// Print regardless of --quiet (but not under --json): warnings.
    pub fn warn(&self, text: impl AsRef<str>) {
        if self.json {
            return;
        }
        let text = text.as_ref();
        if self.color && self.stderr_tty {
            self.write_err(
                &text
                    .if_supports_color(Stream::Stderr, |t| t.yellow())
                    .to_string(),
                true,
            );
        } else {
            self.write_err(text, true);
        }
    }

    /// Print an error message (always, even under --json it goes to stderr).
    pub fn error(&self, text: impl AsRef<str>) {
        self.write_err(text.as_ref(), true);
    }

    /// Emit a JSON report with `schema_version`.
    pub fn json_report<T: Serialize>(&self, report: &T) -> std::io::Result<()> {
        let value = with_schema(report);
        let mut text = serde_json::to_string_pretty(&value)?;
        text.push('\n');
        self.write_out(&text, false);
        Ok(())
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
    // Prompts go to stderr so stdout stays a clean report stream.
    console.raw_err(format!("{question} {suffix} "));
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
    console.raw_err(format!("{question} "));
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
    fn quiet_hides_chatter_but_not_results_and_json_hides_both() {
        let (mut c, out, err) = Console::capturing();
        c.quiet = true;
        c.line("chatter");
        c.result("answer");
        c.warn("careful");
        assert_eq!(out.text(), "answer\n");
        assert_eq!(err.text(), "careful\n");
        let (mut c, out, _) = Console::capturing();
        c.json = true;
        c.line("chatter");
        c.result("answer");
        c.json_report(&serde_json::json!({ "a": 1 })).unwrap();
        assert!(
            out.text().starts_with("{\n  \"schema_version\": 1"),
            "{}",
            out.text()
        );
        assert!(!out.text().contains("answer"));
    }

    #[test]
    fn json_mode_never_prompts() {
        let mut c = Console::for_tests();
        c.non_interactive = false;
        c.stdout_tty = true;
        c.json = true;
        assert!(!c.can_prompt());
    }

    #[test]
    fn non_interactive_confirm_fails_with_13() {
        let c = Console::for_tests();
        let err = confirm(&c, "Continue?", false).unwrap_err();
        assert_eq!(err.exit_code().code(), 13);
    }
}
