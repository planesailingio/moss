//! The two confirmation gates before a backup writes anything (spec §10, §14):
//! sensitive data and guardrails. Pure decisions over the scan result and the
//! flags, so every cell of the table is unit-tested; the CLI only asks the
//! question the gate hands back.

use crate::config::Config;
use crate::error::MossError;
use crate::scan::{GuardrailWarning, ScanResult};

/// What the caller must do.
#[derive(Debug)]
pub enum Gate {
    Proceed,
    Refuse(MossError),
    /// Ask this question; on "no", do `on_decline`.
    Confirm {
        preamble: Option<String>,
        question: &'static str,
        on_decline: Decline,
    },
}

#[derive(Debug)]
pub enum Decline {
    /// A "no" is an error with this message (exit code from the variant).
    Refuse(MossError),
    /// A "no" ends the command quietly with exit 1.
    Cancel,
}

/// The flags that influence both gates.
#[derive(Debug, Clone, Copy)]
pub struct Flags {
    pub yes: bool,
    pub non_interactive: bool,
    pub dry_run: bool,
    pub can_prompt: bool,
}

/// Spec §14. `allow_sensitive` false refuses outright; otherwise a warning
/// needs consent once (`--yes`, a prompt, or `--non-interactive`, where the
/// configuration is the standing consent).
pub fn sensitive_gate(config: &Config, result: &ScanResult, flags: Flags) -> Gate {
    let sensitive_files: u64 = result.sensitive.values().sum();
    if sensitive_files == 0 {
        return Gate::Proceed;
    }
    if !config.safety.allow_sensitive {
        return Gate::Refuse(MossError::SensitiveRefusal(format!(
            "This profile contains {sensitive_files} sensitive credential files and safety.allow_sensitive is false."
        )));
    }
    if !config.safety.warn_on_sensitive || flags.dry_run || flags.yes {
        return Gate::Proceed;
    }
    if flags.can_prompt {
        let kinds = result
            .sensitive
            .iter()
            .map(|(k, v)| format!("{} {}", k.display_name(), v))
            .collect::<Vec<_>>()
            .join(", ");
        return Gate::Confirm {
            preamble: Some(format!(
                "\nThis profile contains sensitive credentials ({kinds}).\n\nRepository encryption is enabled.\n"
            )),
            question: "Continue?",
            on_decline: Decline::Refuse(MossError::SensitiveRefusal(
                "Backup cancelled by user.".into(),
            )),
        };
    }
    if !flags.non_interactive {
        return Gate::Refuse(MossError::InteractionRequired(
            "Sensitive data requires confirmation (or --yes).".into(),
        ));
    }
    Gate::Proceed
}

/// Spec §10. Warnings are shown by the caller; this decides whether they stop
/// the run.
pub fn guardrail_gate(warnings: &[GuardrailWarning], flags: Flags) -> Gate {
    if warnings.is_empty() || flags.yes || flags.dry_run {
        return Gate::Proceed;
    }
    if flags.non_interactive {
        return Gate::Refuse(MossError::InteractionRequired(
            "A guardrail threshold was exceeded. Raise the limit in config or pass --yes.".into(),
        ));
    }
    Gate::Confirm {
        preamble: None,
        question: "Continue anyway?",
        on_decline: Decline::Cancel,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ExitCode;
    use crate::profile::sensitive::SensitiveKind;

    fn result(sensitive: u64) -> ScanResult {
        let mut r = ScanResult::default();
        if sensitive > 0 {
            r.sensitive.insert(SensitiveKind::SshPrivateKey, sensitive);
        }
        r
    }

    const fn flags(yes: bool, non_interactive: bool, dry_run: bool, can_prompt: bool) -> Flags {
        Flags {
            yes,
            non_interactive,
            dry_run,
            can_prompt,
        }
    }

    #[test]
    fn sensitive_table() {
        let mut cfg = Config::default();
        // No sensitive files: always proceed.
        assert!(matches!(
            sensitive_gate(&cfg, &result(0), flags(false, false, false, false)),
            Gate::Proceed
        ));
        // allow_sensitive=false refuses with exit 6 regardless of flags.
        cfg.safety.allow_sensitive = false;
        match sensitive_gate(&cfg, &result(3), flags(true, true, true, true)) {
            Gate::Refuse(e) => assert_eq!(e.exit_code(), ExitCode::SensitiveRefusal),
            other => panic!("{other:?}"),
        }
        cfg.safety.allow_sensitive = true;
        cfg.safety.warn_on_sensitive = true;
        // --yes, --dry-run, or warn_on_sensitive=false: proceed without asking.
        assert!(matches!(
            sensitive_gate(&cfg, &result(3), flags(true, false, false, true)),
            Gate::Proceed
        ));
        assert!(matches!(
            sensitive_gate(&cfg, &result(3), flags(false, false, true, true)),
            Gate::Proceed
        ));
        // A terminal: ask, and "no" is a refusal with exit 6.
        match sensitive_gate(&cfg, &result(3), flags(false, false, false, true)) {
            Gate::Confirm {
                question,
                on_decline: Decline::Refuse(e),
                preamble,
            } => {
                assert_eq!(question, "Continue?");
                assert_eq!(e.exit_code(), ExitCode::SensitiveRefusal);
                let text = preamble.unwrap();
                assert!(
                    text.contains(&format!(
                        "{} 3",
                        SensitiveKind::SshPrivateKey.display_name()
                    )),
                    "{text}"
                );
            }
            other => panic!("{other:?}"),
        }
        // No terminal and not --non-interactive: exit 13.
        match sensitive_gate(&cfg, &result(3), flags(false, false, false, false)) {
            Gate::Refuse(e) => assert_eq!(e.exit_code(), ExitCode::InteractionRequired),
            other => panic!("{other:?}"),
        }
        // --non-interactive with allow_sensitive=true: configuration is consent.
        assert!(matches!(
            sensitive_gate(&cfg, &result(3), flags(false, true, false, false)),
            Gate::Proceed
        ));
        cfg.safety.warn_on_sensitive = false;
        assert!(matches!(
            sensitive_gate(&cfg, &result(3), flags(false, false, false, true)),
            Gate::Proceed
        ));
    }

    #[test]
    fn guardrail_table() {
        let warn = vec![GuardrailWarning {
            message: "too big".into(),
        }];
        assert!(matches!(
            guardrail_gate(&[], flags(false, true, false, false)),
            Gate::Proceed
        ));
        assert!(matches!(
            guardrail_gate(&warn, flags(true, true, false, false)),
            Gate::Proceed
        ));
        assert!(matches!(
            guardrail_gate(&warn, flags(false, false, true, false)),
            Gate::Proceed
        ));
        match guardrail_gate(&warn, flags(false, true, false, false)) {
            Gate::Refuse(e) => assert_eq!(e.exit_code(), ExitCode::InteractionRequired),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            guardrail_gate(&warn, flags(false, false, false, true)),
            Gate::Confirm {
                question: "Continue anyway?",
                on_decline: Decline::Cancel,
                ..
            }
        ));
    }
}
