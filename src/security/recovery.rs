//! The recovery code (spec §6).
//!
//! 32 bytes of entropy → 24 BIP39 English words. The canonical sentence
//! (lowercase words, single spaces) *is* the Kopia repository password.

use bip39::{Language, Mnemonic};
use zeroize::Zeroize;

use crate::error::{MossError, Result};
use crate::security::secret::Secret;

pub const WORD_COUNT: usize = 24;

/// Generate a fresh password from the OS CSPRNG.
pub fn generate() -> Result<Secret> {
    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy)
        .map_err(|e| MossError::Other(format!("system random number generator failed: {e}")))?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| MossError::Other(format!("mnemonic generation failed: {e}")))?;
    entropy.zeroize();
    Ok(Secret::new(mnemonic.to_string()))
}

/// Parse user input in any spacing or case into the canonical password.
///
/// Reports the first word that is not in the list, or a checksum failure.
pub fn parse(input: &str) -> Result<Secret> {
    let words: Vec<String> = input
        .split(|c: char| c.is_whitespace() || c == ',' || c == '-' || c == '.')
        .filter(|w| !w.is_empty())
        // Tolerate numbered sheets: "1. abandon" or "1) abandon".
        .filter(|w| {
            !w.chars()
                .all(|c| c.is_ascii_digit() || c == ')' || c == '.')
        })
        .map(|w| w.to_lowercase())
        .collect();
    if words.len() != WORD_COUNT {
        return Err(MossError::Credential(format!(
            "The recovery code has {} words; expected {WORD_COUNT}.",
            words.len()
        )));
    }
    let list = Language::English;
    for (i, w) in words.iter().enumerate() {
        if list.find_word(w).is_none() {
            let suggestions = list
                .words_by_prefix(&w[..w.len().min(3)])
                .iter()
                .take(4)
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(MossError::Credential(format!(
                "Word {} (\"{w}\") is not a recovery-code word.{}",
                i + 1,
                if suggestions.is_empty() {
                    String::new()
                } else {
                    format!(" Did you mean one of: {suggestions}?")
                }
            )));
        }
    }
    let sentence = words.join(" ");
    let mnemonic = Mnemonic::parse_in_normalized(list, &sentence).map_err(|e| {
        MossError::Credential(format!(
            "The recovery code did not validate ({e}). Check each word against the sheet; one is probably transposed or misspelled."
        ))
    })?;
    Ok(Secret::new(mnemonic.to_string()))
}

/// Render the 24 words as a numbered grid, four per row.
pub fn format_words(secret: &Secret) -> String {
    let words: Vec<&str> = secret.expose().split(' ').collect();
    let mut lines = Vec::new();
    for row in words.chunks(4) {
        let base = lines.len() * 4;
        let cells: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, w)| format!("{:>2}. {:<10}", base + i + 1, w))
            .collect();
        lines.push(format!("    {}", cells.join(" ").trim_end()));
    }
    lines.join("\n")
}

pub struct SheetInfo<'a> {
    pub repository: &'a str,
    pub endpoint: Option<&'a str>,
    pub created: &'a str,
    pub profile: &'a str,
    pub moss_version: &'a str,
    pub kopia_version: &'a str,
}

/// The recovery sheet (spec §6).
pub fn format_sheet(info: &SheetInfo<'_>, secret: &Secret) -> String {
    let mut s = String::new();
    s.push_str("RECOVERY SHEET — store this offline, away from this machine\n\n");
    s.push_str(&format!("  Repository:  {}\n", info.repository));
    if let Some(e) = info.endpoint {
        s.push_str(&format!("  Endpoint:    {e}\n"));
    }
    s.push_str(&format!("  Created:     {}\n", info.created));
    s.push_str(&format!("  Profile:     {}\n", info.profile));
    s.push_str(&format!(
        "  moss:        {:<9} Kopia: {}\n",
        info.moss_version, info.kopia_version
    ));
    s.push_str("\n  Recovery code (24 words, in this order):\n");
    s.push_str(&format_words(secret));
    s.push_str("\n\n  Without this code, and without access to this machine's\n");
    s.push_str("  keychain, the repository CANNOT be recovered. There is no\n");
    s.push_str("  reset, no vendor, and no backdoor.\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn generate_is_24_valid_words() {
        let s = generate().unwrap();
        let words: Vec<&str> = s.expose().split(' ').collect();
        assert_eq!(words.len(), 24);
        assert_eq!(parse(s.expose()).unwrap(), s);
        assert_ne!(generate().unwrap(), s);
    }

    #[test]
    fn parse_normalises_case_and_spacing() {
        let messy = SAMPLE.to_uppercase().replace(' ', "  \n");
        assert_eq!(parse(&messy).unwrap().expose(), SAMPLE);
        let numbered = format_words(&Secret::new(SAMPLE));
        assert_eq!(parse(&numbered).unwrap().expose(), SAMPLE);
    }

    #[test]
    fn parse_names_bad_word() {
        let bad = SAMPLE.replacen("abandon", "abandan", 1);
        let err = parse(&bad).unwrap_err().to_string();
        assert!(err.contains("Word 1"), "{err}");
        let short = "abandon abandon";
        assert!(parse(short).unwrap_err().to_string().contains("2 words"));
    }

    #[test]
    fn checksum_catches_swapped_word() {
        // Replace the checksum-bearing last word.
        let swapped = SAMPLE.replace(" art", " zoo");
        let err = parse(&swapped).unwrap_err().to_string();
        assert!(err.contains("did not validate"), "{err}");
    }

    #[test]
    fn sheet_contains_words_and_versions() {
        let sheet = format_sheet(
            &SheetInfo {
                repository: "s3://bucket/rhys",
                endpoint: Some("https://s3.example.com"),
                created: "2026-09-02",
                profile: "rhys",
                moss_version: "0.1.0",
                kopia_version: "0.23.1",
            },
            &Secret::new(SAMPLE),
        );
        assert!(sheet.contains("24. art"));
        assert!(sheet.contains("Kopia: 0.23.1"));
        assert!(sheet.contains("Endpoint:    https://s3.example.com"));
    }
}
