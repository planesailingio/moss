//! Conflict handling (spec §16): what to do when a destination already exists.
//!
//! Bulk policies come from `--conflict` or the config; `interactive` asks per
//! file with the exact prompt from the spec and offers a diff for text files.
//! A prompt that cannot be shown is an error (exit 13), never a silent
//! overwrite.

use std::io::Read;
use std::path::Path;
use std::time::SystemTime;

use crate::config::ConflictPolicy;
use crate::error::{MossError, Result};
use crate::output::Console;
use crate::restore::contain::Metadata;

/// Diffs are shown only for text files up to this size.
pub const DIFF_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Skip,
    Overwrite,
    Backup,
}

impl Decision {
    pub fn label(self) -> &'static str {
        match self {
            Decision::Skip => "skip",
            Decision::Overwrite => "overwrite",
            Decision::Backup => "backup",
        }
    }
}

/// The existing file's side of a conflict, read only when a diff is asked for.
pub struct Existing<'a> {
    pub display: &'a str,
    pub meta: &'a Metadata,
    /// Opens the existing file through containment.
    pub open: &'a dyn Fn() -> std::io::Result<std::fs::File>,
}

/// The staged file's side.
pub struct Staged<'a> {
    pub path: &'a Path,
    pub len: u64,
    pub mode: u32,
    pub modified: Option<SystemTime>,
}

type PromptFn = Box<dyn FnMut(&str) -> Result<String>>;

pub struct Resolver {
    policy: ConflictPolicy,
    /// Set by a capital answer: applies to every remaining conflict.
    bulk: Option<Decision>,
    prompt: PromptFn,
    show: Box<dyn FnMut(&str)>,
}

impl Resolver {
    /// A resolver that prompts on the console. `Interactive` without a usable
    /// terminal fails with exit 13 at the first conflict.
    pub fn new(policy: ConflictPolicy, console: &Console) -> Resolver {
        let console = *console;
        let prompt_console = console;
        Resolver {
            policy,
            bulk: None,
            prompt: Box::new(move |q| crate::output::prompt_line(&prompt_console, q)),
            show: Box::new(move |text| console.line(text)),
        }
    }

    /// A resolver with scripted answers (tests).
    pub fn with_prompt(
        policy: ConflictPolicy,
        prompt: impl FnMut(&str) -> Result<String> + 'static,
        show: impl FnMut(&str) + 'static,
    ) -> Resolver {
        Resolver {
            policy,
            bulk: None,
            prompt: Box::new(prompt),
            show: Box::new(show),
        }
    }

    pub fn policy(&self) -> ConflictPolicy {
        self.policy
    }

    /// Decide for one existing destination.
    pub fn decide(&mut self, existing: &Existing<'_>, staged: &Staged<'_>) -> Result<Decision> {
        if let Some(d) = self.bulk {
            return Ok(d);
        }
        match self.policy {
            ConflictPolicy::Skip => Ok(Decision::Skip),
            ConflictPolicy::Overwrite => Ok(Decision::Overwrite),
            ConflictPolicy::Backup => Ok(Decision::Backup),
            ConflictPolicy::Interactive => self.ask(existing, staged),
        }
    }

    fn ask(&mut self, existing: &Existing<'_>, staged: &Staged<'_>) -> Result<Decision> {
        loop {
            (self.show)(&format!(
                "\n{} exists\n\n  [s] Skip\n  [o] Overwrite\n  [b] Backup existing\n  [d] Diff\n\n  (S, O or B applies the choice to all remaining conflicts)",
                existing.display
            ));
            let answer = match (self.prompt)(">") {
                Ok(a) => a,
                Err(MossError::InteractionRequired(_)) => {
                    return Err(MossError::InteractionRequired(format!(
                        "{} exists and no --conflict policy was given.",
                        existing.display
                    )));
                }
                Err(e) => return Err(e),
            };
            match answer.trim() {
                "s" => return Ok(Decision::Skip),
                "o" => return Ok(Decision::Overwrite),
                "b" => return Ok(Decision::Backup),
                "S" => {
                    self.bulk = Some(Decision::Skip);
                    return Ok(Decision::Skip);
                }
                "O" => {
                    self.bulk = Some(Decision::Overwrite);
                    return Ok(Decision::Overwrite);
                }
                "B" => {
                    self.bulk = Some(Decision::Backup);
                    return Ok(Decision::Backup);
                }
                "d" | "D" => {
                    let text = match diff_sides(existing, staged) {
                        Ok(t) => t,
                        Err(e) => format!("(could not read both sides: {e})"),
                    };
                    (self.show)(&text);
                }
                _ => (self.show)("Please answer s, o, b or d."),
            }
        }
    }
}

fn diff_sides(existing: &Existing<'_>, staged: &Staged<'_>) -> std::io::Result<String> {
    let mut old = Vec::new();
    (existing.open)()?
        .take(DIFF_MAX_BYTES + 1)
        .read_to_end(&mut old)?;
    let mut new = Vec::new();
    std::fs::File::open(staged.path)?
        .take(DIFF_MAX_BYTES + 1)
        .read_to_end(&mut new)?;
    Ok(render_diff(
        &old,
        &new,
        &Side {
            label: "existing",
            len: existing.meta.len,
            modified: existing.meta.modified,
        },
        &Side {
            label: "snapshot",
            len: staged.len,
            modified: staged.modified,
        },
    ))
}

pub struct Side {
    pub label: &'static str,
    pub len: u64,
    pub modified: Option<SystemTime>,
}

/// A line diff for text (both sides ≤ 1 MB, valid UTF-8, no NUL); size,
/// mtime and SHA-256 of both sides otherwise.
pub fn render_diff(old: &[u8], new: &[u8], old_side: &Side, new_side: &Side) -> String {
    if old.len() as u64 <= DIFF_MAX_BYTES
        && new.len() as u64 <= DIFF_MAX_BYTES
        && let (Some(a), Some(b)) = (as_text(old), as_text(new))
    {
        let body = line_diff(a, b);
        return format!(
            "--- {} ({})\n+++ {} ({})\n{}",
            old_side.label,
            crate::output::human::bytes(old_side.len),
            new_side.label,
            crate::output::human::bytes(new_side.len),
            body
        );
    }
    let describe = |side: &Side, bytes: &[u8]| {
        format!(
            "  {:<9} {:>10}  {}  sha256:{}",
            side.label,
            crate::output::human::bytes(side.len),
            side.modified
                .map(|t| {
                    chrono::DateTime::<chrono::Local>::from(t)
                        .format("%Y-%m-%d %H:%M:%S")
                        .to_string()
                })
                .unwrap_or_else(|| "unknown mtime".into()),
            if bytes.len() as u64 > DIFF_MAX_BYTES {
                "(not computed: larger than 1 MB)".to_string()
            } else {
                hex(&sha256(bytes))
            }
        )
    };
    format!(
        "Binary or large files; no diff shown.\n{}\n{}",
        describe(old_side, old),
        describe(new_side, new)
    )
}

fn as_text(bytes: &[u8]) -> Option<&str> {
    if bytes.iter().take(8192).any(|b| *b == 0) {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Keep,
    Del,
    Add,
}

/// Longest-common-subsequence line diff with two lines of context.
pub fn line_diff(old: &str, new: &str) -> String {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    if a == b {
        return "(contents are identical; only metadata differs)".into();
    }
    if a.len().saturating_mul(b.len()) > 4_000_000 {
        return format!(
            "(files differ; {} vs {} lines, too large for an inline diff)",
            a.len(),
            b.len()
        );
    }
    let script = edit_script(&a, &b);
    let mut out = Vec::new();
    let mut i = 0;
    let mut j = 0;
    let mut pending_keep: Vec<String> = Vec::new();
    let mut started = false;
    for op in script {
        match op {
            Op::Keep => {
                pending_keep.push(format!("  {}", a[i]));
                i += 1;
                j += 1;
            }
            Op::Del | Op::Add => {
                flush_context(&mut out, &mut pending_keep, started);
                started = true;
                if op == Op::Del {
                    out.push(format!("- {}", a[i]));
                    i += 1;
                } else {
                    out.push(format!("+ {}", b[j]));
                    j += 1;
                }
            }
        }
    }
    // Trailing context.
    let tail: Vec<String> = pending_keep.into_iter().take(2).collect();
    out.extend(tail);
    out.join("\n")
}

fn flush_context(out: &mut Vec<String>, pending: &mut Vec<String>, started: bool) {
    if pending.is_empty() {
        return;
    }
    let n = pending.len();
    if started && n > 4 {
        out.extend(pending.drain(..2));
        out.push("  …".into());
        let rest: Vec<String> = std::mem::take(pending);
        out.extend(rest.into_iter().skip(n - 4));
    } else if !started && n > 2 {
        if n > 2 {
            out.push("  …".into());
        }
        let rest: Vec<String> = std::mem::take(pending);
        out.extend(rest.into_iter().skip(n - 2));
    } else {
        out.append(pending);
    }
}

fn edit_script(a: &[&str], b: &[&str]) -> Vec<Op> {
    let n = a.len();
    let m = b.len();
    let w = m + 1;
    let mut table = vec![0u32; (n + 1) * (m + 1)];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            table[i * w + j] = if a[i] == b[j] {
                table[(i + 1) * w + j + 1] + 1
            } else {
                table[(i + 1) * w + j].max(table[i * w + j + 1])
            };
        }
    }
    let mut ops = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            ops.push(Op::Keep);
            i += 1;
            j += 1;
        } else if table[(i + 1) * w + j] >= table[i * w + j + 1] {
            ops.push(Op::Del);
            i += 1;
        } else {
            ops.push(Op::Add);
            j += 1;
        }
    }
    ops.extend(std::iter::repeat_n(Op::Del, n - i));
    ops.extend(std::iter::repeat_n(Op::Add, m - j));
    ops
}

/// SHA-256 (FIPS 180-4), small and dependency-free; used only to describe
/// binary conflicts to the user.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(v);
        }
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restore::contain::EntryKind;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    fn meta() -> Metadata {
        Metadata {
            kind: EntryKind::File,
            len: 3,
            mode: 0o644,
            modified: None,
        }
    }

    fn scripted(policy: ConflictPolicy, answers: &[&str]) -> (Resolver, Rc<RefCell<Vec<String>>>) {
        let queue: Rc<RefCell<VecDeque<String>>> = Rc::new(RefCell::new(
            answers.iter().map(|s| s.to_string()).collect(),
        ));
        let shown = Rc::new(RefCell::new(Vec::new()));
        let shown2 = shown.clone();
        let resolver = Resolver::with_prompt(
            policy,
            move |_| {
                queue.borrow_mut().pop_front().ok_or_else(|| {
                    MossError::InteractionRequired("no more scripted answers".into())
                })
            },
            move |text| shown2.borrow_mut().push(text.to_string()),
        );
        (resolver, shown)
    }

    fn decide(resolver: &mut Resolver, tmp: &Path) -> Result<Decision> {
        let existing_path = tmp.join("existing");
        let staged_path = tmp.join("staged");
        std::fs::write(&existing_path, "a\nb\nc\n").unwrap();
        std::fs::write(&staged_path, "a\nB\nc\nd\n").unwrap();
        let open = move || std::fs::File::open(&existing_path);
        let m = meta();
        let existing = Existing {
            display: "~/.ssh/config",
            meta: &m,
            open: &open,
        };
        let staged = Staged {
            path: &staged_path,
            len: 8,
            mode: 0o600,
            modified: None,
        };
        resolver.decide(&existing, &staged)
    }

    #[test]
    fn bulk_policies_never_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        for (policy, expected) in [
            (ConflictPolicy::Skip, Decision::Skip),
            (ConflictPolicy::Overwrite, Decision::Overwrite),
            (ConflictPolicy::Backup, Decision::Backup),
        ] {
            let (mut r, shown) = scripted(policy, &[]);
            assert_eq!(decide(&mut r, tmp.path()).unwrap(), expected);
            assert!(shown.borrow().is_empty());
        }
    }

    #[test]
    fn interactive_prompt_matches_spec_and_supports_diff_and_apply_to_all() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut r, shown) = scripted(ConflictPolicy::Interactive, &["x", "d", "O"]);
        assert_eq!(decide(&mut r, tmp.path()).unwrap(), Decision::Overwrite);
        let text = shown.borrow().join("\n");
        assert!(text.contains("~/.ssh/config exists"));
        assert!(text.contains("[s] Skip"));
        assert!(text.contains("[o] Overwrite"));
        assert!(text.contains("[b] Backup existing"));
        assert!(text.contains("[d] Diff"));
        assert!(text.contains("Please answer"));
        assert!(text.contains("- b"), "{text}");
        assert!(text.contains("+ B"), "{text}");
        assert!(text.contains("+ d"), "{text}");
        // Capital O applied to all remaining: no further prompt.
        assert_eq!(decide(&mut r, tmp.path()).unwrap(), Decision::Overwrite);
    }

    #[test]
    fn interactive_without_a_terminal_is_exit_13() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut r, _) = scripted(ConflictPolicy::Interactive, &[]);
        let err = decide(&mut r, tmp.path()).unwrap_err();
        assert_eq!(err.exit_code().code(), 13);
        assert!(err.to_string().contains("~/.ssh/config exists"));
        let console = Console::for_tests();
        let mut r = Resolver::new(ConflictPolicy::Interactive, &console);
        assert_eq!(
            decide(&mut r, tmp.path()).unwrap_err().exit_code().code(),
            13
        );
    }

    #[test]
    fn diff_rendering() {
        let side = |len| Side {
            label: "x",
            len,
            modified: None,
        };
        let d = render_diff(b"a\nb\n", b"a\nc\n", &side(4), &side(4));
        assert!(d.contains("- b") && d.contains("+ c"), "{d}");
        assert_eq!(
            line_diff("same\n", "same\n"),
            "(contents are identical; only metadata differs)"
        );
        let long_old: String = (0..30).map(|i| format!("l{i}\n")).collect();
        let long_new = long_old.replace("l15\n", "L15\n");
        let d = line_diff(&long_old, &long_new);
        assert!(d.contains("…"), "{d}");
        assert!(d.contains("- l15") && d.contains("+ L15"));
        assert!(!d.contains("l3\n"), "far context should be elided: {d}");
        let bin = render_diff(b"\x00\x01", b"\x00\x02", &side(2), &side(2));
        assert!(bin.contains("sha256:"), "{bin}");
        assert!(bin.contains("Binary"));
    }

    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let long = vec![b'a'; 1000];
        assert_eq!(
            hex(&sha256(&long)),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }
}
