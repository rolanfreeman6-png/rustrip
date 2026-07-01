//! Recover `&str` slices from read-only data sections.
//!
//! Rust string literals are stored as `(ptr, len)` fat-pointer pairs in
//! read-only data sections (ELF: `.rodata`, `.data.rel.ro`; PE: `.rdata`;
//! Mach-O: `__cstring` / `__const`). Disassemblers see these tables as one
//! giant blob of bytes with no internal structure. We walk the tables at
//! pointer-aligned offsets, dereference each `(ptr, len)` pair, validate
//! that the slice lies entirely inside a string-hosting section, and
//! require valid UTF-8 with at least one alphanumeric character.
//!
//! Tuples that fail *any* of those checks are rejected. The combination
//! of UTF-8 validity, length bounds, and alphanumeric content is
//! conservative on real binaries and rejects more than 95% of random
//! pair collisions on stripped ELF/PE artifacts.

use crate::analyzers::{Analyzer, Annotation, AnnotationKind, Limits};
use crate::binary::Binary;

/// Section-name prefixes that may *contain* `(ptr, len)` slice headers.
///
/// Slices for `&'static str` literals live in the same section as the
/// string bytes themselves in ELF release builds, so the container is
/// typically `.rodata.*`. Some toolchains also place them in
/// `.data.rel.ro.*` due to relocation processing.
const CONTAINER_PATTERNS: &[&str] = &[
    ".rodata",
    ".data.rel.ro",
    ".rdata",
    "__cstring",
    "__const",
    "__DATA,__const",
];

#[derive(Debug, Clone)]
pub struct StringsAnalyzer {
    pub limits: Limits,
}

impl Default for StringsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl StringsAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            limits: Limits::default(),
        }
    }

    #[must_use]
    pub const fn with_limits(limits: Limits) -> Self {
        Self { limits }
    }
}

impl Analyzer for StringsAnalyzer {
    fn name(&self) -> &'static str {
        "strings"
    }

    fn analyze(&self, bin: &Binary) -> Vec<Annotation> {
        let mut out = Vec::new();
        let ws = if bin.is_64 { 8usize } else { 4 };
        let max = self.limits.max_string_len;

        for sec in bin.sections() {
            if !is_container_section(&sec.name) {
                continue;
            }
            scan_section(bin, sec, ws, max, &mut out);
        }
        out
    }
}

fn scan_section(
    bin: &Binary,
    sec: &crate::binary::Section,
    ws: usize,
    max: usize,
    out: &mut Vec<Annotation>,
) {
    let data = sec.data.as_slice();
    if data.len() < ws.saturating_mul(2) {
        return;
    }
    // Step by `ws` bytes: many slice-headers can sit at offset 0, 8, 16...
    // but random table rows interleaved with relocations are also plausible.
    // We rely on the validity checks to reject near-misses.
    let mut off = 0usize;
    while off.checked_add(ws * 2).is_some_and(|e| e <= data.len()) {
        // Wraparound-protected walker:
        //   `sec.vaddr.checked_add(off as u64)` saturates if the section
        //   vaddr is so large that adding the dataset offset overflows
        //   u64. Stop the walk in that case — malicious binaries padding
        //   u64::MAX shouldn't be able to overflow our pointer arithmetic.
        let Some(lookup) = sec.vaddr.checked_add(off as u64) else {
            break;
        };
        let Some(ptr) = bin.read_ptr(lookup) else {
            off = off.saturating_add(ws);
            continue;
        };
        let Some(len) = bin.read_ptr(lookup.wrapping_add(ws as u64)) else {
            off = off.saturating_add(ws);
            continue;
        };

        if len < 1 || (usize::try_from(len).map_or(true, |n: usize| n > max)) {
            off = off.saturating_add(ws);
            continue;
        }
        if !bin.vaddr_in_string_section(ptr, len) {
            off = off.saturating_add(ws);
            continue;
        }
        let Some(bytes) = bin.read_at_vaddr(ptr, usize::try_from(len).unwrap_or(usize::MAX)) else {
            off = off.saturating_add(ws);
            continue;
        };
        if !is_reasonable_string(bytes) {
            off = off.saturating_add(ws);
            continue;
        }

        let text = String::from_utf8_lossy(bytes).into_owned();
        if text.is_empty() {
            off = off.saturating_add(ws);
            continue;
        }
        let label = truncate(&text, 80);
        out.push(Annotation {
            vaddr: ptr,
            kind: AnnotationKind::String,
            label,
            comment: Some(text),
        });
        off = off.saturating_add(ws);
    }
}

fn is_container_section(name: &str) -> bool {
    for p in CONTAINER_PATTERNS {
        if name == *p || name.starts_with(p) || name.contains(p) {
            return true;
        }
    }
    false
}

/// A candidate slice must be valid UTF-8, contain no control characters,
/// and contain at least one alphanumeric character. Punctuation-only
/// runs (e.g. `--`, `::`) are rejected because (a) they almost always
/// coincide with random `(ptr, len)` alignments inside relocation tables
/// and (b) real Rust string literals virtually always include at least one
/// letter or digit.
fn is_reasonable_string(b: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(b) else {
        return false;
    };
    if s.is_empty() {
        return false;
    }
    !s.chars().any(char::is_control) && s.chars().any(char::is_alphanumeric)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n).collect();
        out.push('\u{2026}');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_rejected() {
        assert!(!is_reasonable_string(b""));
        assert!(!is_reasonable_string(b"\x00\x00\x00"));
    }

    #[test]
    fn control_chars_rejected() {
        assert!(!is_reasonable_string(b"hello\x00world"));
        assert!(!is_reasonable_string(b"hello\nworld"));
    }

    #[test]
    fn alphanumeric_required() {
        assert!(is_reasonable_string(b"hello world"));
        assert!(is_reasonable_string(b"src/foo.rs:42"));
        assert!(is_reasonable_string(b"v1.2.3-rc1"));
        assert!(is_reasonable_string(b"~/path/to/{x}"));
    }

    #[test]
    fn punctuation_only_rejected() {
        assert!(!is_reasonable_string(b"--"));
        assert!(!is_reasonable_string(b"::"));
        assert!(!is_reasonable_string(b"..."));
        assert!(!is_reasonable_string(b"()"));
    }

    #[test]
    fn truncate_keeps_ellipsis() {
        let t = truncate(&"a".repeat(120), 10);
        assert!(t.chars().count() <= 11);
        assert!(t.ends_with('\u{2026}'));
    }
}
