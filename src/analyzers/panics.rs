//! Detect `core::panic::Location` structures in read-only data and emit
//! source `file:line:col` annotations.
//!
//! When Rust compiles a `panic!`, `unwrap()`, `expect()`, or bounds-check
//! failure, the compiler embeds a `core::panic::Location` record adjacent
//! to the panic message / formatting machinery:
//!
//! ```text
//! struct Location {
//!     file_ptr: usize,   // pointer to "../src/foo.rs"
//!     file_len: usize,
//!     line: u32,
//!     col: u32,
//! }
//! ```
//!
//! Validation: file slice must be valid UTF-8, end in `.rs`, and line/col
//! must be plausible (line < `Limits::max_line`, col < `Limits::max_col`).
//! The combination is tight enough that false positives are rare even on
//! noisy binaries.

use crate::analyzers::{Analyzer, Annotation, AnnotationKind, Limits};
use crate::binary::Binary;

#[derive(Debug, Clone)]
pub struct PanicsAnalyzer {
    pub limits: Limits,
}

impl Default for PanicsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PanicsAnalyzer {
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

impl Analyzer for PanicsAnalyzer {
    fn name(&self) -> &'static str {
        "panics"
    }

    fn analyze(&self, bin: &Binary) -> Vec<Annotation> {
        let mut out = Vec::new();
        if bin.is_64 {
            // 64-bit layout: ptr, ptr, u32, u32 -> 24 bytes total.
            scan_locations::<8>(bin, &self.limits, &mut out);
        } else {
            // 32-bit layout: ptr32, ptr32, u32, u32 -> 16 bytes total.
            scan_locations::<4>(bin, &self.limits, &mut out);
        }
        out
    }
}

fn scan_locations<const WS: usize>(bin: &Binary, limits: &Limits, out: &mut Vec<Annotation>) {
    let entry_size = WS * 2 + 4 + 4;
    for sec in bin.sections() {
        if !is_panic_container(&sec.name, sec.size) {
            continue;
        }
        let data = sec.data.as_slice();
        if data.len() < entry_size {
            continue;
        }
        let mut off = 0usize;
        while off + entry_size <= data.len() {
            let lookup = sec.vaddr + off as u64;
            let Some(file_ptr) = bin.read_ptr(lookup) else {
                off += WS;
                continue;
            };
            let Some(file_len) = bin.read_ptr(lookup + WS as u64) else {
                off += WS;
                continue;
            };
            if !(1..=4096).contains(&file_len) {
                off += WS;
                continue;
            }
            if !bin.vaddr_in_string_section(file_ptr, file_len) {
                off += WS;
                continue;
            }
            let line_off = lookup + (WS as u64) * 2;
            let col_off = line_off + 4;
            let Some(line) = bin.read_u32(line_off) else {
                off += WS;
                continue;
            };
            let Some(col) = bin.read_u32(col_off) else {
                off += WS;
                continue;
            };
            if line == 0 || line > limits.max_line || col == 0 || col > limits.max_col {
                off += WS;
                continue;
            }
            // file_len has been bounded to `1..=4096` above; the `as usize`
            // cast cannot truncate on a 64-bit host, and we are not built
            // anywhere else.
            #[allow(clippy::cast_possible_truncation)]
            let Some(bytes) = bin.read_at_vaddr(file_ptr, file_len as usize) else {
                off += WS;
                continue;
            };
            let Ok(file) = std::str::from_utf8(bytes) else {
                off += WS;
                continue;
            };
            // Rust source files are always lowercase-`.rs`. We deliberately
            // do NOT case-fold to "case-insensitive" because Rust toolchain
            // output never produces `Foo.RS`-style names.
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if !file.ends_with(".rs") {
                off += WS;
                continue;
            }
            out.push(Annotation {
                vaddr: lookup,
                kind: AnnotationKind::PanicSite,
                label: format!("{file}:{line}:{col}"),
                comment: None,
            });
            // Skip past the entire record to avoid duplicate emits from
            // overlapping half-step reads.
            off += entry_size;
        }
    }
}

fn is_panic_container(name: &str, size: u64) -> bool {
    // Locations live in any read-only data section. We rely on the section
    // index already being a "string section" — a panic Site struct points
    // into one of those sections, so we only need to scan the same set.
    // For efficiency, we additionally require non-trivial size.
    if size < 16 {
        return false;
    }
    matches!(name, ".rodata" | ".rdata")
        || name.starts_with(".rodata.")
        || name.starts_with(".rdata.")
        || name.starts_with(".data.rel.ro.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_distinct() {
        let lim = Limits::default();
        assert!(lim.max_line >= 100_000);
        assert!(lim.max_col >= 100);
    }
}
