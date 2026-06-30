//! Detect `core::panic::Location` structures in read-only data and emit
//! source file:line annotations.
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
//! Validation: file slice must be valid UTF-8, end in ".rs", and line/col
//! must be plausible (line < 1_000_000, col < 10_000). The combination is
//! tight enough that false positives are rare even on noisy binaries.

use crate::analyzers::{Analyzer, Annotation, AnnotationKind, Limits};
use crate::binary::Binary;

pub struct PanicsAnalyzer {
    pub limits: Limits,
}

impl PanicsAnalyzer {
    pub fn new() -> Self {
        Self {
            limits: Limits::default(),
        }
    }

    pub fn with_limits(limits: Limits) -> Self {
        Self { limits }
    }
}

impl Default for PanicsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for PanicsAnalyzer {
    fn name(&self) -> &'static str {
        "panics"
    }

    fn analyze(&self, bin: &Binary) -> Vec<Annotation> {
        let mut out = Vec::new();
        if bin.is_64 {
            // Layout: ptr, ptr, u32, u32 -> 24 bytes total.
            scan_locations::<8>(bin, &self.limits, &mut out);
        } else {
            // Layout: ptr32, ptr32, u32, u32 -> 16 bytes total.
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
            let file_ptr = match bin.read_ptr(lookup) {
                Some(p) => p,
                None => {
                    off += WS;
                    continue;
                }
            };
            let file_len = match bin.read_ptr(lookup + WS as u64) {
                Some(l) => l,
                None => {
                    off += WS;
                    continue;
                }
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
            let line = match bin.read_u32(line_off) {
                Some(l) => l,
                None => {
                    off += WS;
                    continue;
                }
            };
            let col = match bin.read_u32(col_off) {
                Some(c) => c,
                None => {
                    off += WS;
                    continue;
                }
            };
            if line == 0 || line > limits.max_line || col == 0 || col > limits.max_col {
                off += WS;
                continue;
            }
            let bytes = match bin.read_at_vaddr(file_ptr, file_len as usize) {
                Some(b) => b,
                None => {
                    off += WS;
                    continue;
                }
            };
            let file = match std::str::from_utf8(bytes) {
                Ok(s) => s,
                Err(_) => {
                    off += WS;
                    continue;
                }
            };
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
    // `core::panic::Location` records live in the read-only data sections
    // of the binary — sections that we already classify as string-hosting
    // for the strings analyzer (`.rodata*`, `.data.rel.ro*`, `.rdata*`,
    // Mach-O equivalents). In addition, we treat the named RO sections
    // explicitly so binaries with a `.rdata` section that doesn't
    // appear in our recognizer still work.
    if size < 16 {
        return false;
    }

    name == ".rodata"
        || name.starts_with(".rodata.")
        || name == ".rdata"
        || name.starts_with(".rdata.")
        || name == ".data.rel.ro"
        || name.starts_with(".data.rel.ro.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_distinct() {
        // Sanity: limits default values are sane.
        let lim = Limits::default();
        assert!(lim.max_line >= 100_000);
        assert!(lim.max_col >= 100);
    }
}
