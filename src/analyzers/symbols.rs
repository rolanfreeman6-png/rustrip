//! Demangle Rust symbol names from .symtab / .dynsym.
//!
//! Covers both the legacy `_ZN…E` (C++-style Itanium) mangling used by
//! rustc pre-1.70 and the v0 `_R…` mangling introduced afterward. The
//! `rustc-demangle` crate handles both formats and falls back gracefully
//! on non-Rust symbols by passing them through unchanged.

use crate::analyzers::{Analyzer, Annotation, AnnotationKind};
use crate::binary::Binary;

pub struct SymbolsAnalyzer;

impl SymbolsAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SymbolsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for SymbolsAnalyzer {
    fn name(&self) -> &'static str {
        "symbols"
    }

    fn analyze(&self, bin: &Binary) -> Vec<Annotation> {
        let mut out = Vec::with_capacity(bin.symbols.len());
        for sym in &bin.symbols {
            let pretty = try_demangle(&sym.name);
            out.push(Annotation {
                vaddr: sym.vaddr,
                kind: AnnotationKind::Symbol,
                label: pretty,
                comment: if sym.size > 0 {
                    Some(format!("size={}", sym.size))
                } else {
                    None
                },
            });
        }
        out
    }
}

fn try_demangle(raw: &str) -> String {
    // rustc_demangle 0.1 exposes `try_demangle` which returns
    // `Option<Demangle<'_>>` if `raw` looks like a Rust symbol. The struct's
    // `Display` impl renders the canonical human-readable form (with the
    // version+hash suffix suppressed for stable output).
    match rustc_demangle::try_demangle(raw) {
        Ok(d) => d.to_string(),
        Err(_) => raw.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangles_v0() {
        let s = try_demangle("_RNvCs4fqI2P2rA4_7mycrate3foo");
        assert!(s.contains("mycrate"), "got: {}", s);
    }

    #[test]
    fn demangles_legacy() {
        let s = try_demangle("_ZN7mycrate3fooE");
        assert!(s.contains("mycrate"), "got: {}", s);
    }

    #[test]
    fn passthrough_non_rust() {
        let s = try_demangle("printf");
        assert_eq!(s, "printf");
    }
}
