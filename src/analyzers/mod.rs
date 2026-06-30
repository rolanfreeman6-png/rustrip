//! Pluggable analyzer framework.
//!
//! An analyzer takes a parsed [`Binary`] and produces a `Vec<Annotation>`.
//! The pipeline is simple: every analyzer is independent, the registry
//! aggregates, and a single output backend renders the merged set.

use crate::binary::Binary;

pub mod panics;
pub mod strings;
pub mod symbols;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnnotationKind {
    /// Recovered `&str` slice (Rust fat pointer). The `vaddr` is the *string*
    /// location, not the slice-header location.
    String,
    /// Demangled symbol name.
    Symbol,
    /// Panic/Unwrap/Expect site with file:line:col.
    PanicSite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    pub vaddr: u64,
    pub kind: AnnotationKind,
    pub label: String,
    pub comment: Option<String>,
}

pub trait Analyzer: Sync {
    fn name(&self) -> &'static str;
    fn analyze(&self, bin: &Binary) -> Vec<Annotation>;
}

pub struct Registry {
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            analyzers: Vec::new(),
        }
    }

    pub fn with(mut self, a: Box<dyn Analyzer>) -> Self {
        self.analyzers.push(a);
        self
    }

    pub fn run(&self, bin: &Binary) -> Vec<Annotation> {
        let mut out = Vec::new();
        for a in &self.analyzers {
            out.extend(a.analyze(bin));
        }
        // Stable order — helps determinism for snapshot tests & JSON output.
        out.sort_by(|x, y| {
            x.vaddr
                .cmp(&y.vaddr)
                .then_with(|| format!("{:?}", x.kind).cmp(&format!("{:?}", y.kind)))
                .then_with(|| x.label.cmp(&y.label))
        });
        dedup(&mut out);
        out
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Drop identical annotations (same vaddr+kind+label) so duplicate slice
/// references don't bloat the output. Panic sites with the same vaddr but
/// wildly different line numbers would be suspicious — but identical entries
/// are common because multiple code paths reference the same `&'static str`.
fn dedup(out: &mut Vec<Annotation>) {
    out.dedup_by(|a, b| {
        a.vaddr == b.vaddr && a.kind == b.kind && a.label == b.label && a.comment == b.comment
    });
}

/// Tunables shared by analyzers that walk pointer-sized data structures.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Maximum bytes consumed by any single recovered string.
    pub max_string_len: usize,
    /// Maximum line number accepted as a panic location.
    pub max_line: u32,
    /// Maximum column number accepted as a panic location.
    pub max_col: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_string_len: 4096,
            max_line: 1_000_000,
            max_col: 10_000,
        }
    }
}

// Registry tests live in integration tests where a real Binary fixture is
// available; the in-module test surface just verifies pure logic.
