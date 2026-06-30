//! Convert annotations to a renderable stream.
//!
//! Backends consume a `Vec<Annotation>` and render it. They know nothing
//! about analyzing; new backends can be added without touching analyzers.

use crate::analyzers::Annotation;
use std::io::Write;

pub mod binja;
pub mod ghidra;
pub mod json;
pub mod table;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
    GhidraScript,
    BinjaScript,
}

impl Format {
    /// Parse a `--format` value. Recognized: table/text/cli, json,
    /// ghidra / ghidra-py / py-ghidra, binja / binary-ninja / bn /
    /// py-binja.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "table" | "text" | "cli" => Some(Self::Table),
            "json" => Some(Self::Json),
            "ghidra" | "ghidra-py" | "py-ghidra" => Some(Self::GhidraScript),
            "binja" | "binary-ninja" | "bn" | "py-binja" => Some(Self::BinjaScript),
            _ => None,
        }
    }
}

pub trait OutputBackend {
    /// # Errors
    ///
    /// Returns `Err` when the underlying [`std::io::Write`] fails (typically
    /// a broken pipe or a closed stdout). Backends *do not* report analysis
    /// errors here — those are surfaced by the analyzer pipeline before a
    /// backend is ever invoked.
    fn render(&self, anns: &[Annotation], w: &mut dyn Write) -> std::io::Result<()>;
}
