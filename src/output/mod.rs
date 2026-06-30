//! Output backends — final stage of the pipeline.
//!
//! Backends consume a `Vec<Annotation>` and render it. They know nothing
//! about analyzing; new backends can be added without touching analyzers.

use crate::analyzers::Annotation;
use std::io::Write;

pub mod binja;
pub mod ghidra;
pub mod json;
pub mod table;

pub enum Format {
    Table,
    Json,
    GhidraScript,
    BinjaScript,
}

impl Format {
    /// Parse a `--format` value. Renamed from `from_str` to avoid the
    /// clippy `should_implement_trait` false-positive against
    /// `std::str::FromStr::from_str` (we return `Option`, the trait returns
    /// `Result`).
    #[allow(clippy::should_implement_trait)]
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
    fn render(&self, anns: &[Annotation], w: &mut dyn Write) -> std::io::Result<()>;
}
