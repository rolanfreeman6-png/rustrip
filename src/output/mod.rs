//! Output backends — final stage of the pipeline.
//!
//! Backends consume a `Vec<Annotation>` and render it. They know nothing
//! about analyzing; new backends can be added without touching analyzers.

use crate::analyzers::Annotation;
use std::io::Write;

pub mod table;
pub mod json;
pub mod ghidra;
pub mod binja;

pub enum Format {
    Table,
    Json,
    GhidraScript,
    BinjaScript,
}

impl Format {
    pub fn from_str(s: &str) -> Option<Self> {
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
