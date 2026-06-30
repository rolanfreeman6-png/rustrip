//! rustrip — make stripped Rust binaries readable again.
//!
//! Public API re-exports. The pipeline is:
//!
//! ```text
//! goblin Parse -> `Binary` -> `[Analyzer]` -> `Vec<Annotation>` -> Output backend
//! ```
//!
//! Each stage is independent. New analyzers and new output backends can be added
//! without touching the others. See `analyzers` and `output` modules.

pub mod analyzers;
pub mod binary;
pub mod output;

pub use analyzers::{Analyzer, Annotation, AnnotationKind, Registry};
pub use binary::{Binary, BinaryFormat, Section, Symbol};
