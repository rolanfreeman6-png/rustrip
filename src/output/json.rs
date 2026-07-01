//! Machine-readable JSON output.
//!
//! Schema:
//! ```json
//! [
//!   {
//!     "vaddr": "0x401000",
//!     "kind": "string",
//!     "label": "...",
//!     "comment": "..."
//!   }
//! ]
//! ```

use crate::analyzers::{Annotation, AnnotationKind};
use crate::output::OutputBackend;
use serde::Serialize;
use std::io::Write;

#[derive(Serialize)]
struct Out<'a> {
    vaddr: String,
    kind: &'a str,
    label: &'a str,
    comment: Option<&'a str>,
}

pub struct Json;

impl OutputBackend for Json {
    fn render(&self, anns: &[Annotation], w: &mut dyn Write) -> std::io::Result<()> {
        let projection: Vec<Out> = anns
            .iter()
            .map(|a| Out {
                vaddr: format!("0x{:x}", a.vaddr),
                kind: kind_str(&a.kind),
                label: &a.label,
                comment: a.comment.as_deref(),
            })
            .collect();
        serde_json::to_writer_pretty(&mut *w, &projection)?;
        writeln!(w)
    }
}

const fn kind_str(k: &AnnotationKind) -> &'static str {
    use AnnotationKind::{PanicSite, String as KString, Symbol};
    match k {
        KString => "string",
        Symbol => "symbol",
        PanicSite => "panic",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::{Annotation, AnnotationKind};

    #[test]
    fn json_array_shape() {
        let anns = vec![Annotation {
            vaddr: 0x0040_1000,
            kind: AnnotationKind::Symbol,
            label: "core::fmt::write".into(),
            comment: Some("size=128".into()),
        }];
        let mut buf = Vec::new();
        // nosemgrep: rustrip-no-unwrapping-trust-bytes (test code)
        Json.render(&anns, &mut buf).unwrap();
        // nosemgrep: rustrip-no-unwrapping-trust-bytes (test code)
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("\"vaddr\": \"0x401000\""));
        assert!(s.contains("\"kind\": \"symbol\""));
        assert!(s.contains("core::fmt::write"));
    }
}
