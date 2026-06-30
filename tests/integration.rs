//! Smoke integration tests against real binaries.
//!
//! Strategy: `cargo` automatically sets `CARGO_BIN_EXE_<bin>` to the path
//! of each compiled binary. We point rustrip at itself.
//!
//! Self-analysis has two purposes:
//! 1. exercises the full pipeline (parse → analyzers → output) against
//!    a real PE/ELF/Mach-O;
//! 2. ensures regressions in the analyzer logic are caught even if unit
//!    tests happen to pass.

use rustrip::analyzers::{
    panics::PanicsAnalyzer, strings::StringsAnalyzer, symbols::SymbolsAnalyzer, Limits, Registry,
};
use rustrip::binary::Binary;
use rustrip::Analyzer;
use std::path::PathBuf;

fn self_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rustrip"))
}

#[test]
fn parses_self_binary() {
    let p = self_binary();
    let bytes = std::fs::read(&p).expect("read rustrip binary");
    let bin = Binary::parse(Some(p.to_str().unwrap()), bytes).expect("parse");
    assert!(!bin.sections().is_empty(), "must expose >= 1 section");
    assert!(
        !bin.string_section_indices().is_empty()
            || bin.sections().iter().any(|s| !s.data.is_empty()),
        "binary must contain data we can read"
    );
}

#[test]
fn strings_analyzer_recovers_or_is_safe_on_no_strings() {
    let p = self_binary();
    let bytes = std::fs::read(&p).expect("read rustrip binary");
    let bin = Binary::parse(Some(p.to_str().unwrap()), bytes).expect("parse");
    let analyzer = StringsAnalyzer::with_limits(Limits::default());
    let anns = analyzer.analyze(&bin);
    // rustrip's literal count and layout vary across PE / ELF / Mach-O and
    // across debug vs release profiles. We don't require a specific count;
    // we only assert the analyzer did not panic and that any annotations
    // it produced have non-empty labels.
    for a in &anns {
        assert!(!a.label.is_empty(), "empty label at vaddr {:#x}", a.vaddr);
    }
}

#[test]
fn symbols_analyzer_demangles_self_without_panic() {
    let p = self_binary();
    let bytes = std::fs::read(&p).expect("read rustrip binary");
    let bin = Binary::parse(Some(p.to_str().unwrap()), bytes).expect("parse");
    let analyzer = SymbolsAnalyzer::new();
    let _anns = analyzer.analyze(&bin);
}

#[test]
fn full_registry_does_not_panic_on_self() {
    let p = self_binary();
    let bytes = std::fs::read(&p).expect("read rustrip binary");
    let bin = Binary::parse(Some(p.to_str().unwrap()), bytes).expect("parse");
    let r = Registry::new()
        .with(Box::new(StringsAnalyzer::new()))
        .with(Box::new(SymbolsAnalyzer::new()))
        .with(Box::new(PanicsAnalyzer::new()));
    let anns = r.run(&bin);
    assert!(!anns.is_empty());
}

#[test]
fn rejects_garbage_input() {
    let res = Binary::parse(Some("junk"), vec![0u8; 64]);
    assert!(res.is_err(), "garbage must error out, not silently succeed");
}

#[test]
fn rejects_truncated_input() {
    let res = Binary::parse(Some("tiny"), b"AB".to_vec());
    assert!(res.is_err());
}

#[test]
fn table_output_renders_without_panic() {
    use rustrip::analyzers::{Annotation, AnnotationKind};
    use rustrip::output::table::Table;
    use rustrip::output::OutputBackend;

    let anns = vec![
        Annotation {
            vaddr: 0x0040_1000,
            kind: AnnotationKind::String,
            label: "hello".into(),
            comment: Some("hello world".into()),
        },
        Annotation {
            vaddr: 0x0040_1100,
            kind: AnnotationKind::Symbol,
            label: "core::fmt::Write::write_str".into(),
            comment: None,
        },
        Annotation {
            vaddr: 0x0040_1200,
            kind: AnnotationKind::PanicSite,
            label: "src/foo.rs:42:9".into(),
            comment: None,
        },
    ];
    let mut sink: Vec<u8> = Vec::new();
    Table.render(&anns, &mut sink).unwrap();
    let s = String::from_utf8(sink).unwrap();
    assert!(s.contains("hello world"));
    assert!(s.contains("core::fmt"));
    assert!(s.contains("src/foo.rs:42:9"));
}

#[test]
fn json_output_serializes() {
    use rustrip::analyzers::{Annotation, AnnotationKind};
    use rustrip::output::json::Json;
    use rustrip::output::OutputBackend;

    let anns = vec![Annotation {
        vaddr: 0x0040_1000,
        kind: AnnotationKind::String,
        label: "ok".into(),
        comment: None,
    }];
    let mut sink: Vec<u8> = Vec::new();
    Json.render(&anns, &mut sink).unwrap();
    let s = String::from_utf8(sink).unwrap();
    assert!(s.contains("\"vaddr\": \"0x401000\""));
}

#[test]
fn ghidra_script_contains_assignments() {
    use rustrip::analyzers::{Annotation, AnnotationKind};
    use rustrip::output::ghidra::Ghidra;
    use rustrip::output::OutputBackend;

    let anns = vec![Annotation {
        vaddr: 0x0040_1000,
        kind: AnnotationKind::Symbol,
        label: "core::fmt::write".into(),
        comment: None,
    }];
    let mut sink: Vec<u8> = Vec::new();
    Ghidra.render(&anns, &mut sink).unwrap();
    let s = String::from_utf8(sink).unwrap();
    assert!(s.contains("currentProgram"));
    assert!(s.contains("0x401000"));
}

#[test]
fn binja_script_contains_assignments() {
    use rustrip::analyzers::{Annotation, AnnotationKind};
    use rustrip::output::binja::Binja;
    use rustrip::output::OutputBackend;

    let anns = vec![Annotation {
        vaddr: 0x0040_1000,
        kind: AnnotationKind::Symbol,
        label: "core::fmt::write".into(),
        comment: None,
    }];
    let mut sink: Vec<u8> = Vec::new();
    Binja.render(&anns, &mut sink).unwrap();
    let s = String::from_utf8(sink).unwrap();
    assert!(s.contains("binaryninja"));
    assert!(s.contains("0x401000"));
}
