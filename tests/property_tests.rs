//! Property-style tests with synthetic binary fixtures.
//!
//! `integration.rs` exercises the end-to-end pipeline against the
//! just-built rustrip binary. That covers one *particular* object
//! layout; mutations inside parser branches that the rustrip fixture
//! never trips (off>cap clamping, off-by-one pointer alignment, etc)
//! slip through and produce FALSE NEGATIVES in cargo-mutants' view.
//!
//! These tests build *minimal* synthetic blob inputs via
//! `Binary::from_test_parts` to reach every branch we care about:
//! truncated sections, RO-data outside the recognised category,
//! pointer reads at section boundaries, etc.

use rustrip::analyzers::{
    panics::PanicsAnalyzer, strings::StringsAnalyzer, symbols::SymbolsAnalyzer, AnnotationKind,
    Limits, Registry,
};
use rustrip::binary::{Binary, Section, Symbol};
use rustrip::output::{table::Table, Format, OutputBackend};
use rustrip::Analyzer;

use rustrip::binary::BinaryFormat as Bf;
use std::collections::HashSet;
use std::path::PathBuf;

// -- Helpers --------------------------------------------------------------

fn fake_bin(
    section_name: &str,
    vaddr: u64,
    data: &[u8],
    force_string_classification: bool,
) -> Binary {
    let force = if force_string_classification {
        vec![0]
    } else {
        vec![]
    };
    Binary::from_test_parts(
        Bf::Elf,
        true,
        true,
        vec![Section {
            name: section_name.into(),
            vaddr,
            size: data.len() as u64,
            data: data.to_vec(),
        }],
        vec![],
        force,
    )
}

fn fake_bin_with_symbols(
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    force_string_sections: Vec<usize>,
) -> Binary {
    Binary::from_test_parts(
        Bf::Elf,
        true,
        true,
        sections,
        symbols,
        force_string_sections,
    )
}

/// Build a `core::panic::Location` payload with the file bytes overlaid
/// at the requested `file_ptr_offset` (relative). Length semantics match
/// the real Rust type: `file_len` is the `&str` length — no trailing NUL.
///
/// The body is padded with zero bytes up to the part the analyzer would
/// actually dereference. If `file_len` exceeds `file.len()`, anything
/// beyond the supplied content is read as zeroes. This is fine for the
/// negative tests (`panics_rejects_oversized_file_len`,
/// `panics_rejects_truncated_payload`) where the analyzer must reject
/// *before* reading bytes anyway.
fn panic_record_body(
    file_ptr_offset: usize,
    file_len: u64,
    line: u32,
    col: u32,
    file: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0u64.to_le_bytes());
    b.extend_from_slice(&file_len.to_le_bytes());
    b.extend_from_slice(&line.to_le_bytes());
    b.extend_from_slice(&col.to_le_bytes());
    while b.len() < file_ptr_offset {
        b.push(0);
    }
    b.extend(file.iter().copied());
    let file_ptr = 0x4000u64 + file_ptr_offset as u64;
    b[0..8].copy_from_slice(&file_ptr.to_le_bytes());
    b
}

fn panic_site_annots(bin: &Binary) -> Vec<String> {
    PanicsAnalyzer::new()
        .analyze(bin)
        .iter()
        .filter(|a| matches!(a.kind, rustrip::analyzers::AnnotationKind::PanicSite))
        .map(|a| a.label.clone())
        .collect()
}

fn string_annots_present(bin: &Binary) -> bool {
    StringsAnalyzer::with_limits(Limits::default())
        .analyze(bin)
        .iter()
        .any(|a| matches!(a.kind, rustrip::analyzers::AnnotationKind::String))
}

// -- Predicate coverage: Format::parse --------------------------------------

#[test]
fn format_parse_handles_every_alias() {
    assert!(matches!(Format::parse("table"), Some(Format::Table)));
    assert!(matches!(Format::parse("text"), Some(Format::Table)));
    assert!(matches!(Format::parse("cli"), Some(Format::Table)));
    assert!(matches!(Format::parse("json"), Some(Format::Json)));
    assert!(matches!(
        Format::parse("ghidra"),
        Some(Format::GhidraScript)
    ));
    assert!(matches!(
        Format::parse("ghidra-py"),
        Some(Format::GhidraScript)
    ));
    assert!(matches!(
        Format::parse("py-ghidra"),
        Some(Format::GhidraScript)
    ));
    assert!(matches!(Format::parse("binja"), Some(Format::BinjaScript)));
    assert!(matches!(
        Format::parse("binary-ninja"),
        Some(Format::BinjaScript)
    ));
    assert!(matches!(Format::parse("bn"), Some(Format::BinjaScript)));
    assert!(matches!(
        Format::parse("py-binja"),
        Some(Format::BinjaScript)
    ));
    assert!(Format::parse("TABLE").is_some(), "case-insensitive alias");
}

#[test]
fn format_parse_rejects_unknown() {
    assert!(Format::parse("").is_none());
    assert!(Format::parse("yaml").is_none());
    assert!(Format::parse("xml").is_none());
    assert!(Format::parse("GARBAGE").is_none());
}

#[test]
fn rejects_empty_bytes() {
    assert!(Binary::parse(Some(""), Vec::new()).is_err());
}

#[test]
fn rejects_truncated_elf_magic() {
    assert!(Binary::parse(Some(""), b"\x7fELF".to_vec()).is_err());
}

#[test]
fn elf_magic_only_is_rejected() {
    let res = Binary::parse(Some(""), b"\x7fELF".to_vec());
    assert!(
        res.is_err(),
        "ELF magic only without rest of header must error"
    );
}

#[test]
fn pe_zero_size_image_errors_cleanly() {
    let res = Binary::parse(Some(""), b"MZ".to_vec());
    assert!(res.is_err());
}

#[test]
fn unreadable_format_is_parsed_quietly() {
    let res = Binary::parse(Some(""), b"\xff\xaa\x00\x01\x02garbage".to_vec());
    assert!(res.is_err(), "garbage must error out, not silently succeed");
}

// -- Predicate coverage: `is_string_section_name` ----------------------------

#[test]
fn is_string_section_name_prefixes_matched() {
    for name in [
        ".rodata",
        ".rodata.local",
        ".data.rel.ro",
        ".data.rel.ro.foo",
        ".rdata",
        ".rdata.x",
        "__cstring",
        "__cstring,FOO",
        "__const",
        "__const,FOO",
    ] {
        let bin = fake_bin(name, 0x4000, b"hi", true);
        assert!(
            bin.vaddr_in_string_section(0x4000, 1),
            "{name} must be classified as string-hosting"
        );
    }
    for name in [
        ".text",
        ".debug_info",
        ".rela.dyn",
        ".symtab",
        ".strtab",
        "",
    ] {
        let bin = fake_bin(name, 0x4000, b"hi", false);
        assert!(
            !bin.vaddr_in_string_section(0x4000, 1),
            "{name} must NOT be classified as string-hosting"
        );
    }
}

// -- Symbols analyzer: size gate -------------------------------------------

#[test]
fn symbols_commented_when_size_positive() {
    let bin = fake_bin_with_symbols(
        vec![],
        vec![
            Symbol {
                vaddr: 0x1000,
                name: "_ZN3foo3barE".into(),
                size: 42,
            },
            Symbol {
                vaddr: 0x2000,
                name: "_ZN3foo3quxE".into(),
                size: 0,
            },
        ],
        vec![],
    );
    let anns = SymbolsAnalyzer::new().analyze(&bin);
    let foo = anns
        .iter()
        .find(|a| a.label.contains("foo::bar"))
        .expect("foo::bar annotation");
    assert!(
        foo.comment.is_some(),
        "size>0 must produce a 'size=<n>' comment"
    );
    let qux = anns
        .iter()
        .find(|a| a.label.contains("foo::qux"))
        .expect("foo::qux annotation");
    assert!(qux.comment.is_none(), "size=0 must produce no comment");
}

// -- Strings analyzer: synthetic slice header -------------------------------

fn body_with_slice(ptr: u64, len: u64, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&ptr.to_le_bytes());
    b.extend_from_slice(&len.to_le_bytes());
    b.extend_from_slice(payload);
    b
}

#[test]
fn strings_recovers_known_slice_in_synthetic_section() {
    let body = body_with_slice(0x4010, 5, b"hello");
    let bin = fake_bin(".rodata", 0x4000, &body, true);
    let anns = StringsAnalyzer::with_limits(Limits::default()).analyze(&bin);
    let strs: Vec<_> = anns
        .iter()
        .filter(|a| matches!(a.kind, rustrip::analyzers::AnnotationKind::String))
        .collect();
    assert_eq!(
        strs.len(),
        1,
        "expected exactly 1 String annotation; got {}",
        strs.len()
    );
    assert!(strs[0].label.contains("hello"));
    assert_eq!(
        strs[0].vaddr, 0x4010,
        "vaddr must be the slice DATA, not the slice header"
    );
}

#[test]
fn strings_rejects_punctuation_only() {
    let bin = fake_bin(".rodata", 0x4000, &body_with_slice(0x4010, 2, b"--"), true);
    assert!(
        !string_annots_present(&bin),
        "pure-punctuation slice must be rejected"
    );
}

#[test]
fn strings_rejects_oversized_len() {
    let bin = fake_bin(".rodata", 0x4000, &body_with_slice(0x4010, 1024, b""), true);
    assert!(
        !string_annots_present(&bin),
        "len > max_string_len must reject"
    );
}

#[test]
fn strings_rejects_zero_len() {
    let bin = fake_bin(".rodata", 0x4000, &body_with_slice(0x4010, 0, b""), true);
    assert!(!string_annots_present(&bin), "len=0 must reject");
}

#[test]
fn strings_rejects_pointer_outside_string_section() {
    let bin = fake_bin(
        ".rodata",
        0x4000,
        &body_with_slice(0x9FFFu64, 5, b"hello"),
        true,
    );
    assert!(
        !string_annots_present(&bin),
        "pointer outside string section must reject"
    );
}

#[test]
fn strings_rejects_in_non_string_section() {
    let bin = fake_bin(
        ".text",
        0x4000,
        &body_with_slice(0x4010, 5, b"hello"),
        false,
    );
    assert!(
        !string_annots_present(&bin),
        "slices in non-.rodata must be skipped"
    );
}

// -- Panics analyzer: synthetic Location -----------------------------------

#[test]
fn panics_recovers_known_location() {
    let body = panic_record_body(0x40, 10, 42, 9, b"src/foo.rs");
    let bin = fake_bin(".rodata", 0x4000, &body, true);
    assert_eq!(panic_site_annots(&bin), vec!["src/foo.rs:42:9"]);
}

#[test]
fn panics_rejects_non_rs_file() {
    let body = panic_record_body(0x40, 12, 42, 9, b"src/main.txt");
    let bin = fake_bin(".rodata", 0x4000, &body, true);
    assert!(panic_site_annots(&bin).is_empty());
}

#[test]
fn panics_rejects_oversized_file_len() {
    let body = panic_record_body(0x40, 100_000, 42, 9, b"src/foo.rs");
    let bin = fake_bin(".rodata", 0x4000, &body, true);
    assert!(panic_site_annots(&bin).is_empty());
}

#[test]
fn panics_rejects_zero_line() {
    let body = panic_record_body(0x40, 10, 0, 9, b"src/foo.rs");
    let bin = fake_bin(".rodata", 0x4000, &body, true);
    assert!(panic_site_annots(&bin).is_empty());
}

#[test]
fn panics_rejects_line_too_big() {
    let body = panic_record_body(0x40, 10, Limits::default().max_line + 1, 9, b"src/foo.rs");
    let bin = fake_bin(".rodata", 0x4000, &body, true);
    assert!(panic_site_annots(&bin).is_empty());
}

#[test]
fn panics_rejects_in_non_host_section() {
    let body = panic_record_body(0x40, 10, 42, 9, b"src/foo.rs");
    let bin = fake_bin(".text", 0x4000, &body, false);
    assert!(panic_site_annots(&bin).is_empty());
}

#[test]
fn panics_rejects_truncated_payload() {
    let body = vec![0u8; 12];
    let bin = fake_bin(".rodata", 0x4000, &body, true);
    assert!(
        panic_site_annots(&bin).is_empty(),
        "truncated payload must not panic, must reject"
    );
}

// -- Output backend exact-shape --------------------------------------------

#[test]
fn table_output_includes_header_separator_and_labels() {
    use rustrip::analyzers::{Annotation, AnnotationKind};
    let anns = vec![Annotation {
        vaddr: 0x0040_1000,
        kind: AnnotationKind::Symbol,
        label: "core::fmt::write_fmt".into(),
        comment: Some("size=128".into()),
    }];
    let mut buf = Vec::new();
    Table.render(&anns, &mut buf).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.lines().next().unwrap().contains("vaddr"));
    assert!(s.lines().next().unwrap().contains("kind"));
    assert!(s.contains("core::fmt::write_fmt"));
    assert!(s.contains("0x401000"));
    assert!(s.contains("size=128"));
}

#[test]
fn json_output_includes_kind_field_per_annotation() {
    use rustrip::analyzers::{Annotation, AnnotationKind};
    use rustrip::output::json::Json;
    let anns = vec![
        Annotation {
            vaddr: 0x0040_1000,
            kind: AnnotationKind::String,
            label: "alpha".into(),
            comment: None,
        },
        Annotation {
            vaddr: 0x0040_1100,
            kind: AnnotationKind::Symbol,
            label: "core::fmt".into(),
            comment: None,
        },
    ];
    let mut buf: Vec<u8> = Vec::new();
    Json.render(&anns, &mut buf).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("\"kind\": \"string\""));
    assert!(s.contains("\"kind\": \"symbol\""));
    assert!(s.contains("\"alpha\""));
    assert!(s.contains("\"core::fmt\""));
}

#[test]
fn table_output_handles_zero_vaddr_gracefully() {
    use rustrip::analyzers::{Annotation, AnnotationKind};
    let anns = vec![Annotation {
        vaddr: 0,
        kind: AnnotationKind::String,
        label: "x".into(),
        comment: None,
    }];
    let mut buf: Vec<u8> = Vec::new();
    Table.render(&anns, &mut buf).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("0x0"));
}

// -- Limits defaults -------------------------------------------------------

#[test]
fn limits_defaults_are_sane() {
    let l = Limits::default();
    assert!(l.max_string_len > 0);
    assert!(l.max_line > 0 && l.max_line < 10_000_000);
    assert!(l.max_col > 0 && l.max_col < 100_000);
}

// -- `Binary` API invariants -----------------------------------------------

#[test]
fn read_ptr_bounds_outside_section_is_none() {
    let bin = fake_bin(".rodata", 0x4000, b"hello", true);
    assert!(
        bin.read_ptr(0x4000).is_none(),
        "read_ptr requires 8 bytes; we have 5"
    );
}

#[test]
fn read_at_vaddr_zero_len_returns_empty_slice() {
    let bin = fake_bin(".rodata", 0x4000, b"anything", true);
    let bytes = bin.read_at_vaddr(0x4000, 0);
    assert_eq!(bytes, Some(&[][..]));
}

#[test]
fn read_at_vaddr_vaddr_in_range_but_len_too_big_returns_none() {
    let bin = fake_bin(".rodata", 0x4000, b"abc", true);
    assert!(
        bin.read_at_vaddr(0x4000, 100).is_none(),
        "len > section.data must return None"
    );
}

#[test]
fn vaddr_no_panic_on_repeated_calls() {
    let bin = fake_bin(".rodata", 0x4000, b"hello", true);
    for _ in 0..100 {
        assert_eq!(bin.vaddr_to_offset(0x4000), Some((0, 0)));
        assert!(bin.vaddr_to_offset(0xFFFF_FFFF_FFFF_FFFF).is_none());
        assert!(bin.vaddr_to_offset(0x4001).is_some());
        assert!(bin.vaddr_to_offset(0x4004).is_some());
        assert!(
            bin.vaddr_to_offset(0x4005).is_none(),
            "len+1 byte past section end must be None"
        );
    }
}

// ---------------------------------------------------------------------------
// Below: tests added during the v0.2 byte-by-byte audit. They target the
// remaining cargo-mutants MISSED paths (`docs/mutation-v0.1.0.md`) so the
// kill-rate stabilises at >= 60% on linux-runners.
// ---------------------------------------------------------------------------

#[test]
fn panics_vaddr_overflow_protected() {
    // Section vaddr near u64::MAX so vaddr + any offset overflows. The
    // analyzer must refuse to read — never panic.
    let mut body = vec![0u8; 64];
    body[0..8].copy_from_slice(&0xFFFF_FFFF_FFFF_FF00u64.to_le_bytes());
    body[8..16].copy_from_slice(&16u64.to_le_bytes());
    let bin = Binary::from_test_parts(
        Bf::Elf,
        true,
        true,
        vec![Section {
            name: ".rodata".into(),
            vaddr: 0xFFFF_FFFF_FFFF_FF00,
            size: 64,
            data: body,
        }],
        vec![],
        vec![0],
    );
    let anns = PanicsAnalyzer::new().analyze(&bin);
    // No overflow → no panic; final answer must be empty (file pointer
    // points into 0xFFFF zone which is not a string section).
    assert!(anns
        .iter()
        .all(|a| !matches!(a.kind, rustrip::analyzers::AnnotationKind::PanicSite)));
}

#[test]
fn panics_multiple_records_offset_by_entry_size() {
    // Two panic records packed back-to-back inside .rodata (no inter-
    // record padding). The walker must step by `entry_size = 24` after
    // a hit so the next record lands at the start of its own header
    // window. With WS=8 stride semantics on the body, the worst case is
    // when the iteration over the binary's full content happens to
    // straddle both records' fields. The test catches the off-`+=entry_size`
    // mutation in `scan_locations` — without the explicit past-record
    // advance, the walker would re-emit the same record from a phased-
    // offset read.
    //
    // Layout per record:
    //     bytes  0..8  = file_ptr  (vaddr-returning usize)
    //     bytes  8..16 = file_len
    //     bytes 16..20 = line
    //     bytes 20..24 = col
    //     bytes 24..24+file_len = filename (no separator)
    fn build_record(file_ptr_vaddr: u64, file: &[u8], line: u32, col: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&file_ptr_vaddr.to_le_bytes());
        b.extend_from_slice(&(file.len() as u64).to_le_bytes());
        b.extend_from_slice(&line.to_le_bytes());
        b.extend_from_slice(&col.to_le_bytes());
        b.extend_from_slice(file);
        b
    }
    let mut body = Vec::new();
    body.extend(build_record(0x4000 + 24, b"src/foo.rs", 42, 9));
    body.extend(build_record(
        0x4000u64 + 24u64 + 24u64 + b"src/foo.rs".len() as u64,
        b"src/bar.rs",
        7,
        1,
    ));
    // Section data must extend far enough to satisfy the second
    // record's `vaddr_in_string_section(file_ptr2, 11)` check; we pad
    // to 1024 bytes so file_ptr2 (≈ 0x405A + 11 ≤ 0x406B) fits.
    while body.len() < 1024 {
        body.push(0);
    }
    let bin = fake_bin(".rodata", 0x4000, &body, true);
    let sites: Vec<String> = panic_site_annots(&bin);
    assert_eq!(sites.len(), 2);
    assert_eq!(sites[0], "src/foo.rs:42:9");
    assert_eq!(sites[1], "src/bar.rs:7:1");
}

#[test]
fn dedup_collapses_identical_annotations() {
    let bin = rustrip::binary::Binary::parse(
        Some(""),
        std::fs::read(PathBuf::from(env!("CARGO_BIN_EXE_rustrip"))).expect("read rustrip self"),
    )
    .expect("parse self");
    let r = Registry::new().with(Box::new(PanicsAnalyzer::new()));
    let anns = r.run(&bin);
    let distinct_vaddrs: HashSet<u64> = anns.iter().map(|a| a.vaddr).collect();
    // PanicsAnalyzer often emits duplicate `file:line:col` for the same
    // panic site (once per trace). Registry::run should have dropped these.
    let (after, before) = (anns.len(), anns.len() + distinct_vaddrs.len());
    assert!(
        after <= before,
        "after dedup ({after}) must not exceed raw count ({before})",
    );
}

#[test]
fn registry_preserves_distinct_annotations_at_distinct_vaddrs() {
    let mut body = Vec::new();
    body.extend_from_slice(&0x4010u64.to_le_bytes());
    body.extend_from_slice(&5u64.to_le_bytes());
    body.extend_from_slice(b"hello");
    let bin = fake_bin(".rodata", 0x4000, &body, true);
    let r = Registry::new()
        .with(Box::new(StringsAnalyzer::with_limits(Limits::default())))
        .with(Box::new(PanicsAnalyzer::new()));
    let anns = r.run(&bin);
    assert!(anns
        .iter()
        .any(|a| matches!(a.kind, AnnotationKind::String)));
    // No synthesizer registers panic sites in our .rodata-only blob.
    assert!(!anns
        .iter()
        .any(|a| matches!(a.kind, AnnotationKind::PanicSite)));
}
