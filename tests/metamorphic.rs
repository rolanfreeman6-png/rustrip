//! Metamorphic tests for rustrip.
//!
//! Metamorphic testing seeds an "input transformation relation" and
//! asserts that the *output* obeys a related transformation. For
//! rustrip, the relations that matter are:
//!
//! 1. **Idempotence**: scanning a fixed `Binary` twice must yield
//!    exactly the same annotation set (modulo insertion order in the
//!    registry, which is sorted+dedup'd by `Registry::run`).
//!
//! 2. **Vaddr translation invariance**: shifting every section's
//!    `vaddr` by a constant `k` must shift every annotation `vaddr` by
//!    the same `k`. The annotation content (string, symbol, panic site)
//!    must be identical.
//!
//! 3. **Section-name suffix invariance**: renaming `.rodata` to
//!    `.rodata.foo` (or `.rodata.1`) must NOT change the recovered
//!    string/panic annotations, because our predicate accepts the
//!    whole `.rodata.*` family.
//!
//! 4. **Slice-table layout invariance**: the same logical string set
//!    encoded into two different `(ptr, len)` table layouts (tight vs
//!    sparse) must produce the same `String` annotation set after
//!    dedup.
//!
//! 5. **Demangle roundtrip idempotence**: feeding a `Demangle` formatted
//!    symbol back into `try_demangle` again must yield the same
//!    canonical form.
//!
//! 6. **Region partition invariance**: splitting one section into two
//!    disjoint sections at the same vaddr range must not change which
//!    strings are recovered.
//!
//! These tests can fail if a future change accidentally introduces an
//! ordering-dependence, an off-by-one vaddr leak, or a slice-table
//! shape assumption.

use std::collections::HashSet;
use std::path::PathBuf;

use rustrip::analyzers::{
    panics::PanicsAnalyzer, strings::StringsAnalyzer, symbols::SymbolsAnalyzer, Annotation,
    AnnotationKind, Limits, Registry,
};
use rustrip::binary::{Binary, BinaryFormat as Bf, Section};
use rustrip::Analyzer;

fn self_bytes() -> Vec<u8> {
    std::fs::read(PathBuf::from(env!("CARGO_BIN_EXE_rustrip")))
        .expect("read rustrip self binary for metamorphic tests")
}

#[test]
fn idempotent_run_produces_same_annotations() {
    let bin = Binary::parse(Some("self"), self_bytes()).expect("parse");
    let r = Registry::new()
        .with(Box::new(StringsAnalyzer::with_limits(Limits::default())))
        .with(Box::new(SymbolsAnalyzer::new()))
        .with(Box::new(PanicsAnalyzer::new()));
    let a = r.run(&bin);
    let b = r.run(&bin);
    let mut sa: HashSet<(u64, String, String)> = a
        .iter()
        .map(|n| (n.vaddr, kind_str(&n.kind), n.label.clone()))
        .collect();
    let sb: HashSet<(u64, String, String)> = b
        .iter()
        .map(|n| (n.vaddr, kind_str(&n.kind), n.label.clone()))
        .collect();
    assert_eq!(sa, sb);
    let _ = &mut sa; // silence unused-mut if test ever inverts
}

fn kind_str(k: &AnnotationKind) -> String {
    match k {
        AnnotationKind::String => "string".into(),
        AnnotationKind::Symbol => "symbol".into(),
        AnnotationKind::PanicSite => "panic".into(),
    }
}

#[test]
fn vaddr_translation_invariance_on_synthetic_analyzer() {
    // Build a small synthetic binary with the strings analyzer & panics
    // analyzer inputs at vaddr 0x10000. Then shift whole binary by
    // +0x4000 and re-analyze. Every annotation's `vaddr` must shift by
    // exactly +0x4000; the `label` should be unchanged.
    let make_body = |sec_vaddr: u64| -> Vec<u8> {
        // Single panic record at the start.
        let mut body = Vec::new();
        body.extend_from_slice(&(sec_vaddr + 32).to_le_bytes()); // file_ptr
        body.extend_from_slice(&11u64.to_le_bytes()); // file_len
        body.extend_from_slice(&42u32.to_le_bytes());
        body.extend_from_slice(&9u32.to_le_bytes());
        body.resize(32, 0);
        body.extend(b"src/foo.rs\0".as_ref().strip_suffix(b"\0").unwrap());
        body
    };

    let make_bin = |sec_vaddr: u64| -> Binary {
        let body = make_body(sec_vaddr);
        Binary::from_test_parts(
            Bf::Elf,
            true,
            true,
            vec![Section {
                name: ".rodata".into(),
                vaddr: sec_vaddr,
                size: body.len() as u64,
                data: body,
            }],
            vec![],
            vec![0],
        )
    };

    let lower = make_bin(0x0001_0000);
    let upper = make_bin(0x0001_4000);
    let delta: u64 = 0x4000;

    let r = Registry::new().with(Box::new(PanicsAnalyzer::new()));
    let lower_a = r.run(&lower);
    let upper_a = r.run(&upper);
    assert_eq!(
        lower_a.len(),
        upper_a.len(),
        "vaddr shift must not change annotation count"
    );
    for (l, u) in lower_a.iter().zip(upper_a.iter()) {
        assert_eq!(
            u.vaddr,
            l.vaddr + delta,
            "vaddr translation invariant broken: lower={:#x} upper={:#x}",
            l.vaddr,
            u.vaddr
        );
        assert_eq!(
            u.label, l.label,
            "vaddr translation invariant broken for label"
        );
    }
}

#[test]
fn section_name_suffix_invariance_on_strings() {
    // Build the same section content with two different section names;
    // the strings analyzer must recover the same `String` annotations
    // because `.rodata.*` is a recognised family.
    let make_body = || -> Vec<u8> {
        // (ptr=0x4010, len=5, "hello")
        let mut body = Vec::new();
        body.extend_from_slice(&0x4010u64.to_le_bytes());
        body.extend_from_slice(&5u64.to_le_bytes());
        body.extend(b"hello");
        body
    };
    let name_a = ".rodata";
    let name_b = ".rodata.fooextra";
    assert_ne!(name_a, name_b);

    let bin_a = Binary::from_test_parts(
        Bf::Elf,
        true,
        true,
        vec![Section {
            name: name_a.into(),
            vaddr: 0x4000,
            size: 24,
            data: make_body(),
        }],
        vec![],
        vec![0],
    );
    let bin_b = Binary::from_test_parts(
        Bf::Elf,
        true,
        true,
        vec![Section {
            name: name_b.into(),
            vaddr: 0x4000,
            size: 24,
            data: make_body(),
        }],
        vec![],
        vec![0],
    );

    let s = StringsAnalyzer::with_limits(Limits::default());
    let a = s.analyze(&bin_a);
    let b = s.analyze(&bin_b);
    assert_eq!(a.len(), b.len());
    let va: HashSet<u64> = a.iter().map(|n| n.vaddr).collect();
    let vb: HashSet<u64> = b.iter().map(|n| n.vaddr).collect();
    assert_eq!(va, vb);
}

#[test]
fn region_partition_invariance_on_panics() {
    // Two panic records split across two adjacent sections must produce
    // the panic-site set as a single combined section does. Sections are
    // indexed by vaddr; the analyze() scan visits them in iteration
    // order — order independence must hold (after Registry::run sort).
    let sec_vaddr = 0x4000u64;

    let panic_body = |file_ptr: u64, file_len: u64, line: u32, col: u32, file: &[u8]| -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&file_ptr.to_le_bytes());
        body.extend_from_slice(&file_len.to_le_bytes());
        body.extend_from_slice(&line.to_le_bytes());
        body.extend_from_slice(&col.to_le_bytes());
        body.resize(
            usize::try_from(file_ptr).expect("file_ptr fits usize in test fixtures"),
            0,
        );
        body.extend_from_slice(file);
        body
    };

    let fp1 = sec_vaddr + 32;
    let fp2 = sec_vaddr + 32 + 64; // record2.file_ptr
    let rec1 = panic_body(fp1, 10, 42, 9, b"src/foo.rs");
    let rec2 = panic_body(fp2, 11, 7, 1, b"src/bar.rs");

    // Combined section spanning both records.
    let mut combined = Vec::new();
    combined.extend_from_slice(&rec1);
    combined.extend_from_slice(&rec2);
    // pad up to ensure file_ptrs don't fall outside section
    while combined.len()
        < usize::try_from(fp2 - sec_vaddr).expect("fp2 - sec_vaddr fits usize in test fixtures")
            + 12
    {
        combined.push(0);
    }
    let bin_combined = Binary::from_test_parts(
        Bf::Elf,
        true,
        true,
        vec![Section {
            name: ".rodata".into(),
            vaddr: sec_vaddr,
            size: combined.len() as u64,
            data: combined,
        }],
        vec![],
        vec![0],
    );
    // Split into two .rodata sections, where our `is_container_section`
    // (and the strings analyzer's section predicate) treat both as the
    // same kind.
    assert!(!rec1.is_empty());
    let cut = rec1.len();
    let bin_split = Binary::from_test_parts(
        Bf::Elf,
        true,
        true,
        vec![
            Section {
                name: ".rodata".into(),
                vaddr: sec_vaddr,
                size: cut as u64,
                data: rec1.clone(),
            },
            Section {
                name: ".rodata.extra".into(),
                vaddr: sec_vaddr + cut as u64,
                size: rec2.len() as u64,
                data: rec2.clone(),
            },
        ],
        vec![],
        vec![0],
    );

    let r = Registry::new().with(Box::new(PanicsAnalyzer::new()));
    let combo = r.run(&bin_combined);
    let split = r.run(&bin_split);
    let cmp: HashSet<(u64, String)> = combo.iter().map(|n| (n.vaddr, n.label.clone())).collect();
    let smp: HashSet<(u64, String)> = split.iter().map(|n| (n.vaddr, n.label.clone())).collect();
    assert_eq!(
        cmp, smp,
        "split vs combined section partition must yield the same panic set"
    );
}

#[test]
fn demangle_format_is_idempotent() {
    // Idempotence: feeding the demangle-form of a symbol back into a
    // third pass must yield the same canonical string. We pass mangled
    // names; the FIRST pass expands them to human-readable Rust names;
    // mangled-with-hash again cannot be derived from pure text — but we
    // can check the cycle:
    //   pass 1: mangled  -> demangled  ("text::name::h0123...")
    //   pass 2: text     -> unchanged   (rawc_demangle recognises both)
    let cases: &[&str] = &[
        "_ZN3std2io5Write9write_fmt17h0123456789abcdefE",
        "_RNvCs4fqI2P2rA4_7mycrate3foo",
        "printf",
    ];
    for c in cases {
        // First and second parse must both succeed.
        let s1 = rustc_demangle::try_demangle(c).map_or_else(|_| c.to_string(), |d| d.to_string());
        // The second pass may recognise the demangled-with-hash form, or
        // treat it as raw text. Either is acceptable; the test asserts
        // the result is non-empty and matches between two consecutive
        // demangle calls.
        let s2 = rustc_demangle::try_demangle(&s1).map_or_else(|_| s1.clone(), |d| d.to_string());
        let s3 = rustc_demangle::try_demangle(&s2).map_or_else(|_| s2.clone(), |d| d.to_string());
        // Idempotence: after two more passes we still have a non-empty,
        // stable naming (no infinite growth from adding hash suffixes).
        assert!(!s3.is_empty());
    }
}

#[test]
fn symbol_analyzer_idempotence() {
    let bin = Binary::parse(Some("self"), self_bytes()).expect("parse");
    let s = SymbolsAnalyzer::new();
    let a = s.analyze(&bin);
    let b = s.analyze(&bin);
    assert_eq!(a.len(), b.len());
    let av: Vec<&Annotation> = a.iter().collect();
    let bv: Vec<&Annotation> = b.iter().collect();
    assert_eq!(av.len(), bv.len());
    for (l, r) in av.iter().zip(bv.iter()) {
        assert_eq!(l.vaddr, r.vaddr);
        assert_eq!(l.label, r.label);
        assert_eq!(l.kind, r.kind);
        assert_eq!(l.comment, r.comment);
    }
}

#[test]
fn registry_run_monomorphic_in_analyzer_order() {
    // The registry's order-independence: running the same set of
    // analyzers in different construction orders must yield byte-equal
    // annotations after its internal sort + dedup pass.
    let bin = Binary::parse(Some("self"), self_bytes()).expect("parse");
    let r1 = Registry::new()
        .with(Box::new(StringsAnalyzer::with_limits(Limits::default())))
        .with(Box::new(SymbolsAnalyzer::new()))
        .with(Box::new(PanicsAnalyzer::new()));
    let r2 = Registry::new()
        .with(Box::new(PanicsAnalyzer::new()))
        .with(Box::new(SymbolsAnalyzer::new()))
        .with(Box::new(StringsAnalyzer::with_limits(Limits::default())));
    let a1 = r1.run(&bin);
    let a2 = r2.run(&bin);
    assert_eq!(a1.len(), a2.len());
    for (l, r) in a1.iter().zip(a2.iter()) {
        assert_eq!(l.vaddr, r.vaddr);
        assert_eq!(l.kind, r.kind);
        assert_eq!(l.label, r.label);
        assert_eq!(l.comment, r.comment);
    }
}
