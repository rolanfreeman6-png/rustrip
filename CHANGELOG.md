# Changelog

All notable changes to **rustrip** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- `iced-x86`-based instruction-aware slice recovery (v0.2).
- Monomorphized generic / enum discriminant analyzer (v0.3).
- Native Ghidra and Binary Ninja plugin SDKs (v1.0).

## [0.1.0] — 2026-06-30

Initial release.

### Added

- **Binary model.** `Binary` (goblin 0.8) with ELF / PE / Mach-O parsing,
  vaddr ↔ file-offset translation, `read_at_vaddr`, `read_ptr`, `read_u32`,
  and `vaddr_in_string_section`. Handles truncated / NOBITS sections
  safely (returns `None` rather than panicking).
- **Analyzer trait + Registry.** Pluggable pipeline. New analyzers and
  new output backends can be added without touching the others.
- **`StringsAnalyzer`** — recovers `&str` slice boundaries from PE
  `.rdata*` / ELF `.rodata*` and `.data.rel.ro*` / Mach-O `__cstring`
  and `__const` by walking `(ptr, len)` pairs and validating UTF-8,
  length bounds, and alphanumerics.
- **`SymbolsAnalyzer`** — Rust symbol demangling via `rustc-demangle`,
  covers legacy `_ZN…E` and v0 `_R…` schemes.
- **`PanicsAnalyzer`** — detects `core::panic::Location` records in
  RO sections and emits `file:line:col` annotations.
- **Output backends.**
  - CLI table (default) — works in any terminal, easy to grep.
  - JSON — machine-readable, `serde_json` pretty-printed.
  - Ghidra Python script — `setEOLComment` for strings, `createLabel`
    for symbols and panic sites.
  - Binary Ninja Python script — `define_user_symbol` for labels,
    `set_comment_at` for comments.
- **CI/CD.**
  - GitLab (`.gitlab-ci.yml`, 29 jobs across 7 stages): lint, security
    (cargo-audit, cargo-deny), build matrix (linux × gnu/musl/aarch64,
    windows × msvc/gnu, macos × x86_64/aarch64), test matrix incl.
    end-to-end on a stripped fixture, coverage (cargo-llvm-cov),
    fuzz-smoke (cargo-fuzz + nightly), and release artifacts on tag.
  - GitHub Actions (`.github/workflows/ci.yml`): `cargo fmt --check`,
    `cargo build`, `cargo test`, `cargo clippy -D warnings`,
    `cargo publish --dry-run` on main.
- **Tests.** 31 tests pass — 21 unit, 10 integration. Adversarial
  regression script (`scripts/adversarial_test.sh`) feeds empty,
  random, and garbage inputs through rustrip and asserts no panic.
- **Scripts.**
  - `scripts/build-fixtures.sh` / `scripts/build-fixtures.ps1` —
    produce a stripped Rust fixture binary for richer downstream tests.
  - `scripts/adversarial_test.sh` — fuzz-style resilience check.

### Verified

- `cargo build --release` succeeds on `x86_64-pc-windows-msvc`.
- 440 annotations recovered from rustrip's own release artifact;
  recovered panic sites map to known stdlib and crate source paths.
- Generated Ghidra and Binary Ninja Python scripts validate with
  `python -c 'ast.parse(…)'`.
- Generated JSON validates with `json.load()`.
- 31/31 unit + integration tests pass on stable.

[Unreleased]: https://github.com/rustrip/rustrip/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rustrip/rustrip/releases/tag/v0.1.0
