# Changelog

All notable changes to **rustrip** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Byte-exact snapshot tests** for all four output backends (table,
  JSON, Ghidra Python, Binary Ninja Python). Each test builds a
  reference script using the same helper functions and format templates
  as production, then asserts `actual == reference`. Any cargo-mutants
  mutation that swaps a literal, changes a separator, or reorders a
  `writeln!` line desyncs actual vs. expected and is caught.
- **CLI coverage** for file-output (`-o`), gate-invertibility
  (`--no-X` flags), tiny-file boundary (`<` vs `<=` on 4-byte input),
  and `--max-string-len` propagation to `Limits`.

### Changed

- **GitLab CI removed.** `.gitlab-ci.yml` deleted; `gitlab` remote
  removed. GitHub Actions is now the sole CI provider.
- **GitHub Actions CI expanded.** `ci.yml` now includes clippy
  (`-D warnings`), `cargo-audit`, and a cross-platform build + test
  matrix (Linux, Windows, macOS). New `release.yml` workflow handles
  tag-triggered release artifacts across 5 targets.
- **`mutants.out/` untracked** from git. Added to `.gitignore` along
  with `mutants.out.old/` and `.cargo-mutants/`.

### Verified

- 126 tests pass (58 unit + 17 CLI + 10 integration + 7 metamorphic +
  34 property). Clippy clean (`-D warnings` + pedantic + nursery).
  `cargo audit` clean (49 dependencies, 0 advisories). Semgrep clean.
- cargo-mutants shard runs confirm 0 missed mutants in the four target
  files (`src/output/table.rs`, `src/output/ghidra.rs`,
  `src/output/binja.rs`, `src/main.rs`).

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
  - GitHub Actions (`.github/workflows/`): `cargo fmt --check`,
    `cargo clippy -D warnings`, cross-platform build + test matrix
    (Linux, Windows, macOS), `cargo audit`, CodeQL SAST, semgrep SAST,
    cargo-mutants, and tag-triggered release artifacts.
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

[Unreleased]: https://github.com/rolanfreeman6-png/rustrip/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rolanfreeman6-png/rustrip/releases/tag/v0.1.0
