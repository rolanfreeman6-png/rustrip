# rustrip

[![CI](https://github.com/rustrip/rustrip/actions/workflows/ci.yml/badge.svg)](https://github.com/rustrip/rustrip/actions/workflows/ci.yml)
[![Pipeline](https://gitlab.com/rustrip/rustrip/badges/main/pipeline.svg)](https://gitlab.com/rustrip/rustrip/-/pipelines)
[![crates.io](https://img.shields.io/crates/v/rustrip.svg)](https://crates.io/crates/rustrip)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Make stripped Rust binaries readable again.**

`rustrip` recovers three classes of artifacts that disassembly tools miss
on stripped, release-mode Rust binaries:

1. **String boundaries** — `&str` fat pointers `(ptr, len)` are reconstructed
   into individual labeled strings instead of a single stretching blob.
2. **Demangled symbol names** — both legacy `_ZN…E` and v0 `_R…` mangling,
   including generic-parameter context, are rendered in `core::fmt::write`
   form rather than `<core::fmt::Write as core::fmt::Write>::write_fmt`.
3. **Panic site source paths** — every `core::panic::Location` is recovered
   as `path/to/source.rs:line:col`, letting you map a binary back to its
   source tree.

Output goes to a CLI table, JSON, or a Ghidra / Binary Ninja Python script
that re-applies the annotations to whichever view you open it in.

```
$ rustrip target/release/my_app.exe
vaddr              kind     label
------------------  ------   -------------------------------------------------------
0x7ff60a402200      string   "GET /api/v1/login HTTP/1.1\r\nHost: example.com\r\n\r\n"
0x7ff60a402382      string   "https://example.com/api/v1/login"
0x7ff60a402432      panic    src/main.rs:42:9
0x7ff60a410500      symbol   <my_app::net::connect as core::future::future::Future>::poll
…
```

## CI matrix

|           | Linux | Windows | macOS |
| --------- | :---: | :-----: | :---: |
| fmt       | ✓     | ✓       | ✓     |
| clippy    | ✓     | ✓       | ✓     |
| build     | ✓×3¹  | ✓×2²    | ✓×2³  |
| test      | ✓     | ✓       | ✓     |
| coverage  | ✓     | —       | —     |
| adversarial | ✓   | manual  | manual |
| audit     | weekly | — | — |

¹ gnu, musl, aarch64-gnu. ² msvc, gnu. ³ x86_64, aarch64.

GitLab pipeline has 29 jobs across 7 stages; GitHub Actions has the
equivalent readiness matrix. CI matrix is duplicated intentionally so
that the canonical readiness gate is GitHub, where the orange bar is
visible to anyone scanning the repo, and the heavier Linux/Windows/macOS
matrix runs on GitLab where shared runner resources are abundant.

## Install

```sh
cargo install rustrip
```

## Use

```sh
# Default CLI table
rustrip path/to/binary

# Export to Ghidra or Binary Ninja
rustrip target/release/foo.exe -f ghidra -o foo_ghidra.py
rustrip target/release/foo.exe -f binja  -o foo_binja.py

# Machine-readable
rustrip foo.exe -f json -o foo.json
```

Open the script in Ghidra (`Window > Script Manager > New > Python > paste`),
or in Binary Ninja's Python console, and run it on the open view.

## How it works

```
goblin (ELF / PE / Mach-O)  →  Binary  →  [Analyzer, Analyzer, …]  →  Vec<Annotation>  →  Output backend
```

- **`binary.rs`** — goblin-backed model with `vaddr ↔ file-offset`
  translation and size-aware readers (`read_ptr`, `read_at_vaddr`).
- **`analyzers/`** — independent passes. Each walks the binary and emits
  typed annotations.
- **`output/`** — backends receive only the merged annotation list and
  render it. CLI table, JSON, Ghidra Python, Binary Ninja Python.

The architecture is intentionally narrow: only data analysis, no full
disassembly in v0.1. That keeps the tool fast (sub-second on multi-MB
binaries) and reliable on stripped output where disassembly is messy.

## Roadmap

- v0.1 (now): string-slice recovery, symbol demangling, panic-site
  recovery. ELF, PE, Mach-O. CLI + table / JSON / Ghidra / Binary Ninja.
- v0.2: instruction-aware slice recovery via `iced-x86`
  (catches slices that aren't stored as static `(ptr, len)` pairs).
- v0.3: enum discriminant and monomorphized generic-type recovery.
- v1.0: native Ghidra and Binary Ninja plugins; type propagation.

## Reliability & threat model

rustrip is intended for reverse-engineering and malware triage. It must
not panic on adversarial input. The bundled `tests/integration.rs`
includes garbage- and truncated-input coverage; the analyzer pipeline
returns an empty or parser-error result rather than crashing.

## License

MIT OR Apache-2.0.
