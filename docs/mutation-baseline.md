## cargo-mutants baseline (commit 3c6c1e2, cargo-mutants 27.1.0)

`cargo mutants --no-shuffle --timeout 60` against the full test
suite (21 unit + 10 integration; arm64 ELF and Mach-O codecs
not exercised because we build on Windows x86_64 PE only).

### Counts

| outcome     | count |
| ----------- | ----- |
| caught      |    80 |
| missed      |   174 |
| unviable    |    13 |
| timeout     |     6 |
| **total**   |  273  |

Kill rate = 80/259 (excluding unviable/timeout) = **30.9 %**.

### Where the misses concentrate

- **src/main.rs** — 11 misses. Causes:
  - `is_64 ==` to `!=` / `<`, `read_bytes` path-replacements,
    CLI flag handling. Tests exercise the binary via subprocess
    harness, but the mutations on `Cli` parse paths aren't covered
    directly because clap's parser is its own well-tested crate.
  - **Mostly noise** — clap arguments are paths the user-given
    mutation tested would normally flip (`!cli.no_strings`
    → `cli.no_strings`) but the integration suite never invokes the
    CLI with non-default values. **TODO**: see test plan below.

- **src/binary.rs** — 24 misses. Sources:
  - `load_elf` and `load_pe` clamping logic
    (`off <= cap && end <= cap`, `<= with >`) — the binary fixture
    used by integration tests is a pristine `cargo build` PE, so
    over-/under-flow clamping (off > cap, end > cap) is never
    exercised.
  - `arch_name_elf` / `arch_name_pe` default arms deleted
    (e_map values we never feed into the fixture).
  - `is_string_section_name` matching primitives.
  - **Action**: add a hand-crafted minimal ELF fixture in
    `tests/property_tests.rs` so every branch is reachable.

- **src/analyzers/panics.rs** — 47 misses. By far the largest surface
  with the lowest coverage. All `+= -` / `*` / `/` mutations on
  pointer arithmetic inside `scan_locations` survive because the
  integration self-test happens to walk panic records on a path where
  the offsets line up; a mutated loop that scanned ahead by 1 still
  hit the same records.
  - **Action**: introduce synthetic `Binary` unit tests that seed a
    section with multiple collision-prone offset values; the
    mutated off-by-one paths will then produce different annotation
    counts.

- **src/analyzers/strings.rs** — 20 misses. Same pattern as panics:
  loop-body mutations change behavior on edges the integration
  binary never exercises. **Same fix**.

- **src/analyzers/symbols.rs** — 3 misses. Targets the size gate in
  `analyze`. **Same fix**.

- **src/output/{mod,table,json,ghidra,binja}.rs** — ~25 misses.
  Output backends are only smoke-tested for `not_panic` and one
  specific representation; mutations to format strings / write order
  don't change observable output for the test fixture.
  - **Action**: add format-shape assertions (specific substrings,
  byte counts) to the integration tests so the ghidra/binja output
  shapes are exact-validated.

### Plan to lift kill rate

Add `tests/property_tests.rs`, with synthetic binaries that cover:

| predicate                              | tests added              |
| -------------------------------------- | ------------------------ |
| `Binary::vaddr_to_offset` saturating    | 4 (low/high boundary)    |
| `load_elf` / `load_pe` clamp branches  | 8 (off>cap, end>cap etc) |
| `Binary::read_ptr` 4/8 byte read       | 4 (LE/BE × small/large) |
| `arch_name_elf`/`arch_name_pe` defaults| 8 (one per machine)      |
| `is_string_section_name` matches       | 6 (each prefix)          |
| analyzer loop body mutations           | 8 synthetic binaries     |
| `Format::parse` arm deletions          | 4 (negative tests)       |
| output backend exact-shape strings     | 8 per backend            |
| `Limits` field-by-field default        | 3                        |
| `Registry::run` sort + dedup           | 4 (built-in dedup doubles)|

Targeted kill rate after this commit: >= 60% of 273, i.e. >= 165.

### Timeouts

`TIMEOUT  src/analyzers/panics.rs:NN: replace += with -= in scan_locations`
appeared 6 times. Each individual `scan_locations` mutation runs
each binary. The `+=` mutations, when they widen the produced
`off` value, push the loop into quadratic behavior on the established
`rustrip.exe` self-test fixture (where the section is ~hundreds of KB).
60-second timeout cut them. Real fix: bigger limits on the runner.
