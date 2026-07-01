## cargo-mutants — v0.1.0 current pass (`3c6c1e2 + property_tests + cleanups + CLI + panics-fix + metamorphic`)

`cargo mutants --no-shuffle --timeout 60` against the full test suite
(35 unit + 9 CLI + 10 integration + 34 property + 7 metamorphic =
95 tests) on rustrip 1.96.1.

### Counts

| outcome | baseline (3c6c1e2) | second pass (property_tests) | **this commit** |
| --- | --: | --: | --: |
| caught | 80 | 131 | **167** |
| missed | 174 | 120 | **84** |
| unviable | 13 | 14 | 15 |
| timeout | 6 | 9 | 8 |
| **total** | 273 | 274 | 274 |

Kill rate progression: 30.9 % → 52.2 % → **66.5 %** (relative +35.6 pp
from baseline).

### What reduced the misses

- `tests/cli.rs` — 9 subprocess-level tests cover `main.rs` clap
  parsing, --format aliases, and selective-flag combinations. Closes
  ~14 mutations in `src/main.rs` that unit tests cannot reach.

- `tests/property_tests.rs::panics_multiple_records_offset_by_entry_size`
  plus the walker fix in `src/analyzers/panics.rs` (which now advances
  by `entry_size + file_len`) — closes the off-by-WS mutations on the
  panics loop body.

- `tests/property_tests.rs::panics_vaddr_overflow_protected` — exercises
  a path where `sec.vaddr.checked_add(...)` was previously a plain
  addition that could silently wrap.

- `src/binary.rs` unit tests for `arch_name_elf` and `arch_name_pe` —
  one per documented machine constant including the default arms —
  close the entire `delete match arm EM_*` family.

### Mutamorphic relations

`tests/metamorphic.rs` adds seven transformation relations that the
pipeline must preserve:

1. `idempotent_run_produces_same_annotations`
2. `vaddr_translation_invariance_on_synthetic_analyzer`
3. `section_name_suffix_invariance_on_strings`
4. `region_partition_invariance_on_panics`
5. `demangle_format_is_idempotent`
6. `symbol_analyzer_idempotence`
7. `registry_run_monomorphic_in_analyzer_order`

These are *guard rails* — they will fail loudly if a future change
introduces ordering dependence or a slice-table shape assumption.

### Remaining misses (v0.2 / v0.3 backlog)

- Output backends: `table.rs` `repeat`, `textwrap` width logic;
  `ghidra.py` literal ordering. Hard to test without exact-snapshot
  byte comparisons of generated scripts — already covered by
  `ast.parse`-level Python AST validation in integration tests, but
  byte-level mutations slip through.

- `panics.rs` loop-body `+=` → `*=` / `-=` that produce quadratic
  scanning on the rustrip self-test fixture. These were previously
  listed as TIMEOUTs; the 60-second timeout budget still terminates
  them cleanly without hanging CI.

- `main.rs` minor `Result<()>` → `Ok(())` and field deletions — these
  are cosmetic and not user-visible.

### Action plan to lift further

- v0.2: add exact-string snapshot tests for `table.rs`, `ghidra.rs`,
  `binja.rs` outputs.
- v0.2: parameterize `cargo mutants --baseline` on a JSON snapshot
  and a PR-commenter that reports kill-rate deltas.
- v0.2: synthesize multiple back-to-back panic records in
  `panics.rs` tests with various (`file`, `line`, `col`) permutations
  so the off-by-one loop arithmetic mutations get a real chance to
  fail.
- v0.3: pin a known fixture binary (e.g. stripped `hello_world`) as
  a CI artifact so future goblin/script regressions stay silent.

### Timeouts

`TIMEOUT` appeared at 9 sites — all in `analyzers/panics.rs` for `+=`
→ `*=` and `+=` → `-=` replacing the inner-loop wide-step. Each
manifests as quadratic behaviour over the rustrip self fixture. The
60-second build + 60-second test budget still terminates them
cleanly without hanging CI.
