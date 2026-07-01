## cargo-mutants — v0.1.0 second pass (commit `3c6c1e2 + property_tests + cleanups`)

`cargo mutants --no-shuffle --timeout 60` against the full test suite
(21 unit + 10 integration + 30 property_test = 61 tests) and rustrip 1.96.

### Counts

| outcome     | baseline | v0.1.0 second pass |
| ----------- | -------- | ------------------ |
| caught      |    80    |    **131**         |
| missed      |   174    |    **120**         |
| unviable    |    13    |    14              |
| timeout     |     6    |  9                 |
| **total**   |  273     | 274                |

Kill rate = 131 / (131 + 120) = **52.2 %** (up from 30.9 % in the baseline).
Relative improvement on kill rate: +69 %.

The miss count dropped from 174 to **120** — a 31 % reduction — without
losing any existing catch. Coverage catches we gained:

- `is_panic_container` predicate branches (`*.rodata` / `*.rdata` /
  namespaced variants) — covered by `property_tests::is_string_section_name_prefixes_matched`
- `File::parse` rejection paths (empty bytes, truncated ELF magic,
  PE zero, garbage) — `rejects_empty_bytes / rejects_truncated_elf_magic /
  pe_zero_size_image_errors_cleanly / unreadable_format_is_parsed_quietly`
- `StringsAnalyzer` scan paths with synthetic `(ptr, len)` blobs —
  `strings_recovers_known_slice_in_synthetic_section / rejects_punctuation_only /
  rejects_oversized_len / rejects_zero_len
  / rejects_pointer_outside_string_section /
  rejects_in_non_string_section`
- `PanicsAnalyzer` scan paths with synthetic
  `core::panic::Location` records —
  `panics_recovers_known_location / rejects_non_rs_file /
  rejects_oversized_file_len / rejects_zero_line /
  rejects_line_too_big / rejects_in_non_host_section /
  rejects_truncated_payload`
- `SymbolsAnalyzer` size-gate —
  `symbols_commented_when_size_positive`
- `Format::parse` table-arms — `format_parse_handles_every_alias + rejects_unknown`
- `Binary::*` API invariants — `read_ptr_bounds_outside_section_is_none /
  read_at_vaddr_zero_len_returns_empty_slice /
  read_at_vaddr_vaddr_in_range_but_len_too_big_returns_none /
  vaddr_no_panic_on_repeated_calls`
- Output backend exact-shape strings —
  `table_output_includes_header_separator_and_labels /
  json_output_includes_kind_field_per_annotation /
  table_output_handles_zero_vaddr_gracefully`

### Why some mutants still MISS

1. **`src/main.rs`** – 11 misses remain. Clap's parser is its own
   well-tested crate and our CLI flag handling isn't exercised
   through tests (only through manual smoke). Adding CLI integration
   tests is a known TODO; we did not block the commit on it.

2. **`src/analyzers/panics.rs`** – ~30 misses still hit the loop body
   mutations like `+=` → `-=` or `+` → `*`. Even our pinned synthetic
   tests rely on the *first* record being valid. Off-by-one steps
   that skip the first record but produce a different one should still
   be caught but seem to be caught. Test plan v0.2: synthesize multiple
   panic records offset by 8 bytes from each other so non-first
   reads are also probed.

3. **`src/output/*.rs`** – output backend ~25 misses still on string
   literals. We pin bytes-via-output for table/json/stdout exact
   representations in property tests but format-spelled output to Ghidra
   and Binja is only matched at the lower-level "syntactic correctness
   of generated Python" level (we parse the generated script with
   `ast.parse` in the integration harness). Mutations like re-ordering
   the literal "strings" vs "ascii" etc. would be visible only with
   string-level exact-match assertions.

4. **`goblin parser internals`** – not mutated by cargo-mutants because
   goblin is an external crate, but we *do* depend on its correctness
   for raw object file parsing. The integration test on rustrip.exe
   catches goblin regressions at the binary level.

### Action plan to lift further

- v0.2: add CLI integration test that invokes rustrip with
  every `--format` / `--no-*` combination and asserts on
  `subprocess.run([exe, …])` exit codes + stdout shape.
- v0.2: synthesize multiple back-to-back panic records in
  scan_locations to catch the off-by-one loop mutations.
- v0.2: property-test all 4 output backends' exact string output
  (current property tests have table+json+stdout; ghidra/binja could
  have static snapshots).
- v0.3: pin a known fixture binary (e.g. stripped `hello_world`) as
  a CI artifact so future goblin/script regressions stay silent.

### Timeouts

`TIMEOUT` appeared at 9 sites — all in `analyzers/panics.rs` for `+=`
→ `*=` and `+=` → `-=` replacing the inner-loop wide-step. Each
manifests as quadratic behaviour over the rustrip self fixture. The
20-second build + 60-second test budget still holds; on the GitLab
shared runner 60 s test should comfortably finish.
