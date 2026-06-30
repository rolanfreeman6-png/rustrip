# Examples

Recipe-style demos of `rustrip` running against real binaries.

## 1. Pick a target

You need an ELF, PE, or Mach-O binary. For maximum drama, take a
release/stripped Rust binary (a malware sample if you have one — that's
exactly the use case rustrip targets). We're using `rustrip` itself for
this README so anyone can reproduce without an external artifact.

```sh
BIN=./target/release/rustrip
```

## 2. Default: CLI table

```sh
$ cargo build --release
$ rustrip "$BIN" 2>/dev/null | head -8
vaddr               kind    label
------------------  ------  -----------------------------------------
0x1400b87d0         panic   …/library\std\src\io\stdio.rs:854:20
0x1400b96f8         string  …/library\alloc\src\wtf8\mod.rs
0x1400b9746         string  …/library\alloc\src\raw_vec\mod.rs
0x1400b9798         panic   …/library\alloc\src\wtf8\mod.rs:481:57
…
```

The same data without rustrip is what a disassembler shows you: a
multi-KB blob of `.rdata` with no internal structure.

## 3. JSON output (machine-readable)

```sh
$ rustrip "$BIN" -f json -o report.json
$ python3 -c "import json,sys; d=json.load(open('report.json')); print(f'{len(d)} annotations')"
440 annotations
```

JSON schema:

```json
[
  {
    "vaddr": "0x1400b87d0",
    "kind": "panic",
    "label": "…/library\\std\\src\\io\\stdio.rs:854:20",
    "comment": null
  },
  …
]
```

## 4. Ghidra integration

```sh
$ rustrip "$BIN" -f ghidra -o apply_annotations.py
# Open Ghidra. Open the binary. Window > Script Manager > New > Python.
# Paste the contents of apply_annotations.py. Run it.
# Then: Search > For Label. You'll see `rustrip_panic_…` and demangled
# symbols mapped to addresses. Comments for strings appear as EOL
# comments where the disassembly shows the string data.
```

## 5. Binary Ninja integration

```sh
$ rustrip "$BIN" -f binja -o apply_annotations.py
# Open Binary Ninja. Open the binary. Open the Python console (bottom).
# Paste the contents of apply_annotations.py. Run it.
# _bv = current_binary_view  # uncomment if not auto-detected.
# Labels and comments appear in the linear view.
```

## 6. Selective analysis

```sh
# Skip symbol demangling; only get strings + panics.
$ rustrip "$BIN" --no-symbols | head -20

# Skip panics; only get strings + symbols.
$ rustrip "$BIN" --no-panics | head -20

# Increase recovered string limit (default 4096).
$ rustrip "$BIN" --max-string-len 65536 | head -40
```

## 7. Adversarial

```sh
$ scripts/adversarial_test.sh ./target/release/rustrip
Running adversarial input regression against: ./target/release/rustrip
  PASS  0 bytes
  PASS  1 byte
  …
  PASS  self (real rustrip binary)
…
OK — N cases passed, no panics observed
```

This script ships as part of the repo and is wired into the CI matrix
(`.gitlab-ci.yml:test:property:adversarial`).

## Repository contents

```
.
├── .github/workflows/ci.yml   # GitHub Actions CI
├── .gitlab-ci.yml             # GitLab CI (29 jobs across 7 stages)
├── Cargo.toml
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE-MIT
├── LICENSE-APACHE
├── examples/
├── scripts/
│   ├── adversarial_test.sh
│   ├── build-fixtures.sh
│   └── build-fixtures.ps1
├── src/                       # the library + CLI (see README.md)
└── tests/
    ├── integration.rs
    └── fixtures/
```
