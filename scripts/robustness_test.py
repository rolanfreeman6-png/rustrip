#!/usr/bin/env python3
"""
Rustrip CLI robustness tests (Python harness).

Cases:
  - stdin via '-': valid binary, junk
  - --help / --version / -h
  - missing file
  - --format garbage
  - no PATH arg
  - 0-byte / 1-byte input files
  - 100 MiB random (perf sanity)
  - 4 parallel processes reading the same file
  - stdout when -o omitted
  - all 8 format aliases
  - max-string-len edge cases (99999 / -1)
  - selective flags
  - all-three selective combined

Usage:
    python3 scripts/robustness_test.py [path-to-rustrip-binary]
"""
# nosec — all subprocess calls use static argv (no shell).

import concurrent.futures
import os
import subprocess  # nosec
import sys
import tempfile
import time
from pathlib import Path

exe = Path(sys.argv[1] if len(sys.argv) > 1 else "./target/release/rustrip")
results = []


def has_panic(out) -> bool:
    if out is None:
        return False
    if isinstance(out, bytes):
        return b"panicked at" in out
    return "panicked at" in out


def record(label: str, ok: bool) -> None:
    print(f"  [{'OK ' if ok else 'FAIL'}]  {label}")
    results.append((label, ok))


def run(label: str, args, *, input_data=None, expect_ok: bool) -> None:
    kw = dict(capture_output=True, text=True, timeout=60)
    if input_data is not None:
        kw["input"] = input_data
        kw.pop("text", None)  # bytes-style input
    cp = subprocess.run([str(exe), *args], **kw)  # nosec
    panic = has_panic(cp.stderr)
    ok = (cp.returncode == 0) == expect_ok and not panic
    record(label, ok)
    if not ok:
        so = (cp.stdout or b"").decode(errors="replace")[:300]
        se = (cp.stderr or b"").decode(errors="replace")[:300]
        print(f"     stdout: {so}")
        print(f"     stderr: {se}")


print("=== robustness ===")

# There is no public class for the formatter, but we use it as a
# type-checker hint; everything below is structural.

# 1. stdin via '-'
self_bytes = exe.read_bytes() if exe.exists() else b""
cp = subprocess.run(  # nosec
    [str(exe), "-", "-f", "json"],
    input=self_bytes, capture_output=True, timeout=30,
)
record("stdin valid binary", cp.returncode == 0
       and b'"vaddr"' in cp.stdout and not has_panic(cp.stderr))
vmark = b'"vaddr"'
print(f"    annotations via stdin: {cp.stdout.count(vmark)}")

cp = subprocess.run(  # nosec
    [str(exe), "-", "-f", "json"],
    input=b"junkjunkjunk", capture_output=True, timeout=20,
)
record("stdin junk", cp.returncode != 0 and not has_panic(cp.stderr))

# 2. --help / --version
cp = subprocess.run([str(exe), "--help"], capture_output=True, text=True, timeout=10)  # nosec
record("--help exit 0", cp.returncode == 0)
record("--help has tagline",
       "Make stripped Rust binaries readable again" in (cp.stdout + cp.stderr))
record("--help has usage info", "Usage:" in (cp.stdout + cp.stderr))

cp = subprocess.run([str(exe), "--version"], capture_output=True, text=True, timeout=10)  # nosec
record("--version", cp.returncode == 0 and "rustrip" in cp.stdout)

cp = subprocess.run([str(exe), "-h"], capture_output=True, text=True, timeout=10)  # nosec
record("-h short-help", cp.returncode == 0)

# 3. failure-case arity
run("missing file",
    [r"C:\nonexistent-does-not-exist.bin", "-f", "json"],
    expect_ok=False)
run("--format garbage", ["Cargo.toml", "-f", "garbage"], expect_ok=False)
run("no PATH arg", [], expect_ok=False)

# 4. tiny files using secure tempfile
for sz, desc in [(0, "0-byte"), (1, "1-byte")]:
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x00" * sz)
        path = f.name
    try:
        run(f"{desc} file", [path, "-f", "json"], expect_ok=False)
    finally:
        os.remove(path)

# 5. 100 MiB random (perf sanity)
with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
    f.write(os.urandom(100 * 1024 * 1024))
    big_path = f.name
try:
    start = time.monotonic()
    cp = subprocess.run([str(exe), big_path, "-f", "json"],
                        capture_output=True, text=True, timeout=60)  # nosec
    elapsed = time.monotonic() - start
    record(f"100 MiB random (elapsed={elapsed:.2f}s)",
           not has_panic(cp.stderr) and elapsed < 30)
finally:
    os.remove(big_path)

# 6. 4 parallel reads
def run_one(_i: int):
    return subprocess.run(  # nosec
        [str(exe), str(exe), "-f", "json"], capture_output=True, timeout=60)
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
    parallel = [f.result() for f in
                [ex.submit(run_one, i) for i in range(4)]]
record("4 parallel reads",
       all(r.returncode == 0 and not has_panic(r.stderr) for r in parallel))

# 7. stdout when -o omitted
run("stdout when -o omitted", [str(exe), "-f", "json"], expect_ok=True)
# workaround: actual stdout should start with '[' since JSON is array.
# Verify with sep:
cp = subprocess.run([str(exe), str(exe), "-f", "json"],
                    capture_output=True, text=True, timeout=30)  # nosec
results[-1] = ("stdout when -o omitted",
               cp.stdout.startswith("[") and not has_panic(cp.stderr))

# 8. format aliases
for fmt in ["json", "ghidra", "binja", "text", "cli",
            "py-ghidra", "binary-ninja", "bn"]:
    with tempfile.NamedTemporaryFile(suffix=".out", delete=False) as f:
        out_path = f.name
    try:
        run(f"fmt '{fmt}'", [str(exe), "-f", fmt, "-o", out_path], expect_ok=True)
    finally:
        os.remove(out_path)

# 9. max-string-len edges
run("max-string-len 99999",
    [str(exe), "-f", "table", "--max-string-len", "99999"], expect_ok=True)
run("max-string-len -1 (rejection)",
    [str(exe), "-f", "table", "--max-string-len", "-1"], expect_ok=False)

# 10. selective flags
for flag in ["--no-strings", "--no-symbols", "--no-panics"]:
    run(flag, [str(exe), "-f", "json", flag], expect_ok=True)
run("all 3 selective (empty output ok)",
    [str(exe), "-f", "json", "--no-strings", "--no-symbols", "--no-panics"],
    expect_ok=True)

print()
ok_count = sum(1 for _, ok in results if ok)
fail_count = len(results) - ok_count
print(f"=== {ok_count} / {len(results)} passed; {fail_count} failures ===")
for label, ok in results:
    if not ok:
        print(f"  FAIL: {label}")
sys.exit(0 if fail_count == 0 else 1)
