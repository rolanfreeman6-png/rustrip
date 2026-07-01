#!/usr/bin/env python3
"""
Adversarial-input regression test for rustrip.

The rustrip binary is fed random/edge-case bytes and must NEVER panic.
A panic here would mean hostile binaries (e.g., malware samples given by a
RE researcher) crash our tool — which is unacceptable.

List of cases:

  - empty / 1-4 byte inputs
  - truncated ELF / PE magic
  - 0xff / 0x00 padding-corpus at various sizes
  - assorted binary signatures that look like other formats (JPEG,
    gzip, AR archive) to ensure goblin rejects them cleanly
  - a JPEG-LIKE file with garbage body
  - 200 random bytes streams of various sizes

Usage:
    python3 scripts/adversarial_test.py [path-to-rustrip-binary]

Exit code: 0 on success, 1 if any panic was observed.
"""
# nosec — subprocess.run is called only with a static argv list and
# shell=False (default). No shell interpolation of user input occurs.

import os
import subprocess  # nosec
import sys
import tempfile
from pathlib import Path

exe_arg = sys.argv[1] if len(sys.argv) > 1 else "./target/release/rustrip"
exe = Path(exe_arg)
tmp = Path(tempfile.mkdtemp(prefix="rustrip-adv-"))
print(f"tmp: {tmp}\n", file=sys.stderr)

failures = 0
total = 0


def run_case(desc: str, outcome: str, data: bytes) -> None:
    """Run one adversarial case and update global counters."""
    global failures, total
    p = tmp / "input.bin"
    p.write_bytes(data)
    total += 1
    try:
        cp = subprocess.run(  # nosec
            [str(exe), str(p), "-f", "json"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        ok = (cp.returncode == 0) if outcome == "ok" else (cp.returncode != 0)
        panic = "panicked at" in (cp.stderr or "")
        if panic:
            print(f"  FAIL PANIC  {desc}")
            print(f"    stderr: {(cp.stderr or '')[:500]}", file=sys.stderr)
            failures += 1
            return
        if not ok:
            status = "FAIL" if outcome == "ok" else "PASS"
        else:
            status = "PASS"
        print(f"  {status:<12}  {desc:<30}  size={len(data):<8} rc={cp.returncode}")
        if not ok:
            failures += 1
    except subprocess.TimeoutExpired:
        print(f"  FAIL TIMEOUT  {desc}")
        failures += 1


# Empty / single-byte / header-only
run_case("0 bytes",               "error", b"")
run_case("1 byte",                "error", b"\x7f")
run_case("2 bytes",               "error", b"AB")
run_case("3 bytes",               "error", b"ABC")
run_case("4 bytes ELF?",          "error", b"\x7fELF")
run_case("4 bytes PE?",           "error", b"MZ\x90\x00")
run_case("7 bytes ELF extend",    "error", b"\x7fELF\xff\xff")
run_case("8 bytes PE extend",     "error", b"MZ\x90\x00\xff\xff")
run_case("0xff x 16",             "error", b"\xff" * 16)
run_case("0xff x 4096",           "error", b"\xff" * 4096)
run_case("0xff x 4096 zeros",     "error", b"\x00" * 4096)
run_case("ASCII like Rust",       "either",
        b"fn main() { println!(\"hi\"); }\n")
run_case("ELF valid micro",       "either", b"\x7fELF")
run_case("Random 1KB",            "either", os.urandom(1024))
run_case("Random 64KB",           "either", os.urandom(65536))
run_case("Random 1MB",            "either", os.urandom(1024 * 1024))
run_case("JPEG-like SOI + garbage", "either",
        b"\xff\xd8\xff\xe0" + b"\x00" * 4096)
run_case("AR archive",            "error", b"!<arch>\x0a" + b"x" * 4096)
run_case("gzip-ish",              "either",
        b"\x1f\x8b\x08\x00" + b"\x00" * 8192)


# 200 random bytes inputs; we don't classify outcome — we only forbid panic.
print("\nstress: 200 random inputs (any panic = failure)...\n", file=sys.stderr)
for i in range(200):
    sz = (i * 17 + 1) % 8192
    p = tmp / f"stress{i}.bin"
    p.write_bytes(os.urandom(sz))
    total += 1
    cp = subprocess.run(  # nosec
        [str(exe), str(p), "-f", "json"],
        capture_output=True, text=True, timeout=15,
    )
    if "panicked at" in (cp.stderr or ""):
        print(f"  FAIL PANIC stress{i} (size={sz})")
        print(f"    stderr: {(cp.stderr or '')[:500]}", file=sys.stderr)
        failures += 1
        break

# Cleanup.
import shutil
shutil.rmtree(tmp, ignore_errors=True)

print()
print(f"=== {total} cases; {failures} failures ===")
sys.exit(0 if failures == 0 else 1)
