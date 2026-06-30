#!/usr/bin/env bash
# Adversarial-input regression test for rustrip.
#
# Purpose: ensure `rustrip` never panics on binary-corpus-style garbage.
# Rustrip will be fed onto malware samples in practice, and a panic is a
# worse failure mode than "empty analysis". This script exercises the
# parser with the bytes that historically trip up goblin and our
# vaddr-translation code (random data, near-empty files, ELF/PE-looking
# but corrupt, strings of 0xFF, etc.).
#
# Usage: ./scripts/adversarial_test.sh <path-to-rustrip-binary>

set -uo pipefail

RUSTRIP="${1:-./target/release/rustrip}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0
total=0

# Each case: stdin description + bytes-to-write-to-tmp + expected outcome.
# outcome ∈ {ok, error}.
run_case() {
    local desc="$1"
    local outcome="$2"
    local bytes="$3"
    local file="$WORK/in.bin"
    printf "%s" "$bytes" > "$file"
    total=$((total + 1))
    if [[ "$outcome" == "ok" ]]; then
        if "$RUSTRIP" "$file" -f table > "$WORK/out.txt" 2>&1; then
            printf "  PASS  %s\n" "$desc"
        else
            printf "  FAIL  %s (expected ok, errored)\n" "$desc"
            failures=$((failures + 1))
        fi
    else
        if "$RUSTRIP" "$file" -f table > "$WORK/out.txt" 2>&1; then
            printf "  FAIL  %s (expected error, succeeded)\n" "$desc"
            failures=$((failures + 1))
        else
            printf "  PASS  %s\n" "$desc"
        fi
    fi
}

echo "Running adversarial input regression against: $RUSTRIP"
echo

# ------------------------------------------------------------------------- #
# Empty / single-byte input — must error.
# ------------------------------------------------------------------------- #
run_case "0 bytes"               error ""
run_case "1 byte"                error $'\x7f'
run_case "2 bytes"               error "AB"
run_case "3 bytes"               error "ABC"
run_case "4 bytes elf? truncated" error $'\x7fELF'
run_case "4 bytes pe? truncated"  error "MZ\x90\x00"

# ------------------------------------------------------------------------- #
# Magic bytes but corrupt — goblin must return Err, not crash.
# ------------------------------------------------------------------------- #
run_case "elf magic then ff"     error $'\x7fELF\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
run_case "pe magic then ff"      error 'MZ\x90\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
run_case "mach magic then ff"    error $'\xcf\xfa\xed\xfe\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'

# ------------------------------------------------------------------------- #
# Random bytes — most should error out at goblin parse time.
# ------------------------------------------------------------------------- #
for i in 1 2 3 4 5; do
    bytes="$(head -c 1024 /dev/urandom | base64 | head -c 512)"
    # 50/50 — random bytes might plausibly parse as some valid object by
    # sheer luck; either outcome is acceptable as long as rustrip doesn't
    # panic. We re-route both to "ok-or-error acceptable" branch below.
    if "$RUSTRIP" <(printf "%s" "$bytes") -f table > "$WORK/out.txt" 2>&1; then
        printf "  PASS  random-bytes case %d (succeeded)\n" "$i"
    else
        printf "  PASS  random-bytes case %d (errored)\n" "$i"
    fi
    # Either is okay — what matters is no panic. Verify non-panic explicitly.
    if grep -q "panicked at" "$WORK/out.txt" 2>/dev/null; then
        printf "  FAIL  random-bytes case %d PANICKED\n" "$i"
        failures=$((failures + 1))
    fi
    total=$((total + 1))
done

# ------------------------------------------------------------------------- #
# Variously sized all-0xFF input. Use printf for portability (POSIX `tr`
# handles \0 inconsistently across implementations).
# ------------------------------------------------------------------------- #
for sz in 16 64 256 1024 4096; do
    run_case "all 0xff size=$sz"    error "$(python3 -c "import sys; sys.stdout.buffer.write(b'\xff' * $sz)")"
done

# ------------------------------------------------------------------------- #
# A real rustrip binary — should succeed.
# ------------------------------------------------------------------------- #
if [[ -f target/release/rustrip.exe || -f target/release/rustrip ]]; then
    SELF="${SELF:-}"
    if [[ -f target/release/rustrip ]]; then SELF=target/release/rustrip; fi
    if [[ -f target/release/rustrip.exe ]]; then SELF=target/release/rustrip.exe; fi
    run_case "self (real rustrip binary)" ok ""
    cp "$SELF" "$WORK/self.bin"
    if "$RUSTRIP" "$WORK/self.bin" -f table > "$WORK/out.txt" 2>&1; then
        printf "  PASS  self (real binary)\n"
    else
        printf "  FAIL  self (real binary) errored: %s\n" "$(head -1 "$WORK/out.txt")"
        failures=$((failures + 1))
    fi
    total=$((total + 1))
fi

# ------------------------------------------------------------------------- #
# Stress: 2000 mixed-size random inputs, fail if any PANIC.
# ------------------------------------------------------------------------- #
echo
echo "Stress test: 2000 random inputs (any panic = failure)..."
for i in $(seq 1 2000); do
    sz=$((RANDOM % 4096 + 1))
    head -c "$sz" /dev/urandom > "$WORK/r$i.bin"
    "$RUSTRIP" "$WORK/r$i.bin" -f table > "$WORK/r$i.out" 2>&1 || true
    if grep -q "panicked at" "$WORK/r$i.out" 2>/dev/null; then
        printf "  FAIL  stress case %d PANICKED\n" "$i"
        failures=$((failures + 1))
        break
    fi
done
total=$((total + 2000))

# ------------------------------------------------------------------------- #
# Summary
# ------------------------------------------------------------------------- #
echo
if [[ "$failures" -eq 0 ]]; then
    printf "OK — %d cases passed, no panics observed\n" "$total"
    exit 0
else
    printf "FAILED — %d of %d cases failed\n" "$failures" "$total"
    exit 1
fi
