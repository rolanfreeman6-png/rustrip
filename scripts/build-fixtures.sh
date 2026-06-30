#!/usr/bin/env bash
# Optional: build a richer Rust fixture binary for rustrip testing.
# Usage: scripts/build-fixtures.sh
# Output: tests/fixtures/dist/sample[-stripped]

set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found on PATH; install rustup first." >&2
    exit 2
fi

cargo build --release --manifest-path "$root/tests/fixtures/Cargo.toml"

mkdir -p "$root/tests/fixtures/dist"
cp "$root/tests/fixtures/target/release/"sample* \
   "$root/tests/fixtures/dist/" 2>/dev/null || true
echo "fixtures built under tests/fixtures/dist/"
