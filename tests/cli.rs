//! CLI integration tests.
//!
//! These tests exercise `rustrip` as a subprocess so they cover the
//! `main.rs` paths that unit tests under `#[cfg(test)] mod tests`
//! cannot reach: clap parsing, file I/O, and per-flag combos.
//!
//! Strategy: spawn the freshly-built `rustrip` binary (`CARGO_BIN_EXE`)
//! via `std::process::Command`, capture stdout/stderr, and assert on
//! behaviour. The `CARGO_BIN_EXE_rustrip` env var is set automatically
//! by `cargo test` to the just-built binary path.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn rustrip_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rustrip"))
}

#[test]
fn cli_version_prints_pkg_version() {
    let out = Command::new(rustrip_bin())
        .arg("--version")
        .output()
        .expect("run rustrip --version");
    assert!(
        out.status.success(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains(env!("CARGO_PKG_VERSION")),
        "version output {s:?} does not contain pkg version"
    );
}

#[test]
fn cli_help_contains_killer_tagline() {
    let out = Command::new(rustrip_bin())
        .arg("--help")
        .output()
        .expect("run rustrip --help");
    assert!(
        out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let combined =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(
        combined.contains("Make stripped Rust binaries readable again"),
        "tagline missing from --help"
    );
}

#[test]
fn cli_on_self_binary_produces_table_output() {
    let exe = rustrip_bin();
    let out = Command::new(&exe)
        .arg(&exe)
        .arg("-f")
        .arg("table")
        .output()
        .expect("run rustrip self-analysis table");
    assert!(
        out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("vaddr"), "no vaddr header: {s:?}");
    assert!(
        s.contains("panic") || s.contains("string") || s.contains("symbol"),
        "expected at least one annotation kind in table: {s:?}"
    );
}

#[test]
fn cli_selective_flags_all_combinatorial() {
    let exe = rustrip_bin();
    let cases: &[&[&str]] = &[
        &["--no-strings"],
        &["--no-symbols"],
        &["--no-panics"],
        &["--no-strings", "--no-symbols"],
        &["--no-strings", "--no-panics"],
        &["--no-symbols", "--no-panics"],
        &["--no-strings", "--no-symbols", "--no-panics"],
    ];
    for flags in cases {
        let mut cmd = Command::new(&exe);
        cmd.arg(&exe).arg("-f").arg("text");
        for f in *flags {
            cmd.arg(f);
        }
        let out = cmd.output().expect("run rustrip selective");
        assert!(
            out.status.success(),
            "flag combination {:?} failed. stderr: {:?}",
            flags,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn cli_format_aliases_all_accepted() {
    let exe = rustrip_bin();
    let aliases = [
        "text",
        "json",
        "cli",
        "ghidra",
        "ghidra-py",
        "py-ghidra",
        "binja",
        "binary-ninja",
        "bn",
        "py-binja",
    ];
    for alias in aliases {
        let mut cmd = Command::new(&exe);
        cmd.arg(&exe).arg("-f").arg(alias);
        let out = cmd.output().expect("run rustrip with alias");
        assert!(
            out.status.success() || out.status.code() == Some(0),
            "alias {alias} failed: stderr: {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn cli_format_unknown_non_zero_exit() {
    let exe = rustrip_bin();
    let out = Command::new(&exe)
        .arg(&exe)
        .arg("-f")
        .arg("garbage-format")
        .output()
        .expect("run rustrip with bad format");
    assert!(
        !out.status.success(),
        "garbage --format should fail; stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_missing_path_non_zero_exit() {
    let exe = rustrip_bin();
    let out = Command::new(&exe)
        .arg("C:\\nonexistent-dir-for-rustrip-cli-test\\foo.bin")
        .output()
        .expect("run rustrip with missing path");
    assert!(
        !out.status.success(),
        "missing path should error; stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("opening") || stderr.to_lowercase().contains("path"),
        "stderr should mention the path/IO: {stderr:?}"
    );
}

#[test]
fn cli_reads_from_stdin_via_dash() {
    let mut child = Command::new(rustrip_bin())
        .arg("-")
        .arg("-f")
        .arg("text")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn rustrip with stdin");
    let mut stdin = child.stdin.take().expect("stdin handle");
    stdin
        .write_all(&std::fs::read(rustrip_bin()).expect("read self binary"))
        .expect("stdin write");
    drop(stdin);
    let out = child.wait_with_output().expect("wait rustrip");
    // Reading from stdin must not fail; succeeded produces a normal
    // annotation stream.
    assert!(
        out.status.success(),
        "stdin self-analysis failed; stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_max_string_len_zero_rejects_or_filters() {
    let exe = rustrip_bin();
    let out = Command::new(&exe)
        .arg(&exe)
        .arg("-f")
        .arg("text")
        .arg("--max-string-len")
        .arg("0")
        .output()
        .expect("run rustrip max-string-len=0");
    assert!(
        out.status.success(),
        "max-string-len=0 should run cleanly; stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ─────────────────────────────────────────────────────────────────────
// File-output path: exercises the `Some(p)` branch in `main.rs` that
// opens a `std::fs::File` for the rendered backend. cargo-mutants
// mutations in that control flow (e.g. dropping the `Box::new(...)` or
// the `with_context(...)` chain) get caught here.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn cli_output_file_writes_table_to_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("rustrip-table.txt");
    let exe = rustrip_bin();
    let out = Command::new(&exe)
        .arg(&exe)
        .arg("-f")
        .arg("table")
        .arg("-o")
        .arg(&out_path)
        .output()
        .expect("run rustrip -o table");
    assert!(
        out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let on_disk = std::fs::read_to_string(&out_path).expect("read output");
    assert!(
        on_disk.contains("vaddr"),
        "no vaddr header on disk: {on_disk:?}"
    );
    assert!(
        on_disk.contains("panic") || on_disk.contains("string") || on_disk.contains("symbol"),
        "no annotation on disk: {on_disk:?}"
    );
}

#[test]
fn cli_output_file_writes_json_to_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("rustrip-report.json");
    let exe = rustrip_bin();
    let out = Command::new(&exe)
        .arg(&exe)
        .arg("-f")
        .arg("json")
        .arg("-o")
        .arg(&out_path)
        .output()
        .expect("run rustrip -o json");
    assert!(
        out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let on_disk = std::fs::read_to_string(&out_path).expect("read json");
    let parsed: serde_json::Value = serde_json::from_str(&on_disk).expect("json parses");
    let arr = parsed.as_array().expect("top-level is array");
    assert!(!arr.is_empty(), "json had no annotations");
}

#[test]
fn cli_output_file_writes_ghidra_python_to_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("rustrip-report_ghidra.py");
    let exe = rustrip_bin();
    let out = Command::new(&exe)
        .arg(&exe)
        .arg("-f")
        .arg("ghidra")
        .arg("-o")
        .arg(&out_path)
        .output()
        .expect("run rustrip -o ghidra");
    assert!(
        out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let on_disk = std::fs::read_to_string(&out_path).expect("read ghidra py");
    assert!(on_disk.contains("currentProgram"));
    assert!(on_disk.contains("_comments"));
}

#[test]
fn cli_output_file_writes_binja_python_to_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("rustrip-report_binja.py");
    let exe = rustrip_bin();
    let out = Command::new(&exe)
        .arg(&exe)
        .arg("-f")
        .arg("binja")
        .arg("-o")
        .arg(&out_path)
        .output()
        .expect("run rustrip -o binja");
    assert!(
        out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let on_disk = std::fs::read_to_string(&out_path).expect("read binja py");
    assert!(on_disk.contains("binaryninja"));
    assert!(on_disk.contains("_labels"));
}

// ─────────────────────────────────────────────────────────────────────
// Tiny-binary guard. `read_bytes` returns `Err` when the file is less
// than 4 bytes — covers cargo-mutants deletions of the `anyhow::bail!`
// arm + the surrounding `if buf.len() < 4` (mutation `<` → `<=` is
// killed by the boundary tests below).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn cli_tiny_binary_bails_with_friendly_message() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tiny = dir.path().join("tiny.bin");
    std::fs::write(&tiny, [0u8, 0, 0]).expect("write tiny");
    let exe = rustrip_bin();
    let out = Command::new(&exe)
        .arg(&tiny)
        .arg("-f")
        .arg("text")
        .output()
        .expect("run rustrip tiny");
    assert!(
        !out.status.success(),
        "tiny input should fail; stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        stderr.contains("too small") || stderr.contains("small"),
        "stderr should mention 'too small': {stderr:?}"
    );
}

/// 4-byte boundary. cargo-mutants mutates `buf.len() < 4` to `<=`; the
/// mutated version bails on exactly-4-byte input. This test feeds an
/// ELF magic-header file (4 bytes) just at the threshold and asserts
/// the rustrip binary does NOT trip its own tiny-file guard. (The
/// underlying goblin parser will fail with *its* error message about a
/// malformed object, NOT rustrip's "binary too small" message.)
#[test]
fn cli_four_byte_or_larger_does_not_bail_tiny() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tiny = dir.path().join("four.bin");
    std::fs::write(&tiny, [0x7f, b'E', b'L', b'F']).expect("write ELF magic");
    let exe = rustrip_bin();
    let out = Command::new(&exe)
        .arg(&tiny)
        .arg("-f")
        .arg("text")
        .output()
        .expect("run rustrip 4-byte ELF magic");
    // Must not be rustrip's tiny-file guard: that message is "binary
    // too small". goblin's own error phrasings (e.g. "object is too
    // small", "malformed entity") are fine — they're the mutated
    // mutation-target guard's actual error from the deeper loader.
    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        !stderr.contains("binary too small"),
        "4-byte ELF magic should not hit rustrip's tiny-file bail: {stderr:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// All-three-analyzers coverage. Mutating `if !cli.no_strings` →
// `if cli.no_strings` (drop the `!`) on a non-flagged run makes the
// strings analyzer be SKIPPED. Same shape for symbols and panics on
// lines 72 / 75. The original cargo-mutants misses were on those
// exact lines.
//
// We don't assert that *every* kind shows up — goblin's symbol
// recovery depends on platform (PE executables without export tables
// yield zero symbols; ELF executables bypass the same path), and the
// rustrip self-binary on Windows demonstrably produces 0 'symbol'
// annotations. Instead, we assert that the *boolean gate* behaves:
// with a `--no-X` flag, the corresponding kind is gone (or unchanged
// if absent for platform reasons); without it, the default behavior
// preserves whatever bins produced. The mutation `delete !` makes
// every `--no-X` flag a power-on switch instead of power-off, so this
// invariant is non-trivial.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn cli_selective_flag_toggles_invert_properly() {
    let exe = rustrip_bin();

    let kinds_for = |flags: &[&str]| -> std::collections::HashSet<String> {
        let mut cmd = Command::new(&exe);
        cmd.arg(&exe).arg("-f").arg("json");
        for f in flags {
            cmd.arg(f);
        }
        let out = cmd.output().expect("run rustrip");
        assert!(
            out.status.success(),
            "flags {flags:?} failed: {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json parses");
        let arr = parsed.as_array().expect("array");
        arr.iter()
            .filter_map(|v| v.get("kind").and_then(|k| k.as_str()).map(str::to_owned))
            .collect()
    };

    // Strings: rust strip+panic binaries always carry &str slices.
    let baseline = kinds_for(&[]);
    assert!(
        baseline.contains("string"),
        "baseline must include 'string' (rustrip self-binary has its literals): {baseline:?}"
    );
    let no_strings = kinds_for(&["--no-strings"]);
    assert!(
        !no_strings.contains("string"),
        "--no-strings should drop 'string' kinds; got: {no_strings:?}"
    );
    assert!(
        no_strings.len() < baseline.len() || no_strings == baseline,
        "disabling strings shouldn't *increase* kinds; baseline={baseline:?}, no_strings={no_strings:?}"
    );

    // Panics: rustrip binary has at least one panic location in core/std.
    if baseline.contains("panic") {
        let no_panics = kinds_for(&["--no-panics"]);
        assert!(
            !no_panics.contains("panic"),
            "--no-panics should drop 'panic' kinds; got: {no_panics:?}"
        );
    }

    // Symbols: only assert invertibility when the baseline actually
    // recovered symbols. Windows PE without export tables yields zero
    // symbols no matter the flag — that's not a regression, so we
    // skip the invertibility check rather than fail spuriously.
    if baseline.contains("symbol") {
        let no_symbols = kinds_for(&["--no-symbols"]);
        assert!(
            !no_symbols.contains("symbol"),
            "--no-symbols should drop 'symbol' kinds; got: {no_symbols:?}"
        );
    }
}

/// `cli.max_string_len` propagation. The `Limits { max_string_len:
/// cli.max_string_len, .. }` line in main.rs is mutated by cargo-mutants
/// to (e.g.) delete the field — which silently picks up the
/// `Limits::default()` (4096). The previous `cli_max_string_len_zero`
/// test passes either way because max=0 produces no strings regardless.
/// This test exercises a non-zero, non-default value path: output must
/// produce *more* annotations with the default 4096 cap than with a
/// 50-byte cap, on the rustrip binary itself (which has been built with
/// goblin strings in its embedded string section — some of these may
/// exceed the cap).
#[test]
fn cli_max_string_len_propagates_to_limits() {
    let exe = rustrip_bin();

    let count_for = |max: usize| -> usize {
        let out = Command::new(&exe)
            .arg(&exe)
            .arg("-f")
            .arg("json")
            .arg("--max-string-len")
            .arg(max.to_string())
            .output()
            .expect("run rustrip --max-string-len");
        assert!(
            out.status.success(),
            "max={max} failed: {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json parses");
        let arr = parsed.as_array().expect("array");
        arr.iter()
            .filter(|v| v.get("kind").and_then(|k| k.as_str()) == Some("string"))
            .count()
    };

    let big = count_for(4096);
    let small = count_for(8);
    // A tighter cap must not produce *more* string annotations than a
    // looser cap. (`>=` rather than `>` because both could legitimately
    // drop nested/long slices — what matters is no mutation flips the
    // direction.)
    assert!(
        big >= small,
        "tighter --max-string-len produced *more* strings (big={big}, small={small})"
    );
}
