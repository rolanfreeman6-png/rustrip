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
