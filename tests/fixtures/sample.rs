//! Source files used to build sample binaries for richer fixture tests.
//!
//! These are NOT compiled by the main `rustrip` Cargo.toml. They live here
//! for `scripts/build-fixtures.{ps1,sh}` to invoke when a separate fixture
//! binary is needed (e.g. for fuzzing or external integration runs).
//!
//! Often we simply analyze `rustrip` itself, which already exercises the
//! full pipeline. This directory is here so a richer fixture can be
//! produced on demand.

pub fn do_panic() {
    let _ = 1u32 + 1;
    panic!("smoke panic from fixture");
}

pub fn strings() -> &'static str {
    "https://example.com/api/v1/login"
}
