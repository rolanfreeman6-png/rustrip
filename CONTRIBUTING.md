# Contributing to rustrip

Thanks for taking an interest. The project lives at
<https://github.com/rolanfreeman6-png/rustrip>.

## Workflow

1. Fork the repository.
2. Create a topic branch (`git checkout -b feat/<short-name>`).
3. Make small, focused commits with imperative-mood messages
   ("Add…, Fix…, Refactor…").
4. Ensure:
   ```sh
   cargo fmt --all
   cargo clippy --all-targets -- -D warnings
   cargo test --all-targets
   cargo build --release
   scripts/adversarial_test.sh target/release/rustrip
   ```
   …all pass locally.
5. Squash-fixup before opening a pull request if you have many "wip:"
   commits.
6. Open a PR against `main`. CI must pass before a maintainer reviews.

## Coding conventions

- Edition 2021, MSRV = current stable - 2.
- Comments only where the *why* is non-obvious. The *what* should be
  expressed by the code itself.
- `pub` APIs go in `lib.rs`; binaries/binaries call into the library.
- Analyzer implementations must implement the `Analyzer` trait in
  `analyzers/mod.rs`. New output formats implement `OutputBackend`
  in `output/mod.rs`. Analyzers and output backends don't see each
  other — they communicate only through `Annotation`.
- Tests in `tests/integration.rs` exercise the full pipeline against
  a real binary. Unit tests next to each module cover the predicate
  itself. Adversarial fuzzing in `scripts/adversarial_test.sh` covers
  parser resilience.

## What we won't accept

- Half-implemented features (TODO-without-impl) in production code.
- New dependencies without a discussion in the issue tracker.
- Premature abstractions — three similar lines beat one helper.
- Performance work without `#![feature]` benchmarks on representative
  real binaries (not synthetic data).

## Reporting security issues

Open a GitHub Security Advisory (not a public issue) for anything
that touches parsing of untrusted binaries.
