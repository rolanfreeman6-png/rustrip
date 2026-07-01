//! CLI-text table output: address | kind | label.
//!
//! Plain ASCII — works in any terminal, easy to grep, suitable for the
//! README screenshot/GIF without depending on a terminal color library.

use crate::analyzers::Annotation;
use crate::output::OutputBackend;
use std::io::Write;

pub struct Table;

impl OutputBackend for Table {
    fn render(&self, anns: &[Annotation], w: &mut dyn Write) -> std::io::Result<()> {
        let kind_w = kind_width(anns);
        let label_w = label_width(anns);

        writeln!(
            w,
            "{:<18}  {:<kind_w$}  label",
            "vaddr",
            "kind",
            kind_w = kind_w
        )?;
        writeln!(
            w,
            "{}  {}  {}",
            repeat('-', 18),
            repeat('-', kind_w),
            repeat('-', label_w)
        )?;

        for a in anns {
            writeln!(
                w,
                "0x{:<16x}  {:<kind_w$}  {}",
                a.vaddr,
                kind_str(&a.kind),
                one_line(&a.label, label_w),
                kind_w = kind_w
            )?;
            if let Some(c) = &a.comment {
                for line in textwrap(c, label_w) {
                    writeln!(w, "  {:<kind_w$}  │ {}", "", line, kind_w = kind_w)?;
                }
            }
        }
        Ok(())
    }
}

const fn kind_str(k: &crate::analyzers::AnnotationKind) -> &'static str {
    use crate::analyzers::AnnotationKind::{PanicSite, String as KString, Symbol};
    match k {
        KString => "string",
        Symbol => "symbol",
        PanicSite => "panic",
    }
}

fn kind_width(anns: &[Annotation]) -> usize {
    let mut w = "kind".len();
    for a in anns {
        w = w.max(kind_str(&a.kind).len());
    }
    w
}

fn label_width(anns: &[Annotation]) -> usize {
    let mut w = "label".len();
    for a in anns {
        let chars = a.label.chars().count().min(120);
        w = w.max(chars);
    }
    w
}

fn one_line(s: &str, max: usize) -> String {
    let one = s
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    if one.chars().count() <= max {
        one
    } else {
        let mut t: String = one.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn textwrap(s: &str, width: usize) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    // Word- or char-based wrap; char-based is the safe utf8 fallback.
    let mut lines = Vec::new();
    let mut cur = String::new();
    let mut cur_len = 0usize;
    for ch in s.chars() {
        if ch == '\n' {
            lines.push(std::mem::take(&mut cur));
            cur_len = 0;
            continue;
        }
        if cur_len >= width {
            lines.push(std::mem::take(&mut cur));
            cur_len = 0;
        }
        cur.push(ch);
        cur_len += 1;
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

fn repeat(c: char, n: usize) -> String {
    std::iter::repeat_n(c, n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::{Annotation, AnnotationKind};
    use std::cmp;

    fn render_bytes(anns: &[Annotation]) -> Vec<u8> {
        let mut buf = Vec::new();
        // nosemgrep: rustrip-no-unwrapping-trust-bytes (test code)
        Table.render(anns, &mut buf).unwrap();
        buf
    }

    fn render_string(anns: &[Annotation]) -> String {
        // nosemgrep: rustrip-no-unwrapping-trust-bytes (test code)
        String::from_utf8(render_bytes(anns)).unwrap()
    }

    #[test]
    fn renders_address_kind_label() {
        let anns = vec![Annotation {
            vaddr: 0x0040_1000,
            kind: AnnotationKind::String,
            label: "hello".into(),
            comment: None,
        }];
        let s = render_string(&anns);
        assert!(s.contains("0x401000"));
        assert!(s.contains("string"));
        assert!(s.contains("hello"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // Helper tests — `repeat`, `textwrap`, `one_line`, `kind_width`,
    // `label_width`. These pin exact behaviour callers depend on; cargo-
    // mutants off-by-one mutations of `repeat_n` get caught by length
    // asserts, and literal ordering inside backends is verified by the
    // byte-exact snapshot tests below.
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn repeat_emits_exactly_n_chars() {
        assert_eq!(repeat('-', 0), "");
        assert_eq!(repeat('-', 1), "-");
        assert_eq!(repeat('-', 5), "-----");
        assert_eq!(repeat('-', 18).chars().count(), 18);
        assert_eq!(repeat('-', 120).chars().count(), 120);
        assert_eq!(repeat('a', 3), "aaa");
    }

    #[test]
    fn one_line_passes_through_short_strings() {
        assert_eq!(one_line("abc", 10), "abc");
        assert_eq!(one_line("", 10), "");
    }

    #[test]
    fn one_line_truncates_with_ellipsis_on_overflow() {
        let out = one_line(&"x".repeat(50), 10);
        assert_eq!(out.chars().count(), 10);
        assert!(out.ends_with('…'));
        assert_eq!(&out[..9], &"x".repeat(9));
    }

    #[test]
    fn one_line_truncates_at_max_zero() {
        // max=0: take(0).collect() → "" + ellipsis → "…"
        assert_eq!(one_line("hello", 0), "…");
    }

    #[test]
    fn one_line_escapes_control_chars() {
        assert_eq!(one_line("a\nb", 100), "a\\nb");
        assert_eq!(one_line("a\rb", 100), "a\\rb");
        assert_eq!(one_line("a\tb", 100), "a\\tb");
        assert_eq!(one_line("\n\t\r", 100), "\\n\\t\\r");
    }

    #[test]
    fn textwrap_splits_on_newline() {
        assert_eq!(textwrap("ab\ncd", 80), vec!["ab", "cd"]);
        assert_eq!(textwrap("\n\n\n", 80), vec!["", "", ""]);
    }

    #[test]
    fn textwrap_chops_at_width_char_count() {
        assert_eq!(textwrap("abcdef", 2), vec!["ab", "cd", "ef"]);
        assert_eq!(textwrap("abcdef", 3), vec!["abc", "def"]);
        assert_eq!(textwrap("abcde", 3), vec!["abc", "de"]);
    }

    #[test]
    fn textwrap_handles_empty_input() {
        assert!(textwrap("", 80).is_empty());
    }

    #[test]
    fn kind_width_picks_max_kind_label() {
        // "string" and "symbol" are the longest (6 chars); "panic" is 5.
        let anns = vec![
            Annotation {
                vaddr: 1,
                kind: AnnotationKind::String,
                label: "x".into(),
                comment: None,
            },
            Annotation {
                vaddr: 2,
                kind: AnnotationKind::Symbol,
                label: "y".into(),
                comment: None,
            },
        ];
        assert_eq!(kind_width(&anns), 6);
    }

    #[test]
    fn label_width_picks_max_label_up_to_cap() {
        let anns = vec![
            Annotation {
                vaddr: 1,
                kind: AnnotationKind::String,
                label: "short".into(),
                comment: None,
            },
            Annotation {
                vaddr: 2,
                kind: AnnotationKind::String,
                label: "a".repeat(500),
                comment: None,
            },
        ];
        assert_eq!(label_width(&anns), 120);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Byte-exact snapshot tests. We compose the expected output by calling
    // *the same `writeln!` format strings* as production. cargo-mutants
    // mutates one location at a time, so any mutation of a production
    // `writeln!(...)` desyncs actual vs. expected — caught by `assert_eq!`
    // even though the test code looks "duplicate".
    // ─────────────────────────────────────────────────────────────────────

    fn render_reference(anns: &[Annotation]) -> String {
        use std::fmt::Write as _;
        let kind_w = kind_width(anns);
        let label_w = label_width(anns);
        let mut s = String::new();
        // Header — mirror src/output/table.rs exactly.
        let _ = writeln!(
            s,
            "{:<18}  {:<kind_w$}  label",
            "vaddr",
            "kind",
            kind_w = kind_w
        );
        let _ = writeln!(
            s,
            "{}  {}  {}",
            repeat('-', 18),
            repeat('-', kind_w),
            repeat('-', label_w)
        );
        for a in anns {
            let _ = writeln!(
                s,
                "0x{:<16x}  {:<kind_w$}  {}",
                a.vaddr,
                kind_str(&a.kind),
                one_line(&a.label, label_w),
                kind_w = kind_w
            );
            if let Some(c) = &a.comment {
                for line in textwrap(c, label_w) {
                    let _ = writeln!(s, "  {:<kind_w$}  │ {}", "", line, kind_w = kind_w);
                }
            }
        }
        s
    }

    #[test]
    fn byte_exact_no_comments() {
        let anns = vec![
            Annotation {
                vaddr: 0x0040_1000,
                kind: AnnotationKind::String,
                label: "alpha".into(),
                comment: None,
            },
            Annotation {
                vaddr: 0x0040_2000,
                kind: AnnotationKind::PanicSite,
                label: "src/main.rs:7".into(),
                comment: None,
            },
        ];
        assert_eq!(render_string(&anns), render_reference(&anns));
    }

    #[test]
    fn byte_exact_with_wrapped_comment() {
        // Comment wider than label so textwrap() runs multiple times.
        let anns = vec![Annotation {
            vaddr: 0x0040_1000,
            kind: AnnotationKind::Symbol,
            label: "core::fmt::write".into(),
            comment: Some("recovered &str slice at offset 0x401000, len=18, valid utf-8".into()),
        }];
        assert_eq!(render_string(&anns), render_reference(&anns));
    }

    #[test]
    fn byte_exact_truncated_label() {
        let long = "L".repeat(130);
        let anns = vec![Annotation {
            vaddr: 0x1000,
            kind: AnnotationKind::String,
            label: long.clone(),
            comment: None,
        }];
        assert_eq!(render_string(&anns), render_reference(&anns));
        // Belt-and-suspenders: ellipsis present, truncated length correct.
        let out = render_string(&anns);
        let mut truncated = String::with_capacity(120);
        truncated.push_str(&"L".repeat(cmp::min(120, long.len()) - 1));
        truncated.push('…');
        assert!(out.contains(&truncated), "missing: {truncated} in {out:?}");
    }

    #[test]
    fn byte_exact_empty() {
        assert_eq!(render_string(&[]), render_reference(&[]));
    }

    #[test]
    fn byte_exact_all_three_kinds() {
        // Mixes all three AnnotationKind variants so kind_w exercises
        // the max-of-each path.
        let anns = vec![
            Annotation {
                vaddr: 0x0040_0000,
                kind: AnnotationKind::String,
                label: "string_data".into(),
                comment: Some("note for string".into()),
            },
            Annotation {
                vaddr: 0x0040_0010,
                kind: AnnotationKind::Symbol,
                label: "_ZN3std2io5Write9write_fmt".into(),
                comment: None,
            },
            Annotation {
                vaddr: 0x0040_0020,
                kind: AnnotationKind::PanicSite,
                label: "src/main.rs:42:5".into(),
                comment: Some("called from thread main".into()),
            },
        ];
        assert_eq!(render_string(&anns), render_reference(&anns));
    }
}
