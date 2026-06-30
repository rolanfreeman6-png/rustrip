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

        // Header
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

fn kind_str(k: &crate::analyzers::AnnotationKind) -> &'static str {
    use crate::analyzers::AnnotationKind::*;
    match k {
        String => "string",
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
        let oneline_len = one_line(&a.label, usize::MAX).chars().count();
        w = w.max(oneline_len.min(120));
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

    #[test]
    fn renders_address_kind_label() {
        let anns = vec![Annotation {
            vaddr: 0x401000,
            kind: AnnotationKind::String,
            label: "hello".into(),
            comment: None,
        }];
        let mut buf = Vec::new();
        Table.render(&anns, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("0x401000"));
        assert!(s.contains("string"));
        assert!(s.contains("hello"));
    }
}
