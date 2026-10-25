// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The writer's scalar rules (D20, O2a): the replaced backend's choice of
//! plain, single-quoted, double-quoted or literal style, and libyaml's
//! writing of each, ported so the output stays byte-equal to the MIG.0
//! writer goldens. Checked by the K0 spike on 785,419 generated strings.
#![allow(
    clippy::many_single_char_names,
    reason = "a byte-level port of libyaml's scanner classes; the names follow it"
)]

fn digits_but_not_number(s: &str) -> bool {
    let s = s.strip_prefix(['-', '+']).unwrap_or(s);
    s.len() > 1 && s.starts_with('0') && s[1..].bytes().all(|b| b.is_ascii_digit())
}

fn radix_ok(rest: &str, radix: u32) -> bool {
    !rest.starts_with(['+', '-']) && u128::from_str_radix(rest, radix).is_ok()
}

fn is_int(s: &str) -> bool {
    let unpos = s.strip_prefix('+').unwrap_or(s);
    for (p, r) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(rest) = unpos.strip_prefix(p)
            && radix_ok(rest, r)
        {
            return true;
        }
        if let Some(rest) = s.strip_prefix(&format!("-{p}"))
            && i128::from_str_radix(&format!("-{rest}"), r).is_ok()
        {
            return true;
        }
    }
    if digits_but_not_number(s) {
        return false;
    }
    if !unpos.starts_with(['+', '-']) && unpos.parse::<u128>().is_ok() {
        return true;
    }
    s.parse::<i128>().is_ok()
}

fn is_float(s: &str) -> bool {
    let unpos = match s.strip_prefix('+') {
        Some(u) if u.starts_with(['+', '-']) => return false,
        Some(u) => u,
        None => s,
    };
    matches!(unpos, ".inf" | ".Inf" | ".INF")
        || matches!(s, "-.inf" | "-.Inf" | "-.INF" | ".nan" | ".NaN" | ".NAN")
        || unpos.parse::<f64>().is_ok_and(f64::is_finite)
}

/// The replaced backend's `serialize_str` pre-choice: true when the text would read back
/// as something other than a string, so it must be single-quoted.
pub(crate) fn resolves_non_string(s: &str) -> bool {
    s.is_empty()
        || matches!(s, "null" | "Null" | "NULL" | "~")
        || matches!(s, "true" | "True" | "TRUE" | "false" | "False" | "FALSE")
        || is_int(s)
        || digits_but_not_number(s)
        || is_float(s)
}

// --- libyaml byte classes (over UTF-8) ---
fn is_break(b: &[u8], i: usize) -> bool {
    let c = b[i];
    c == b'\r'
        || c == b'\n'
        || (c == 0xC2 && b.get(i + 1) == Some(&0x85))
        || (c == 0xE2 && b.get(i + 1) == Some(&0x80) && matches!(b.get(i + 2), Some(0xA8 | 0xA9)))
}
fn is_space(b: &[u8], i: usize) -> bool {
    b[i] == b' '
}
fn is_blankz_at(b: &[u8], i: usize) -> bool {
    i >= b.len() || b[i] == b' ' || b[i] == b'\t' || is_break(b, i) || b[i] == 0
}
fn is_printable(b: &[u8], i: usize) -> bool {
    let c = b[i];
    let n = b.get(i + 1).copied().unwrap_or(0);
    let n2 = b.get(i + 2).copied().unwrap_or(0);
    match c {
        0x0A | 0x20..=0x7E | 0xC3..=0xEC | 0xEE | 0xF0..=0xF4 => true,
        0xC2 => (0xA0..=0xBF).contains(&n),
        0xED => n <= 0x9F,
        0xEF => match n {
            0xBB => n2 != 0xBF,
            0xBF => !matches!(n2, 0xBE | 0xBF),
            _ => true,
        },
        _ => false,
    }
}
fn width(c: u8) -> usize {
    if c & 0x80 == 0 {
        1
    } else if c & 0xE0 == 0xC0 {
        2
    } else if c & 0xF0 == 0xE0 {
        3
    } else {
        4
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "libyaml's scalar analysis flags, one per rule, as the emitter reads them"
)]
pub(crate) struct Analysis {
    pub(crate) multiline: bool,
    pub(crate) block_plain: bool,
    pub(crate) single: bool,
    pub(crate) block: bool,
    pub(crate) empty: bool,
}

#[allow(
    clippy::too_many_lines,
    reason = "a single pass over the bytes, as libyaml's analyze_scalar; splitting it splits its state"
)]
pub(crate) fn analyze(s: &str) -> Analysis {
    let b = s.as_bytes();
    if b.is_empty() {
        return Analysis {
            multiline: false,
            block_plain: true,
            single: true,
            block: false,
            empty: true,
        };
    }
    let (mut bi, mut lb, mut sc, mut ls, mut lbr, mut ts, mut tbr, mut bs, mut sb) = (
        false, false, false, false, false, false, false, false, false,
    );
    if s.starts_with("---") || s.starts_with("...") {
        bi = true;
    }
    let mut preceded = true;
    let mut followed = is_blankz_at(b, width(b[0]));
    let (mut psp, mut pbr) = (false, false);
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let w = width(c);
        if i == 0 {
            if b"#,[]{}&*!|>'\"%@`".contains(&c) {
                bi = true;
            }
            if (c == b'?' || c == b':') && followed {
                bi = true;
            }
            if c == b'-' && followed {
                bi = true;
            }
        } else {
            if c == b':' && followed {
                bi = true;
            }
            if c == b'#' && preceded {
                bi = true;
            }
        }
        if !is_printable(b, i) {
            sc = true;
        }
        if is_break(b, i) {
            lb = true;
        }
        if is_space(b, i) {
            if i == 0 {
                ls = true;
            }
            if i + w == b.len() {
                ts = true;
            }
            if pbr {
                bs = true;
            }
            psp = true;
            pbr = false;
        } else if is_break(b, i) {
            if i == 0 {
                lbr = true;
            }
            if i + w == b.len() {
                tbr = true;
            }
            if psp {
                sb = true;
            }
            psp = false;
            pbr = true;
        } else {
            psp = false;
            pbr = false;
        }
        preceded = is_blankz_at(b, i);
        i += w;
        if i < b.len() {
            followed = is_blankz_at(b, i + width(b[i]));
        }
    }
    let mut a = Analysis {
        multiline: lb,
        block_plain: true,
        single: true,
        block: true,
        empty: false,
    };
    if ls || lbr || ts || tbr {
        a.block_plain = false;
    }
    if ts {
        a.block = false;
    }
    if bs {
        a.block_plain = false;
        a.single = false;
    }
    if sb || sc {
        a.block_plain = false;
        a.single = false;
        a.block = false;
    }
    if lb {
        a.block_plain = false;
    }
    if bi {
        a.block_plain = false;
    }
    a
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Style {
    Plain,
    Single,
    Double,
    Literal,
}

/// The replaced backend's pre-choice, then libyaml's `select_scalar_style` (block
/// context, no flow, never canonical).
pub(crate) fn style_for(s: &str, simple_key: bool) -> Style {
    let a = analyze(s);
    let mut st = if s.contains('\n') {
        Style::Literal
    } else if resolves_non_string(s) {
        Style::Single
    } else {
        Style::Plain
    };
    if simple_key && a.multiline {
        st = Style::Double;
    }
    if st == Style::Plain {
        if !a.block_plain {
            st = Style::Single;
        }
        if a.empty && simple_key {
            st = Style::Single;
        }
    }
    if st == Style::Single && !a.single {
        st = Style::Double;
    }
    if st == Style::Literal && (!a.block || simple_key) {
        st = Style::Double;
    }
    st
}

/// libyaml's single-quoted writer: `'` doubled; a line break (only U+2028
/// or U+2029 reach here) is written raw and the next text is re-indented.
pub(crate) fn single_quoted(s: &str, indent: usize) -> String {
    let b = s.as_bytes();
    let pad = " ".repeat(indent);
    let mut out = String::from("'");
    let (mut breaks, mut i) = (false, 0);
    while i < b.len() {
        let w = width(b[i]);
        let t = &s[i..i + w];
        if is_break(b, i) {
            if !breaks && t == "\n" {
                out.push('\n');
            }
            out.push_str(t);
            breaks = true;
        } else {
            if breaks {
                out.push_str(&pad);
            }
            if t == "'" {
                out.push('\'');
            }
            out.push_str(t);
            breaks = false;
        }
        i += w;
    }
    if breaks {
        out.push_str(&pad);
    }
    out.push('\'');
    out
}

pub(crate) fn double_quoted(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::from("\"");
    for (i, ch) in s.char_indices() {
        let bom = b[i] == 0xEF && b.get(i + 1) == Some(&0xBB) && b.get(i + 2) == Some(&0xBF);
        if !is_printable(b, i) || bom || is_break(b, i) || ch == '"' || ch == '\\' {
            out.push_str(&escape(ch));
        } else {
            out.push(ch);
        }
    }
    out.push('"');
    out
}

/// libyaml's double-quoted escape for one character.
fn escape(ch: char) -> String {
    match ch {
        '\0' => "\\0".into(),
        '\u{7}' => "\\a".into(),
        '\u{8}' => "\\b".into(),
        '\t' => "\\t".into(),
        '\n' => "\\n".into(),
        '\u{b}' => "\\v".into(),
        '\u{c}' => "\\f".into(),
        '\r' => "\\r".into(),
        '\u{1b}' => "\\e".into(),
        '"' => "\\\"".into(),
        '\\' => "\\\\".into(),
        '\u{85}' => "\\N".into(),
        '\u{a0}' => "\\_".into(),
        '\u{2028}' => "\\L".into(),
        '\u{2029}' => "\\P".into(),
        c if u32::from(c) <= 0xFF => format!("\\x{:02X}", u32::from(c)),
        c if u32::from(c) <= 0xFFFF => format!("\\u{:04X}", u32::from(c)),
        c => format!("\\U{:08X}", u32::from(c)),
    }
}

/// `|` + hints, then the text: a break is written as itself (`\n` as a
/// newline), and text after a break is padded to `indent`. Returns the text
/// and whether it ended on a break (then the caller adds no newline).
pub(crate) fn literal(s: &str, indent: usize) -> (String, bool) {
    let b = s.as_bytes();
    let mut h = String::from("|");
    if b[0] == b' ' || is_break(b, 0) {
        h.push('2');
    }
    // the last character, and the one before it
    // Literal style is chosen only for text holding a line break, so `s`
    // is not empty here.
    let Some(last) = s.char_indices().last().map(|(i, _)| i) else {
        return (h, false);
    };
    let prev = s[..last].char_indices().last().map(|(i, _)| i);
    if !is_break(b, last) {
        h.push('-');
    } else if prev.is_none_or(|p| is_break(b, p)) {
        h.push('+');
    }
    let pad = " ".repeat(indent);
    let mut out = h;
    out.push('\n');
    let (mut breaks, mut i) = (true, 0);
    while i < b.len() {
        let w = width(b[i]);
        let t = &s[i..i + w];
        if is_break(b, i) {
            out.push_str(t);
            breaks = true;
        } else {
            if breaks {
                out.push_str(&pad);
            }
            out.push_str(t);
            breaks = false;
        }
        i += w;
    }
    (out, breaks)
}

/// The scalar's text and whether it ended on a line break.
pub(crate) fn scalar_text(s: &str, simple_key: bool, indent: usize) -> (String, bool) {
    match style_for(s, simple_key) {
        Style::Plain => (s.to_string(), false),
        Style::Single => (single_quoted(s, indent), false),
        Style::Double => (double_quoted(s), false),
        Style::Literal => literal(s, indent),
    }
}

/// libyaml's `check_simple_key` for a string key: single line, at most 128 bytes.
pub(crate) fn simple_key_ok(s: &str) -> bool {
    !analyze(s).multiline && s.len() <= 128
}
