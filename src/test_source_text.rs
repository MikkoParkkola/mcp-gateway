// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The production part of a Rust source file, for the tests that scan the
//! source tree: each `#[cfg(test)]` item is blanked by its own extent, so code
//! after an early test module or test-only item is still scanned. Shared by
//! the library's tests and, through `#[path]`, by the binary's tests and the
//! integration tests.

const MARK: &str = "#[cfg(test)]";

/// `text` with every `#[cfg(test)]` item blanked: spaces in place of its
/// bytes, newlines kept, so positions and line numbers still match `text`
/// and literals outside test items survive. Only marks in code count: one in
/// a comment or a string is not an attribute. An item whose extent cannot be
/// found is left in place (a scan sees more, never less); the others are
/// still blanked.
pub(crate) fn production_text(text: &str) -> String {
    let code = sanitize(text);
    let mut out = text.as_bytes().to_vec();
    let mut from = 0;
    while let Some(at) = code[from..].find(MARK).map(|p| p + from) {
        match item_end(code.as_bytes(), text.as_bytes(), at + MARK.len()) {
            Some(end) => {
                blank(&mut out, at, end);
                from = end;
            }
            None => from = at + MARK.len(),
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
}

/// Where the item after an attribute ends, in `code` (comments and literals
/// already blanked): at a `;` or `,` at its own level (a declaration, a field,
/// a variant, an arm), after a block at its own level that nothing continues
/// (`else`, a method call, `?`), or just before the bracket that closes the
/// item's parent (a last field with no comma). `None` when the text ends first.
/// `text` is the original, to tell a masked literal or comment after a block
/// (which ends the item) from plain whitespace.
fn item_end(code: &[u8], text: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0_usize;
    let mut i = start;
    while i < code.len() {
        match code[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth == 0 => return Some(i),
            b')' | b']' => depth -= 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    let next = code[i + 1..].iter().position(|c| !c.is_ascii_whitespace());
                    let gap = &text[i + 1..next.map_or(code.len(), |n| i + 1 + n)];
                    if gap.iter().any(|c| !c.is_ascii_whitespace()) {
                        return Some(i + 1);
                    }
                    let rest = next.map_or(&[][..], |n| &code[i + 1 + n..]);
                    match rest.first() {
                        Some(b';' | b',') => return Some(i + 1 + next.unwrap_or(0) + 1),
                        // `..` after a block starts a range, the next item.
                        Some(b'.') if rest.get(1) != Some(&b'.') => {}
                        Some(b'?') => {}
                        _ if continues_with_else(rest) => {}
                        _ => return Some(i + 1),
                    }
                }
            }
            b';' | b',' if depth == 0 => return Some(i + 1),
            _ => {}
        }
        i += 1;
    }
    None
}

fn continues_with_else(rest: &[u8]) -> bool {
    rest.starts_with(b"else")
        && !rest
            .get(4)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_' || !c.is_ascii())
}

fn blank(out: &mut [u8], from: usize, to: usize) {
    for c in &mut out[from..to] {
        if *c != b'\n' {
            *c = b' ';
        }
    }
}

/// `src` with comments, string literals and char literals replaced by spaces,
/// newlines kept so positions stay meaningful.
pub(crate) fn sanitize(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    while i < b.len() {
        let start = i;
        if b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i..].starts_with(b"/*") {
            let mut depth = 0;
            while i < b.len() {
                if b[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if b[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if b[i] == b'r' && (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#')) {
            let hashes = b[i + 1..].iter().take_while(|c| **c == b'#').count();
            if b.get(i + 1 + hashes) != Some(&b'"') {
                i += 1;
                continue;
            }
            let close: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', hashes))
                .collect();
            i += 2 + hashes;
            while i < b.len() && !b[i..].starts_with(&close) {
                i += 1;
            }
            i = (i + close.len()).min(b.len());
        } else if b[i] == b'"' {
            i += 1;
            while i < b.len() && b[i] != b'"' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i = (i + 1).min(b.len());
        } else if b[i] == b'\'' && (b.get(i + 1) == Some(&b'\\') || b.get(i + 2) == Some(&b'\'')) {
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i = (i + 1).min(b.len());
        } else {
            i += 1;
            continue;
        }
        blank(&mut out, start, i.min(b.len()));
    }
    String::from_utf8_lossy(&out).into_owned()
}
