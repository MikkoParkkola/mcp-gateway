// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Byte-level reading of JSON text: where a string literal ends, what an
//! escape stands for, and where each literal of a document lies. Shared by
//! the credential redactor (MIK-8745) and the relay's delivered-text reader,
//! so both read a JSON escape by one rule.

/// The content of one string literal in a JSON document: the bytes between
/// its quotes, whether it is an object key, and which object or array holds
/// it (a number unique within the document; keys of one object share it).
pub(crate) struct Literal {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) key: bool,
    pub(crate) container: usize,
}

/// Every string literal of `text`, in order. `text` must be a JSON document
/// `serde_json` has accepted: outside a literal such text holds no `"`, so
/// each one found opens a literal.
pub(crate) fn string_literals(text: &str) -> Vec<Literal> {
    // Sized from the quotes, two a literal (an escaped one only adds room):
    // collected by doubling, the old and new buffers would both be live at
    // the last growth, half again the list's own size (MIK-8774).
    let mut out = Vec::with_capacity(text.bytes().filter(|&b| b == b'"').count() / 2);
    out.extend(literals(text));
    out
}

/// [`string_literals`] one at a time, holding only the open containers, so a
/// document over the redactor's size cap is walked without a list (MIK-8774).
pub(crate) fn literals(text: &str) -> impl Iterator<Item = Literal> + '_ {
    // Open containers, innermost last; the bottom entry is the top level.
    let (mut open_containers, mut opened) = (vec![0], 0);
    let mut at = 0;
    std::iter::from_fn(move || {
        let open = text[at..].find('"')?;
        for byte in text[at..at + open].bytes() {
            match byte {
                b'{' | b'[' => {
                    opened += 1;
                    open_containers.push(opened);
                }
                b'}' | b']' => {
                    open_containers.pop();
                }
                _ => {}
            }
        }
        let start = at + open + 1;
        let end = start + closing_quote(&text[start..])?;
        let key = text[end + 1..].trim_start().starts_with(':');
        let container = open_containers.last().copied().unwrap_or(0);
        at = end + 1;
        Some(Literal {
            start,
            end,
            key,
            container,
        })
    })
}

/// The byte ranges, offset by `base`, of the escapes in `content`, a string
/// literal's content: two bytes for `\x`, six for `\uXXXX`, twelve for a
/// surrogate pair.
pub(crate) fn escapes(content: &str, base: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(slash) = content[at..].find('\\') {
        let from = at + slash;
        let (_, used) = escape_at(&content[from..]);
        // Valid JSON has no malformed escape; one is still at least `\` and its byte.
        let to = (from + used.max(2)).min(content.len());
        out.push((base + from, base + to));
        at = to;
    }
    out
}

/// The byte offset of the first unescaped `"` in `rest`.
pub(crate) fn closing_quote(rest: &str) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in rest.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return Some(i),
            _ => {}
        }
    }
    None
}

/// The char the escape at the start of `escape` stands for, and its length
/// in bytes; `None` keeps those bytes as written.
pub(crate) fn escape_at(escape: &str) -> (Option<char>, usize) {
    let simple = |c| (Some(c), 2);
    match escape.as_bytes().get(1) {
        Some(b'n') => simple('\n'),
        Some(b't') => simple('\t'),
        Some(b'r') => simple('\r'),
        Some(b'"') => simple('"'),
        Some(b'\\') => simple('\\'),
        Some(b'/') => simple('/'),
        Some(b'b') => simple('\u{8}'),
        Some(b'f') => simple('\u{c}'),
        Some(b'u') => match hex4(escape, 2) {
            Some(high @ 0xD800..=0xDBFF) => match (escape.get(6..8), hex4(escape, 8)) {
                (Some("\\u"), Some(low @ 0xDC00..=0xDFFF)) => (
                    char::from_u32(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)),
                    12,
                ),
                _ => (None, 6),
            },
            Some(code) => (char::from_u32(code), 6),
            None => (None, 1),
        },
        _ => (None, 1),
    }
}

/// The four hex digits at `at` of `text`, as a number.
fn hex4(text: &str, at: usize) -> Option<u32> {
    let digits = text.get(at..at + 4)?;
    digits
        .bytes()
        .all(|b| b.is_ascii_hexdigit())
        .then(|| u32::from_str_radix(digits, 16).ok())
        .flatten()
}

/// `lit`'s content decoded, quotes included in the parse, so JSON escapes
/// read as the characters they stand for.
pub(crate) fn decoded(text: &str, lit: &Literal) -> Option<String> {
    serde_json::from_str::<String>(&text[lit.start - 1..=lit.end]).ok()
}

/// The byte range of `lit`'s content with JSON whitespace, raw or escaped
/// (`\n`, `\t`, `\r`), trimmed from both ends.
pub(crate) fn trimmed_content(text: &str, lit: &Literal) -> (usize, usize) {
    let bytes = text.as_bytes();
    let (mut start, mut end) = (lit.start, lit.end);
    loop {
        if start < end && bytes[start].is_ascii_whitespace() {
            start += 1;
        } else if start + 1 < end
            && bytes[start] == b'\\'
            && matches!(bytes[start + 1], b'n' | b't' | b'r')
        {
            start += 2;
        } else {
            break;
        }
    }
    loop {
        if end > start && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        } else if end >= start + 2
            && bytes[end - 2] == b'\\'
            && matches!(bytes[end - 1], b'n' | b't' | b'r')
        {
            end -= 2;
        } else {
            break;
        }
    }
    (start, end)
}
