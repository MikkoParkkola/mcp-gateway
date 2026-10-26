// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Byte-level reading of JSON text: where a string literal ends, what an
//! escape stands for, and where each literal of a document lies. Shared by
//! the credential redactor (MIK-8745) and the relay's delivered-text reader,
//! so both read a JSON escape by one rule.

/// The content of one string literal in a JSON document: the bytes between
/// its quotes, whether it is an object key, and which object or array holds
/// it (a number unique within the document; keys of one object share it).
/// Offsets are kept in 32 bits, so a literal costs 16 bytes, half the
/// redactor's per-literal bookkeeping over the cap (MIK-8774); a text
/// past [`fits_offsets`] is never walked.
pub(crate) struct Literal {
    start: u32,
    end: u32,
    container: u32,
    pub(crate) key: bool,
}

impl Literal {
    /// Where the content starts, just after the opening quote.
    pub(crate) fn start(&self) -> usize {
        self.start as usize
    }

    /// Where the content ends, at the closing quote.
    pub(crate) fn end(&self) -> usize {
        self.end as usize
    }

    /// The object or array that holds the literal.
    pub(crate) fn container(&self) -> usize {
        self.container as usize
    }
}

/// Whether every offset in a text of `len` bytes fits a [`Literal`]: callers
/// leave a longer text to the whole-value path (4 GiB, far over any body
/// limit the gateway accepts).
pub(crate) fn fits_offsets(len: usize) -> bool {
    u32::try_from(len).is_ok()
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
        // A text past `fits_offsets` ends the walk rather than wrap an offset.
        Some(Literal {
            start: u32::try_from(start).ok()?,
            end: u32::try_from(end).ok()?,
            container: u32::try_from(container).ok()?,
            key,
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
    serde_json::from_str::<String>(&text[lit.start() - 1..=lit.end()]).ok()
}

/// The byte range of `lit`'s content with JSON whitespace, raw or escaped
/// (`\n`, `\t`, `\r`), trimmed from both ends.
pub(crate) fn trimmed_content(text: &str, lit: &Literal) -> (usize, usize) {
    let bytes = text.as_bytes();
    let (mut start, mut end) = (lit.start(), lit.end());
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

/// Whether `text` is a JSON object, array or string that `serde_json` reads
/// into a [`serde_json::Value`]. The same parser runs, so it fails where that
/// read fails (an escape that decodes to no character, a number out of range,
/// nesting past the recursion limit, bytes after the document), but nothing
/// is built: on a 1 MiB document the tree cost several times the scan.
pub(crate) fn is_document(text: &str) -> bool {
    let opens = matches!(
        text.trim_start().as_bytes().first(),
        Some(b'{' | b'[' | b'"')
    );
    if !opens {
        return false;
    }
    match serde_json::from_str::<Read>(text) {
        Ok(Read::Plain) => true,
        // `Value` reads such an object as the document its value spells, so
        // only that read can say what it is.
        Ok(Read::RawToken) => serde_json::from_str::<serde_json::Value>(text)
            .is_ok_and(|value| value.is_object() || value.is_array() || value.is_string()),
        Err(_) => false,
    }
}

/// The key `serde_json`'s `raw_value` feature gives meaning to when it opens
/// an object read into a `Value`.
const RAW_VALUE_TOKEN: &str = "$serde_json::private::RawValue";

/// What reading a value as `Value` would read, kept as nothing but whether an
/// object opened with [`RAW_VALUE_TOKEN`] anywhere inside it.
enum Read {
    Plain,
    RawToken,
}

impl Read {
    fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Plain, Self::Plain) => Self::Plain,
            _ => Self::RawToken,
        }
    }
}

impl<'de> serde::Deserialize<'de> for Read {
    fn deserialize<D: serde::Deserializer<'de>>(reader: D) -> Result<Self, D::Error> {
        reader.deserialize_any(ReadVisitor)
    }
}

struct ReadVisitor;

impl<'de> serde::de::Visitor<'de> for ReadVisitor {
    type Value = Read;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Read, E> {
        Ok(Read::Plain)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Read, E> {
        Ok(Read::Plain)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Read, E> {
        Ok(Read::Plain)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Read, E> {
        Ok(Read::Plain)
    }

    fn visit_str<E>(self, _: &str) -> Result<Read, E> {
        Ok(Read::Plain)
    }

    fn visit_unit<E>(self) -> Result<Read, E> {
        Ok(Read::Plain)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Read, A::Error> {
        let mut read = Read::Plain;
        while let Some(item) = seq.next_element::<Read>()? {
            read = read.or(item);
        }
        Ok(read)
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Read, A::Error> {
        let mut read = Read::Plain;
        let mut first = true;
        while let Some(token) = map.next_key::<IsToken>()? {
            if first && token.0 {
                read = Read::RawToken;
            }
            first = false;
            read = read.or(map.next_value::<Read>()?);
        }
        Ok(read)
    }
}

/// A key, decoded by the parser, compared with [`RAW_VALUE_TOKEN`] and kept
/// as nothing else.
struct IsToken(bool);

impl<'de> serde::Deserialize<'de> for IsToken {
    fn deserialize<D: serde::Deserializer<'de>>(reader: D) -> Result<Self, D::Error> {
        reader.deserialize_str(IsTokenVisitor)
    }
}

struct IsTokenVisitor;

impl serde::de::Visitor<'_> for IsTokenVisitor {
    type Value = IsToken;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an object key")
    }

    fn visit_str<E>(self, key: &str) -> Result<IsToken, E> {
        Ok(IsToken(key == RAW_VALUE_TOKEN))
    }
}
