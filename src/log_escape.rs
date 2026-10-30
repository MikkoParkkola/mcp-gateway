// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The text log layer's one way in: every text layer is built by
//! [`escaping`], so no field value, message or metadata can write a control
//! character, and so a forged line, into the operator's log.
//!
//! Two hooks, one escape rule. The library already escapes ESC and the C1
//! controls in the message and in an error with its sources, but writes a
//! `%` or `?` field value raw. The field formatter escapes those values, so a
//! value cannot even add a colour, and leaves layout, colours and a clean
//! line the library's own, byte for byte. The writer then escapes, on the
//! whole line, every hostile character the library leaves (a newline in a
//! message or an error) and what no field formatter sees (an event's
//! target, which a bridged `log` record sets), except the line's own final
//! newline and the formatter's colour codes.

use std::fmt as stdfmt;
use std::io;

use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::field::{MakeVisitor, VisitFmt, VisitOutput};
use tracing_subscriber::fmt::format::{DefaultFields, DefaultVisitor, Format, Full, Writer};
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::fmt::{self, MakeWriter};
use tracing_subscriber::registry::LookupSpan;

/// The text layer `base`, with its output escaped.
pub(crate) fn escaping<S, T, W>(
    base: fmt::Layer<S, DefaultFields, Format<Full, T>, W>,
) -> impl Layer<S> + Send + Sync + 'static
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    T: FormatTime + Send + Sync + 'static,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    // The message and errors rely on the library's own escape: keep it on,
    // whatever the base layer was built with.
    base.with_ansi_sanitization(true)
        .fmt_fields(EscapingFields)
        .map_writer(EscapingWriter)
}

/// Characters a log line must not carry raw: every C0 and C1 control and
/// DEL, the line and paragraph separators, and the bidirectional controls
/// that reorder what a viewer shows.
fn hostile(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}'
                | '\u{2029}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{061c}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// `text` with each hostile character written as its escape (`\n`,
/// `\u{1b}`, `\u{202e}`); every other character, backslashes and quotes
/// included, is left as it is, so a clean value is unchanged.
fn escaped(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.chars().any(hostile) {
        return text.into();
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if !hostile(c) {
            out.push(c);
        } else if c.is_control() {
            out.extend(c.escape_debug());
        } else {
            out.extend(c.escape_unicode());
        }
    }
    out.into()
}

/// The field formatter: the library's own, fed escaped `%` and `?` values.
struct EscapingFields;

impl<'w> MakeVisitor<Writer<'w>> for EscapingFields {
    type Visitor = EscapingVisitor<'w>;

    fn make_visitor(&self, target: Writer<'w>) -> Self::Visitor {
        EscapingVisitor(DefaultVisitor::new(target, true))
    }
}

struct EscapingVisitor<'w>(DefaultVisitor<'w>);

impl Visit for EscapingVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn stdfmt::Debug) {
        let rendered = format!("{value:?}");
        self.0
            .record_debug(field, &format_args!("{}", escaped(&rendered)));
    }

    // A str field is written with `{:?}`, which escapes, and a str message
    // goes through the library's own escape and then the writer.
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.record_str(field, value);
    }

    // The library writes an error and its sources through its own escape;
    // the writer handles what that escape leaves (a newline).
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.0.record_error(field, value);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.record_i64(field, value);
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.record_u64(field, value);
    }
    fn record_i128(&mut self, field: &Field, value: i128) {
        self.0.record_i128(field, value);
    }
    fn record_u128(&mut self, field: &Field, value: u128) {
        self.0.record_u128(field, value);
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.0.record_f64(field, value);
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.record_bool(field, value);
    }
    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        self.0.record_bytes(field, value);
    }
}

impl VisitOutput<stdfmt::Result> for EscapingVisitor<'_> {
    fn finish(self) -> stdfmt::Result {
        self.0.finish()
    }
}

impl VisitFmt for EscapingVisitor<'_> {
    fn writer(&mut self) -> &mut dyn stdfmt::Write {
        self.0.writer()
    }
}

/// The writer: what the field formatter never sees.
struct EscapingWriter<M>(M);

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for EscapingWriter<M> {
    type Writer = EscapedLine<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        EscapedLine(self.0.make_writer())
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        EscapedLine(self.0.make_writer_for(meta))
    }
}

/// One event's line. The fmt layer formats a whole event into one buffer and
/// writes it with one `write_all` (tracing-subscriber 0.3.23,
/// fmt_layer.rs:1049-1050); `write` takes the whole slice, so its last byte
/// is the line's own newline.
struct EscapedLine<W>(W);

impl<W: io::Write> io::Write for EscapedLine<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let line = String::from_utf8_lossy(bytes);
        let (body, end) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (&*line, ""),
        };
        let mut out = String::with_capacity(bytes.len());
        let mut rest = body;
        while let Some(c) = rest.chars().next() {
            let sgr = (c == '\x1b').then(|| colour_code(rest)).flatten();
            if let Some(len) = sgr {
                out.push_str(&rest[..len]);
                rest = &rest[len..];
                continue;
            }
            out.push_str(&escaped(&rest[..c.len_utf8()]));
            rest = &rest[c.len_utf8()..];
        }
        out.push_str(end);
        self.0.write_all(out.as_bytes())?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// The length of a colour code at the start of `s`, if it is one the
/// formatter itself writes (tracing-subscriber 0.3.23 fmt/format/mod.rs:
/// reset, bold, dimmed, italic, and the five level colours). Any other
/// sequence, such as one that conceals text, is escaped.
fn colour_code(s: &str) -> Option<usize> {
    const OWN: [&str; 9] = ["0", "1", "2", "3", "31", "32", "33", "34", "35"];
    let tail = s.strip_prefix("\x1b[")?;
    let (params, _) = tail.split_once('m')?;
    OWN.contains(&params).then_some(2 + params.len() + 1)
}

#[cfg(test)]
#[path = "log_escape_tests.rs"]
mod tests;
