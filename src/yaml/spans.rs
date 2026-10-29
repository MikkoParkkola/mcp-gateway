// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where each mapping value sits in the source text, as the parser says:
//! the byte range of every scalar that is the value of a key, by its key
//! path. An in-place edit replaces exactly that range, so where a value ends
//! is never decided by hand.

use std::ops::Range;

use granit_parser::{Event, Marker, Parser, ScalarStyle, StructureStyle};

use super::Error;

/// One scalar mapping value, by the keys from the root to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValueSpan {
    /// The decoded key texts. Only `refused` says whether the value may be
    /// edited; a caller naming a path also checks its own segments.
    pub(crate) path: Vec<String>,
    /// The scalar's own bytes, quotes included.
    pub(crate) bytes: Range<usize>,
    /// `None` when the value may be replaced in place, else why not.
    pub(crate) refused: Option<&'static str>,
}

/// An open collection. Only a block mapping with no anchor or tag, reached
/// through plain keys from a root of the same kind, is addressable.
struct Frame {
    path: Vec<String>,
    mapping: bool,
    addressable: bool,
    /// The key read and waiting for its value, and whether it is a plain
    /// key: an unquoted scalar on one line, with no anchor or tag.
    key: Option<(String, bool)>,
}

/// Every scalar mapping value in `text`, with its byte range and whether it
/// may be replaced in place. `text` passes the parser's guard first.
///
/// # Errors
///
/// The guard's refusal, a parser error, or a span the text cannot hold.
pub(crate) fn mapping_values(text: &str) -> Result<Vec<ValueSpan>, Error> {
    super::guard(text)?;
    let offsets = Bytes(text);
    let mut documents = 0;
    let mut frames: Vec<Frame> = Vec::new();
    let mut out = Vec::new();
    for item in Parser::new_from_str(text) {
        let (event, span) = item.map_err(|e| {
            let at = e.marker();
            Error::message_at("YAML syntax error", at.line(), at.col() + 1)
        })?;
        match event {
            Event::Scalar(value, style, anchor, tag) => {
                let tagged = tag.is_some() || span.tag_start.is_some();
                let Some(top) = frames.last_mut().filter(|f| f.mapping) else {
                    continue;
                };
                let Some((key, plain_key)) = top.key.take() else {
                    let plain = style == ScalarStyle::Plain && anchor == 0 && !tagged;
                    top.key = Some((value.into_owned(), plain));
                    continue;
                };
                let refused = if !top.addressable || !plain_key {
                    Some("a key on the path is not a plain key of a block mapping")
                } else if anchor != 0 || tagged {
                    Some("the value carries an anchor or a tag")
                } else {
                    None
                };
                let mut path = top.path.clone();
                path.push(key);
                let bytes = offsets.range(span.start, span.end)?;
                out.push(ValueSpan {
                    path,
                    bytes,
                    refused,
                });
            }
            Event::Alias(_) => {
                let Some(top) = frames.last_mut().filter(|f| f.mapping) else {
                    continue;
                };
                match top.key.take() {
                    None => top.key = Some((String::new(), false)),
                    Some((key, _)) => {
                        let mut path = top.path.clone();
                        path.push(key);
                        let bytes = offsets.range(span.start, span.end)?;
                        let refused = Some("the value is an alias");
                        out.push(ValueSpan {
                            path,
                            bytes,
                            refused,
                        });
                    }
                }
            }
            Event::MappingStart(style, anchor, tag) => {
                let own = style == StructureStyle::Block && anchor == 0 && tag.is_none();
                let frame = open(&mut frames, true, own);
                frames.push(frame);
            }
            Event::SequenceStart(..) => {
                let frame = open(&mut frames, false, false);
                frames.push(frame);
            }
            Event::MappingEnd | Event::SequenceEnd => {
                frames.pop();
            }
            Event::DocumentStart(..) => {
                documents += 1;
                if documents > 1 {
                    return Err(Error::message("more than one document"));
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// The frame a collection opens, from where it sits: the root, a mapping's
/// key (never addressable), a mapping's value, or a sequence item.
fn open(frames: &mut [Frame], mapping: bool, own: bool) -> Frame {
    let (path, addressable) = match frames.last_mut() {
        None => (Vec::new(), own),
        Some(parent) if parent.mapping => match parent.key.take() {
            // A collection used as a key: the value after it is refused.
            None => {
                parent.key = Some((String::new(), false));
                (Vec::new(), false)
            }
            Some((key, plain)) => {
                let mut path = parent.path.clone();
                path.push(key);
                (path, parent.addressable && plain && own)
            }
        },
        Some(parent) => (parent.path.clone(), false),
    };
    Frame {
        path,
        mapping,
        addressable: addressable && mapping,
        key: None,
    }
}

/// Byte positions of the parser's markers: its own byte offset when it gives
/// one, else counted from its character index. Nothing is allocated per
/// character, so a large file costs no more memory than its text.
pub(super) struct Bytes<'a>(pub(super) &'a str);

impl Bytes<'_> {
    pub(super) fn byte(&self, marker: Marker) -> Result<usize, Error> {
        let text = self.0;
        let at = match marker.byte_offset() {
            Some(b) => Some(b).filter(|&b| text.is_char_boundary(b)),
            None => text
                .char_indices()
                .map(|(b, _)| b)
                .chain(std::iter::once(text.len()))
                .nth(marker.index()),
        };
        // A position the text cannot hold would be a parser defect: refuse,
        // never panic on a slice.
        at.ok_or_else(|| Error::message("a parser position the text cannot hold"))
    }

    pub(super) fn range(&self, start: Marker, end: Marker) -> Result<Range<usize>, Error> {
        let (start, end) = (self.byte(start)?, self.byte(end)?);
        if start > end {
            return Err(Error::message("a parser span that ends before it starts"));
        }
        Ok(start..end)
    }
}
