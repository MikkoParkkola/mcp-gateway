// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every node of a one-document YAML text, with where it sits: its path from
//! the root (keys and sequence positions), its key's bytes, and the last byte
//! of everything under it. The key editor inserts and removes whole lines
//! from these positions; it never decides where a node ends by hand.

use std::ops::Range;

use granit_parser::{Event, Parser, ScalarStyle, StructureStyle};

use super::Error;
use super::spans::Bytes;

/// One step from a node to a child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    Key(String),
    Index(usize),
}

/// What a node is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    /// A scalar or an alias; `empty` when it is a plain empty value, as in
    /// `key:` written alone.
    Scalar {
        empty: bool,
    },
    Mapping,
    Sequence,
}

/// One node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Node {
    pub(crate) path: Vec<Step>,
    pub(crate) shape: Shape,
    /// A flow collection, or a node inside one.
    pub(crate) flow: bool,
    /// An anchor, a tag or an alias on this node.
    pub(crate) decorated: bool,
    /// Every key on the path is a plain key, and no collection on the way is
    /// flow, anchored or tagged: the editor may address this node.
    pub(crate) plain: bool,
    /// The bytes of its key, for a mapping entry.
    pub(crate) key: Option<Range<usize>>,
    /// The node's own bytes: a scalar's text, quotes included; a
    /// collection's start marker.
    pub(crate) bytes: Range<usize>,
    /// Its key's first byte for a mapping entry, else its own first byte.
    pub(crate) start: usize,
    /// One past the last byte of the node and everything under it.
    pub(crate) end: usize,
}

/// An open collection.
struct Open {
    /// The collection's node in the output.
    node: usize,
    mapping: bool,
    /// A mapping's key read and waiting for its value: text, plain, bytes.
    key: Option<(String, bool, Range<usize>)>,
    /// The next position in a sequence.
    next: usize,
}

/// Every node of `text`, root first, in document order. `text` passes the
/// parser's guard first.
///
/// # Errors
///
/// The guard's refusal, a parser error, more than one document, or a span
/// the text cannot hold.
pub(crate) fn block_nodes(text: &str) -> Result<Vec<Node>, Error> {
    super::guard(text)?;
    let offsets = Bytes(text);
    let mut documents = 0;
    let mut open: Vec<Open> = Vec::new();
    let mut out: Vec<Node> = Vec::new();
    for item in Parser::new_from_str(text) {
        let (event, span) = item.map_err(|e| {
            let at = e.marker();
            Error::message_at("YAML syntax error", at.line(), at.col() + 1)
        })?;
        let bytes = offsets.range(span.start, span.end)?;
        let mapping = matches!(event, Event::MappingStart(..));
        match event {
            Event::Scalar(value, style, anchor, tag) => {
                let decorated = anchor != 0 || tag.is_some() || span.tag_start.is_some();
                if let Some(top) = open.last_mut().filter(|o| o.mapping && o.key.is_none()) {
                    let plain = style == ScalarStyle::Plain && !decorated && !value.contains('\n');
                    top.key = Some((value.into_owned(), plain, bytes));
                    continue;
                }
                // An implicit null (`key:` alone) has no text of its own, whatever
                // value the parser reports for it; an explicit `~` or `null` does.
                let empty = style == ScalarStyle::Plain
                    && !decorated
                    && text.get(bytes.clone()).is_none_or(|t| t.trim().is_empty());
                push(
                    &mut out,
                    &mut open,
                    Shape::Scalar { empty },
                    false,
                    decorated,
                    bytes,
                );
            }
            Event::Alias(_) => {
                if let Some(top) = open.last_mut().filter(|o| o.mapping && o.key.is_none()) {
                    top.key = Some((String::new(), false, bytes));
                    continue;
                }
                push(
                    &mut out,
                    &mut open,
                    Shape::Scalar { empty: false },
                    false,
                    true,
                    bytes,
                );
            }
            Event::MappingStart(style, anchor, tag) | Event::SequenceStart(style, anchor, tag) => {
                let shape = if mapping {
                    Shape::Mapping
                } else {
                    Shape::Sequence
                };
                let decorated = anchor != 0 || tag.is_some() || span.tag_start.is_some();
                let flow = style == StructureStyle::Flow;
                // A collection used as a key: what follows it is not addressable.
                if let Some(top) = open.last_mut().filter(|o| o.mapping && o.key.is_none()) {
                    top.key = Some((String::new(), false, bytes.clone()));
                }
                let node = push(&mut out, &mut open, shape, flow, decorated, bytes);
                open.push(Open {
                    node,
                    mapping,
                    key: None,
                    next: 0,
                });
            }
            Event::MappingEnd | Event::SequenceEnd => {
                open.pop();
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

/// Add a node under the innermost open collection (or as the root), and
/// stretch every open ancestor's end over it.
fn push(
    out: &mut Vec<Node>,
    open: &mut [Open],
    shape: Shape,
    flow: bool,
    decorated: bool,
    bytes: Range<usize>,
) -> usize {
    let (path, key, inherited_flow, plain) = match open.last_mut() {
        None => (Vec::new(), None, false, !decorated && !flow),
        Some(parent) => {
            let up = &out[parent.node];
            let usable = up.plain && !up.flow && !up.decorated;
            let mut path = up.path.clone();
            let (key, key_plain) = if parent.mapping {
                let (text, key_plain, key_bytes) =
                    parent
                        .key
                        .take()
                        .unwrap_or((String::new(), false, bytes.clone()));
                path.push(Step::Key(text));
                (Some(key_bytes), key_plain)
            } else {
                path.push(Step::Index(parent.next));
                parent.next += 1;
                (None, true)
            };
            (
                path,
                key,
                up.flow,
                usable && key_plain && !decorated && !flow,
            )
        }
    };
    let start = key
        .as_ref()
        .map_or(bytes.start, |k| k.start.min(bytes.start));
    // An empty value (`key:` alone) ends with its key: the parser may place
    // its empty span at the next line.
    let end = match (&key, shape) {
        (Some(k), Shape::Scalar { empty: true }) => k.end,
        _ => bytes.end,
    };
    for o in open.iter() {
        let ancestor = &mut out[o.node];
        ancestor.end = ancestor.end.max(end);
    }
    out.push(Node {
        path,
        shape,
        flow: flow || inherited_flow,
        decorated,
        plain,
        key,
        bytes,
        start,
        end,
    });
    out.len() - 1
}
