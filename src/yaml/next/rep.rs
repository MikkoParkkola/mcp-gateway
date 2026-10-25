// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The parse representation (design section 2): each document's nodes as
//! the parser produced them, before any destination decides what they
//! mean. Scalars stay unresolved, a repeated mapping key keeps both
//! entries, every node keeps its position, and an alias stays a reference
//! to its anchor, so each destination counts its own expansions against the
//! replaced backend's budget (D16).

use granit_parser::{Event, Parser, ScalarStyle};

use super::Error;

/// A node's place in its document's arena.
pub(crate) type NodeId = usize;

/// Where a node starts: line 1-based, column 1-based.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pos {
    pub(crate) line: usize,
    pub(crate) column: usize,
}

#[derive(Clone, Debug)]
pub(crate) enum Kind {
    /// `text` as decoded; `plain` when unquoted; `tag` as the parser
    /// resolved it (`tag:yaml.org,2002:str`, `!custom`, or a URI);
    /// `empty` when the parser synthesized it (a zero-width span).
    Scalar {
        text: String,
        plain: bool,
        /// A literal block (`|`): a typed read accepts it under its own
        /// core tag (`!!int |`), as the replaced backend did.
        literal: bool,
        tag: Option<String>,
        empty: bool,
    },
    Seq {
        tag: Option<String>,
        items: Vec<NodeId>,
    },
    /// Every entry in order, a repeated key included: the destination
    /// decides (D2 to D4).
    Map {
        tag: Option<String>,
        entries: Vec<(NodeId, NodeId)>,
    },
    /// A use of the anchored node.
    Alias(NodeId),
}

#[derive(Clone, Debug)]
pub(crate) struct Node {
    pub(crate) kind: Kind,
    pub(crate) pos: Pos,
}

/// One document. `events` is the count the replaced backend kept for it
/// (scalars, collection starts and ends, aliases; at least one), the base
/// of its alias budget.
#[derive(Debug)]
pub(crate) struct Document {
    pub(crate) nodes: Vec<Node>,
    pub(crate) root: NodeId,
    pub(crate) events: usize,
}

impl Pos {
    /// `text` refused at this place.
    pub(crate) fn refuse(self, text: impl Into<String>) -> Error {
        Error::message_at(text, self.line, self.column)
    }
}

impl Document {
    pub(crate) fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id]
    }

    /// The node `id` stands for, through any aliases; each alias crossed
    /// costs one unit of `budget`.
    pub(crate) fn resolve(&self, mut id: NodeId, budget: &mut Budget) -> Result<NodeId, Error> {
        while let Kind::Alias(target) = self.nodes[id].kind {
            budget.jump()?;
            id = target;
        }
        Ok(id)
    }
}

/// The replaced backend's alias rule: refuse once a document's alias
/// expansions exceed a hundred times its event count. Every expansion a
/// read follows counts; a field the target ignores is skipped without
/// following its aliases, as the replaced backend skipped it.
pub(crate) struct Budget {
    jumps: usize,
    limit: usize,
}

impl Budget {
    pub(crate) fn for_document(document: &Document) -> Self {
        Budget {
            jumps: 0,
            limit: document.events.saturating_mul(100),
        }
    }

    pub(crate) fn jump(&mut self) -> Result<(), Error> {
        self.jumps += 1;
        if self.jumps > self.limit {
            return Err(Error::message("repetition limit exceeded"));
        }
        Ok(())
    }
}

fn tag_text(tag: Option<&granit_parser::Tag>) -> Option<String> {
    tag.map(|t| format!("{}{}", t.handle(), t.suffix()))
}

/// A parser refusal, which keeps only its place: parser text never
/// reaches the error (design section 3).
fn refused_at(at: Pos) -> Error {
    Error::message_at("YAML syntax error", at.line, at.column)
}

fn pos(marker: granit_parser::Marker) -> Pos {
    Pos {
        line: marker.line(),
        column: marker.col().saturating_add(1),
    }
}

/// Where each line starts, as a byte and a character offset, built once per
/// parse so placing a node costs a binary search, not a scan of the text
/// before it.
struct Lines(Vec<(usize, usize)>);

impl Lines {
    fn new(text: &str) -> Self {
        let mut starts = vec![(0, 0)];
        let mut iter = text.char_indices().enumerate().peekable();
        while let Some((chars, (byte, ch))) = iter.next() {
            // `\n`, `\r` and `\r\n` each end a line, as the parser counts.
            let crlf = ch == '\r' && iter.peek().is_some_and(|(_, (_, next))| *next == '\n');
            if (ch == '\n' || ch == '\r') && !crlf {
                starts.push((byte + 1, chars + 1));
            }
        }
        Lines(starts)
    }

    /// The place of the character at `byte`, which is `chars` characters
    /// into the text; both 1-based.
    fn place(&self, byte: usize, chars: usize) -> Pos {
        let line = self.0.partition_point(|&(start, _)| start <= byte);
        let (_, line_chars) = self.0[line - 1];
        Pos {
            line,
            column: chars - line_chars + 1,
        }
    }
}

/// Where the replaced backend placed a node: at its first property (`!tag`
/// or `&anchor`) when it has `properties` of them, rather than at the
/// value after them; and an empty value just after the indicator before it
/// (`v:` places the empty value at the column after `:`). `start` is the
/// parser's span start; every scan here is short, back over one token or
/// one run of spaces.
/// What a node carries before its value.
#[derive(Clone, Copy)]
struct Properties {
    tagged: bool,
    anchored: bool,
}

/// What kind of value a node starts with, for its place.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// A value the parser synthesized (`v:` with nothing after it).
    Empty,
    /// A block scalar (`|` or `>`).
    Block,
    /// Anything else.
    Other,
}

fn node_place(
    text: &str,
    lines: &Lines,
    span: &granit_parser::Span,
    properties: Properties,
    shape: Shape,
) -> Pos {
    let Properties { tagged, anchored } = properties;
    // The parser marks where a tag starts when it is not where the value
    // does (`v: !t` above its mapping); an anchor before it is found by
    // scanning back from there.
    let (start, properties) = match (tagged, span.tag_start) {
        (true, Some(tag)) => (tag, usize::from(anchored)),
        _ => (span.start, usize::from(tagged) + usize::from(anchored)),
    };
    let fallback = pos(start);
    let Some(start_byte) = start.byte_offset().filter(|b| text.is_char_boundary(*b)) else {
        return fallback;
    };
    // A place at `byte`, either side of the span start; `chars` follows it.
    let at = |byte: usize| {
        let chars = if byte <= start_byte {
            start.index() - text[byte..start_byte].chars().count()
        } else {
            start.index() + text[start_byte..byte].chars().count()
        };
        lines.place(byte, chars)
    };
    let mut byte = start_byte;
    if shape == Shape::Empty {
        // The parser starts an empty value's span on its indicator (`:` or
        // `-`), or after the space that follows it.
        let on_indicator = text[byte..].starts_with([':', '-']);
        if tagged || anchored {
            // Placed at its first property (`v: !t`), which follows the
            // indicator when the span sits on it.
            if on_indicator {
                let rest = &text[byte + 1..];
                let pad = rest.len() - rest.trim_start_matches([' ', '\t']).len();
                return at(byte + 1 + pad);
            }
        } else {
            return if on_indicator {
                at(byte + 1)
            } else {
                at(text[..byte].trim_end().len())
            };
        }
    }
    // A block scalar (`|` or `>`) is placed at its indicator, the last token
    // of the line before its content once a trailing comment is cut off.
    if shape == Shape::Block {
        let before = text[..byte].trim_end();
        let line_start = before.rfind(['\n', '\r']).map_or(0, |i| i + 1);
        let line = &before[line_start..];
        let code = line
            .find(" #")
            .or_else(|| line.find("\t#"))
            .map_or(line, |i| &line[..i])
            .trim_end();
        let token = code.rfind(char::is_whitespace).map_or(0, |i| {
            i + code[i..].chars().next().map_or(1, char::len_utf8)
        });
        if code[token..].starts_with(['|', '>']) {
            byte = line_start + token;
        }
    }
    if properties == 0 {
        return if byte == start_byte {
            fallback
        } else {
            at(byte)
        };
    }
    for _ in 0..properties {
        let before = text[..byte].trim_end_matches([' ', '\t']);
        let token = before
            .rfind(|c: char| c.is_whitespace() || matches!(c, '[' | '{' | ','))
            .map_or(0, |i| {
                i + before[i..].chars().next().map_or(1, char::len_utf8)
            });
        if before[token..].starts_with(['!', '&']) {
            byte = token;
        } else {
            break;
        }
    }
    at(byte)
}

/// An open collection while its events arrive.
struct Open {
    id: NodeId,
    pending_key: Option<NodeId>,
}

/// Every document in `text`, in order. The guard has already accepted
/// `text` with this same parser, so a parser error here is not expected;
/// it is still refused, with its position only.
#[allow(
    clippy::too_many_lines,
    reason = "one match over the parser's event kinds; splitting it scatters the arena state"
)]
pub(crate) fn parse(text: &str) -> Result<Vec<Document>, Error> {
    let mut documents = Vec::new();
    let mut nodes: Vec<Node> = Vec::new();
    let mut open: Vec<Open> = Vec::new();
    let mut anchors: std::collections::HashMap<usize, NodeId> = std::collections::HashMap::new();
    let mut root: Option<NodeId> = None;
    let mut events = 0usize;
    let lines = Lines::new(text);
    for item in Parser::new_from_str(text) {
        let (event, span) = item.map_err(|e| refused_at(pos(*e.marker())))?;
        let at = pos(span.start);
        let mut done: Option<NodeId> = None;
        match event {
            Event::DocumentStart(..) => events = 0,
            Event::DocumentEnd => {
                let root = root.take().unwrap_or_else(|| {
                    nodes.push(Node {
                        kind: Kind::Scalar {
                            text: String::new(),
                            plain: true,
                            literal: false,
                            tag: None,
                            empty: true,
                        },
                        pos: at,
                    });
                    nodes.len() - 1
                });
                documents.push(Document {
                    nodes: std::mem::take(&mut nodes),
                    root,
                    events: events.max(1),
                });
                anchors.clear();
            }
            Event::Scalar(value, style, anchor, tag) => {
                events += 1;
                let empty = span.start.index() == span.end.index();
                nodes.push(Node {
                    kind: Kind::Scalar {
                        text: value.into_owned(),
                        plain: style == ScalarStyle::Plain,
                        literal: style == ScalarStyle::Literal,
                        tag: tag_text(tag.as_deref()),
                        empty,
                    },
                    pos: node_place(
                        text,
                        &lines,
                        &span,
                        Properties {
                            tagged: tag.is_some(),
                            anchored: anchor != 0,
                        },
                        if empty {
                            Shape::Empty
                        } else if matches!(style, ScalarStyle::Literal | ScalarStyle::Folded) {
                            Shape::Block
                        } else {
                            Shape::Other
                        },
                    ),
                });
                let id = nodes.len() - 1;
                if anchor != 0 {
                    anchors.insert(anchor, id);
                }
                done = Some(id);
            }
            Event::SequenceStart(_, anchor, tag) => {
                events += 1;
                nodes.push(Node {
                    kind: Kind::Seq {
                        tag: tag_text(tag.as_deref()),
                        items: Vec::new(),
                    },
                    pos: node_place(
                        text,
                        &lines,
                        &span,
                        Properties {
                            tagged: tag.is_some(),
                            anchored: anchor != 0,
                        },
                        Shape::Other,
                    ),
                });
                // Registered at the start, as the replaced backend did, so an
                // alias inside its own anchor refers to it.
                if anchor != 0 {
                    anchors.insert(anchor, nodes.len() - 1);
                }
                open.push(Open {
                    id: nodes.len() - 1,
                    pending_key: None,
                });
            }
            Event::MappingStart(_, anchor, tag) => {
                events += 1;
                nodes.push(Node {
                    kind: Kind::Map {
                        tag: tag_text(tag.as_deref()),
                        entries: Vec::new(),
                    },
                    pos: node_place(
                        text,
                        &lines,
                        &span,
                        Properties {
                            tagged: tag.is_some(),
                            anchored: anchor != 0,
                        },
                        Shape::Other,
                    ),
                });
                if anchor != 0 {
                    anchors.insert(anchor, nodes.len() - 1);
                }
                open.push(Open {
                    id: nodes.len() - 1,
                    pending_key: None,
                });
            }
            Event::SequenceEnd | Event::MappingEnd => {
                events += 1;
                done = open.pop().map(|o| o.id);
            }
            Event::Alias(anchor) => {
                events += 1;
                let target = *anchors
                    .get(&anchor)
                    .ok_or_else(|| at.refuse("unknown anchor"))?;
                nodes.push(Node {
                    kind: Kind::Alias(target),
                    pos: at,
                });
                done = Some(nodes.len() - 1);
            }
            _ => {}
        }
        let Some(id) = done else { continue };
        let Some(parent) = open.last_mut() else {
            root = Some(id);
            continue;
        };
        match &mut nodes[parent.id].kind {
            Kind::Seq { items, .. } => items.push(id),
            Kind::Map { entries, .. } => match parent.pending_key.take() {
                None => parent.pending_key = Some(id),
                Some(key) => entries.push((key, id)),
            },
            Kind::Scalar { .. } | Kind::Alias(_) => {}
        }
    }
    // An empty stream is one null document, as the replaced backend read it.
    if documents.is_empty() {
        documents.push(Document {
            nodes: vec![Node {
                kind: Kind::Scalar {
                    text: String::new(),
                    plain: true,
                    literal: false,
                    tag: None,
                    empty: true,
                },
                pos: Pos { line: 1, column: 1 },
            }],
            root: 0,
            events: 1,
        });
    }
    Ok(documents)
}

#[cfg(test)]
mod tests {
    use super::{Kind, Pos, parse};

    fn value_place(text: &str) -> (Pos, bool) {
        let documents = parse(text).expect("parses");
        let document = &documents[0];
        let Kind::Map { entries, .. } = &document.node(document.root).kind else {
            panic!("a mapping root");
        };
        let node = document.node(entries[0].1);
        let empty = matches!(node.kind, Kind::Scalar { empty: true, .. });
        (node.pos, empty)
    }

    /// The replaced backend's places: a tagged value at its tag, an empty
    /// value just after its `:`.
    #[test]
    fn nodes_are_placed_as_the_replaced_backend_placed_them() {
        assert_eq!(
            value_place("v: !!map {a: 1}\n").0,
            Pos { line: 1, column: 4 }
        );
        assert_eq!(value_place("v: \n"), (Pos { line: 1, column: 3 }, true));
        assert_eq!(value_place("v:\n").0, Pos { line: 1, column: 3 });
        assert_eq!(value_place("v: x\n").0, Pos { line: 1, column: 4 });
    }

    /// Placing a tagged node costs a lookup, not a scan of the text before
    /// it: 200,000 tagged items parse well inside a 10 s budget, and the last
    /// is still placed at its tag. A scan per node would take hours here.
    #[test]
    fn placing_many_tagged_nodes_stays_linear() {
        const ITEMS: usize = 200_000;
        let text = "- !t x\n".repeat(ITEMS);
        let started = std::time::Instant::now();
        let documents = parse(&text).expect("parses");
        let elapsed = started.elapsed();
        let document = &documents[0];
        let Kind::Seq { items, .. } = &document.node(document.root).kind else {
            panic!("a sequence root");
        };
        assert_eq!(items.len(), ITEMS);
        let last = document.node(items[ITEMS - 1]).pos;
        assert_eq!(
            last,
            Pos {
                line: ITEMS,
                column: 3
            }
        );
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "took {elapsed:?}"
        );
    }
}
