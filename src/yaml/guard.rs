// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The MIK-8639 pre-parse guard: budgets and refusals checked on granit-parser's
//! events before any document is built.

use super::{Error, Limit};
use granit_parser::{ErrorKind, Event, Marker, ScanError, Tag, TokenType};
use std::collections::{HashMap, HashSet};

/// Largest text the guard lets through: 16 MiB, the protocol-import limit
/// now on every path. A text of exactly this length is accepted.
pub(crate) const MAX_YAML_BYTES: usize = 16 * 1024 * 1024;

/// Deepest nesting the guard lets through, matching the backend's own cap.
const MAX_DEPTH: usize = 128;

/// Most alias references the guard lets through in one stream.
const MAX_ALIASES: usize = 64;

/// Most `%TAG` directives the guard lets through in one input.
const MAX_TAG_DIRECTIVES: usize = 64;

/// Most alias-added bytes the guard lets one document expand to.
const MAX_EXPANSION_BYTES: u64 = 64 * 1024 * 1024;

/// Cost unit of one node towards the expansion cap.
const NODE_COST: u64 = 64;

/// Refuse hostile YAML text before it reaches the backend (MIK-8639).
///
/// The checks run in order: the size gate, the raw line-break scan, the
/// scanner-token pass (directives, names, reuse, syntax) and the event pass
/// (depth, alias count, expansion, syntax). The first refusal wins, and both
/// passes are linear in the input.
pub(super) fn guard(text: &str) -> Result<(), Error> {
    guard_inner(text).map(|_| ()).map_err(|(err, _)| err)
}

/// The guard result plus the number of parser events and scanner tokens visited.
///
/// Test-only work counter behind the linearity bar; absent from production builds.
#[cfg(test)]
pub(crate) fn guard_work(text: &str) -> (Result<(), Error>, u64) {
    match guard_inner(text) {
        Ok(work) => (Ok(()), work),
        Err((err, work)) => (Err(err), work),
    }
}

/// The guard plus its work count: tokens visited in the scanner pass and
/// events visited in the event pass. On refusal the count covers the work
/// done before the refusal fired.
fn guard_inner(text: &str) -> Result<u64, (Error, u64)> {
    if text.len() > MAX_YAML_BYTES {
        let refused = Error::refused(
            Limit::Size {
                len: text.len(),
                max: MAX_YAML_BYTES,
            },
            None,
        );
        return Err((refused, 0));
    }
    if let Some((offset, _)) = text
        .char_indices()
        .find(|(_, found)| is_disputed_break(*found))
    {
        let refused = Error::refused(Limit::LineBreak { offset }, None);
        return Err((refused, 0));
    }
    let mut work = 0u64;
    if let Err(err) = pass1(text, &mut work) {
        return Err((err, work));
    }
    if let Err(err) = pass2(text, &mut work) {
        return Err((err, work));
    }
    Ok(work)
}

/// Whether `found` is a line break libyaml sees and granit does not. Refusing
/// it fail-closed keeps a granit comment from hiding a libyaml directive.
fn is_disputed_break(found: char) -> bool {
    matches!(found, '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// Whether an anchor or alias name sits inside the grammar both parsers read
/// the same way: one or more of `[A-Za-z0-9_-]`.
fn name_in_grammar(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// A refusal pointing at `marker`: the limit built from its byte offset, or a
/// Syntax refusal at its line and column when no byte offset was recorded.
fn at_offset(marker: Marker, make: impl FnOnce(usize) -> Limit) -> Error {
    match marker.byte_offset() {
        Some(offset) => Error::refused(make(offset), None),
        None => Error::refused(
            Limit::Syntax {
                line: marker.line(),
                column: marker.col().saturating_add(1),
            },
            Some(String::from("syntax error")),
        ),
    }
}

/// The fix hint for a quoted value left unclosed or continued with too little indentation.
const QUOTED_INDENT_HINT: &str =
    "close the quote, or indent the continuation lines, or use a block scalar (| or >)";

/// A granit failure as the guard's refusal: its recursion breach is Depth,
/// every other kind is Syntax at the marker's line and 1-based column.
fn map_scan_error(scan: &ScanError) -> Error {
    let marker = scan.marker();
    if matches!(scan.kind(), ErrorKind::RecursionLimitExceeded) {
        return Error::refused(
            Limit::Depth {
                line: marker.line(),
            },
            None,
        );
    }
    let limit = Limit::Syntax {
        line: marker.line(),
        column: marker.col().saturating_add(1),
    };
    let what = syntax_what(scan.kind());
    if matches!(scan.kind(), ErrorKind::InvalidQuotedScalarIndent) {
        return Error::refused_hint(limit, Some(what), QUOTED_INDENT_HINT);
    }
    Error::refused(limit, Some(what))
}

/// The Syntax wording for a granit kind: granit's own Display, except the nine
/// data-carrying kinds and the quoted-indent kind, which get fixed text (the
/// exact `=2.0.0` pin freezes the set). Never echoes document bytes, names
/// or tags.
fn syntax_what(kind: &ErrorKind) -> String {
    match kind {
        ErrorKind::UnexpectedCharacter { .. } => String::from("unexpected character"),
        ErrorKind::Custom(..) => String::from("syntax error"),
        ErrorKind::InputIo { .. } => String::from("input could not be read"),
        ErrorKind::InputDecoding { .. } => String::from("input could not be decoded"),
        ErrorKind::MismatchedFlowCollectionEnd { .. } => String::from("mismatched bracket"),
        ErrorKind::UnclosedFlowCollection { .. } => String::from("unclosed bracket"),
        ErrorKind::InputByteLimitExceeded { .. } => String::from("input too large"),
        ErrorKind::DirectiveByteLimitExceeded { .. }
        | ErrorKind::TooManyReservedDirectiveParams { .. } => String::from("directive too large"),
        ErrorKind::InvalidQuotedScalarIndent => {
            String::from("quoted text is not closed, or continues with too little indentation,")
        }
        other => other.to_string(),
    }
}

/// First pass: scanner tokens. Counts `%TAG` directives, checks anchor and
/// alias names against the grammar both parsers share, and refuses an anchor
/// name reused within one document. Adds the tokens visited to `work`.
fn pass1(text: &str, work: &mut u64) -> Result<(), Error> {
    let scanner = granit_parser::Scanner::new(granit_parser::StrInput::new(text));
    let mut directives = 0usize;
    let mut anchors: HashSet<String> = HashSet::new();
    for item in scanner {
        *work = work.saturating_add(1);
        let token = match item {
            Ok(token) => token,
            Err(scan) => return Err(map_scan_error(&scan)),
        };
        let start = token.span().start;
        let token_type = token.token_type();
        match &token_type {
            TokenType::TagDirective(..) => {
                directives = directives.saturating_add(1);
                if directives > MAX_TAG_DIRECTIVES {
                    return Err(at_offset(start, |offset| Limit::TagDirectives {
                        max: MAX_TAG_DIRECTIVES,
                        offset,
                    }));
                }
            }
            TokenType::Anchor(name) => {
                if !name_in_grammar(name) {
                    return Err(at_offset(start, |offset| Limit::AnchorName { offset }));
                }
                if !anchors.insert(name.to_string()) {
                    return Err(at_offset(start, |offset| Limit::AnchorReuse { offset }));
                }
            }
            TokenType::Alias(name) => {
                if !name_in_grammar(name) {
                    return Err(at_offset(start, |offset| Limit::AnchorName { offset }));
                }
            }
            TokenType::DocumentStart | TokenType::DocumentEnd => {
                anchors.clear();
            }
            _ => {}
        }
    }
    Ok(())
}

/// An open collection in the expansion walk: its cost so far and its anchor id.
struct Frame {
    cost: u64,
    anchor: usize,
}

/// Add `amount` to the innermost open collection, dropping it when no
/// collection is open. Saturating throughout.
fn add_cost(stack: &mut [Frame], amount: u64) {
    if let Some(frame) = stack.last_mut() {
        frame.cost = frame.cost.saturating_add(amount);
    }
}

/// The cost of one scalar towards the expansion cap: its bytes plus one node.
fn scalar_cost(value: &str) -> u64 {
    u64::try_from(value.len()).map_or(u64::MAX, |len| len.saturating_add(NODE_COST))
}

/// The cost of a node's tag towards the expansion cap: its handle plus its
/// suffix in bytes, or 0 when untagged. Saturating throughout.
fn tag_cost(tag: Option<&Tag>) -> u64 {
    tag.map_or(0, |tag| {
        let bytes = tag.handle().len().saturating_add(tag.suffix().len());
        u64::try_from(bytes).unwrap_or(u64::MAX)
    })
}

/// Second pass: parser events. Refuses nesting past 128 levels, a 65th alias
/// anywhere in the stream, and one document's aliases expanding to 64 MiB.
/// Adds the events visited to `work`.
fn pass2(text: &str, work: &mut u64) -> Result<(), Error> {
    let mut aliases = 0usize;
    let mut expanded = 0u64;
    let mut cost: HashMap<usize, u64> = HashMap::new();
    let mut stack: Vec<Frame> = Vec::new();
    for item in granit_parser::Parser::new_from_str(text) {
        *work = work.saturating_add(1);
        let (event, span) = match item {
            Ok(pair) => pair,
            Err(scan) => return Err(map_scan_error(&scan)),
        };
        match event {
            Event::DocumentStart(..) => {
                expanded = 0;
                cost.clear();
                stack.clear();
            }
            Event::SequenceStart(_, anchor, tag) | Event::MappingStart(_, anchor, tag) => {
                stack.push(Frame {
                    cost: NODE_COST.saturating_add(tag_cost(tag.as_deref())),
                    anchor,
                });
                if stack.len() > MAX_DEPTH {
                    let line = span.start.line();
                    return Err(Error::refused(Limit::Depth { line }, None));
                }
            }
            Event::SequenceEnd | Event::MappingEnd => {
                if let Some(frame) = stack.pop() {
                    add_cost(&mut stack, frame.cost);
                    if frame.anchor != 0 {
                        cost.insert(frame.anchor, frame.cost);
                    }
                }
            }
            Event::Scalar(value, _, anchor, tag) => {
                let single = scalar_cost(&value).saturating_add(tag_cost(tag.as_deref()));
                add_cost(&mut stack, single);
                if anchor != 0 {
                    cost.insert(anchor, single);
                }
            }
            Event::Alias(id) => {
                aliases = aliases.saturating_add(1);
                if aliases > MAX_ALIASES {
                    return Err(Error::refused(Limit::Aliases { max: MAX_ALIASES }, None));
                }
                if id != 0 && stack.iter().any(|frame| frame.anchor == id) {
                    return Err(Error::refused(Limit::Expansion, None));
                }
                let single = cost.get(&id).copied().unwrap_or(NODE_COST);
                if expanded.saturating_add(single) >= MAX_EXPANSION_BYTES {
                    return Err(Error::refused(Limit::Expansion, None));
                }
                expanded = expanded.saturating_add(single);
                add_cost(&mut stack, single);
            }
            _ => {}
        }
    }
    Ok(())
}
