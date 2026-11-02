// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A whole string list set at a path (MIK-9172), written as one inline list.
//! What the file holds there now picks the edit: absent, the key is inserted
//! with the list; `key:` alone, the list goes after the colon; `~`, `null`,
//! or a one-line inline list, its span is replaced; a block list, the item
//! lines go and the list is written after the key's colon. Anything else is
//! refused, naming why. The meaning and bytes proofs still judge the result.

use crate::yaml::{Node, Shape, Value};

use super::shape::{self, CommentRule, Lines, Span};
use super::{ComputeRefusal, FieldPath, GiveUp, Segment, give_up, unprovable, write_value};

/// Set the list at `path` to `items`; `value` is their inline text.
pub(super) fn set(
    lines: &mut Lines,
    path: &FieldPath,
    items: &[String],
    value: &str,
) -> Result<(), ComputeRefusal> {
    let text = lines.text();
    let nodes = shape::nodes(&text)?;
    let Some((Segment::Key(key), parent_path)) = path.0.split_last() else {
        return Err(give_up(
            shape::refusal_code(&nodes, &path.0),
            "a list is set at a key, not at a list position",
        ));
    };
    let Some(node) = shape::find(&nodes, &path.0) else {
        return write_value(lines, path, value);
    };
    // Checked before every branch, the empty values included: the list's own
    // key written plain, under an addressable block mapping; the list
    // undecorated.
    let parent = shape::find(&nodes, parent_path);
    if !parent.is_some_and(|p| p.plain && !p.flow && !p.decorated && p.shape == Shape::Mapping) {
        return Err(give_up(
            shape::refusal_code(&nodes, parent_path),
            "the list's mapping cannot be edited in place",
        ));
    }
    let Some(key_bytes) = node.key.clone().filter(|k| text[k.clone()] == **key) else {
        return Err(give_up(
            GiveUp::NotPlainKey,
            "the list's key is not written plain",
        ));
    };
    if node.decorated {
        return Err(give_up(
            GiveUp::Anchor,
            "the list or an item has an anchor, a tag or an alias",
        ));
    }
    let doc: Value = crate::yaml::from_str(&text)
        .map_err(|_| unprovable("the file is not one mapping the parser accepts"))?;
    let current = value_at(&doc, &path.0);
    match node.shape {
        Shape::Scalar { empty: true } => after_colon(lines, &text, key_bytes.end, value),
        Shape::Scalar { empty: false }
            if current.is_null() && one_line(&text, node.bytes.clone()) =>
        {
            replaced(lines, node.bytes.clone(), value)
        }
        Shape::Scalar { .. } => Err(unprovable("the field is a scalar, not a list")),
        Shape::Mapping => Err(unprovable("the field is a mapping, not a list")),
        Shape::Sequence => {
            let kids: Vec<&Node> = shape::children(&nodes, node).collect();
            strings_only(&text, &kids, current)?;
            // Flow span first: an inline list over two lines refuses even
            // when it already holds these items.
            let close = if node.flow {
                Some(closing_bracket(&text, node, kids.last().copied())?)
            } else {
                None
            };
            let unchanged = holds(current, items);
            if unchanged {
                return Ok(());
            }
            match close {
                Some(close) => replaced(lines, node.bytes.start..close + 1, value),
                None => {
                    // Both positions come from this one parse. The item lines
                    // are under the key's line, so deleting them first leaves
                    // the colon's byte position as it was; nothing is
                    // re-parsed between the two steps.
                    let colon = colon_after(&text, key_bytes.end)?;
                    shape::remove_entry(lines, &path.0, CommentRule::Refuse, Span::Under)?;
                    write_after(lines, colon, value)
                }
            }
        }
    }
}

/// The value at `path` in `doc`; null when absent.
pub(super) fn value_at<'v>(doc: &'v Value, path: &[Segment]) -> &'v Value {
    path.iter().fold(doc, |at, segment| match segment {
        Segment::Key(k) => &at[k.as_str()],
        Segment::Index(i) => &at[*i],
    })
}

/// `current` is a list of exactly `items`, in order.
pub(super) fn holds(current: &Value, items: &[String]) -> bool {
    current.as_sequence().is_some_and(|now| {
        now.iter()
            .map(Value::as_str)
            .eq(items.iter().map(|s| Some(s.as_str())))
    })
}

/// Every item a one-line string scalar with no anchor, tag or alias, and as
/// many items parsed as the parser has nodes.
fn strings_only(text: &str, kids: &[&Node], current: &Value) -> Result<(), ComputeRefusal> {
    if kids.iter().any(|k| k.decorated) {
        return Err(give_up(
            GiveUp::Anchor,
            "the list or an item has an anchor, a tag or an alias",
        ));
    }
    let parsed = current.as_sequence().map_or(&[][..], Vec::as_slice);
    let plain = kids.len() == parsed.len()
        && kids.iter().zip(parsed).all(|(kid, value)| {
            let own = &text[kid.bytes.clone()];
            matches!(kid.shape, Shape::Scalar { empty: false })
                && value.is_string()
                && !own.starts_with(['|', '>'])
                && one_line(text, kid.bytes.clone())
        });
    if plain {
        Ok(())
    } else {
        Err(unprovable("an item is not a plain string on one line"))
    }
}

/// The byte of the `]` closing a one-line inline list: on the `[`'s line,
/// after the last item (or the `[` when empty), with only spaces and commas
/// between.
fn closing_bracket(text: &str, list: &Node, last: Option<&Node>) -> Result<usize, ComputeRefusal> {
    let from = last.map_or(list.bytes.end, |item| item.bytes.end);
    let rest = &text[from..];
    let gap = rest.len() - rest.trim_start_matches([' ', ',']).len();
    let at = from + gap;
    let same_line = !text[list.bytes.start..at].contains('\n');
    if same_line && text[at..].starts_with(']') {
        Ok(at)
    } else {
        Err(give_up(
            GiveUp::Flow,
            "an inline list over more than one line",
        ))
    }
}

fn one_line(text: &str, bytes: std::ops::Range<usize>) -> bool {
    !text[bytes].contains('\n')
}

/// The byte of the colon after a key ending at `key_end`, on its line.
fn colon_after(text: &str, key_end: usize) -> Result<usize, ComputeRefusal> {
    let rest = &text[key_end..];
    let gap = rest.len() - rest.trim_start_matches(' ').len();
    if rest[gap..].starts_with(':') {
        Ok(key_end + gap)
    } else {
        Err(unprovable("the key's colon is not on its line"))
    }
}

/// `key:` written alone: the list goes after the colon, any comment kept.
fn after_colon(
    lines: &mut Lines,
    text: &str,
    key_end: usize,
    value: &str,
) -> Result<(), ComputeRefusal> {
    let colon = colon_after(text, key_end)?;
    write_after(lines, colon, value)
}

fn write_after(lines: &mut Lines, colon: usize, value: &str) -> Result<(), ComputeRefusal> {
    replaced(lines, colon + 1..colon + 1, &format!(" {value}"))
}

fn replaced(
    lines: &mut Lines,
    span: std::ops::Range<usize>,
    value: &str,
) -> Result<(), ComputeRefusal> {
    lines
        .replace(span, value)
        .ok_or_else(|| unprovable("the value runs past the end of its line"))
}
