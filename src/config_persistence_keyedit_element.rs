// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One list element inserted at a position, or one dropped, in place
//! (`Change::Insert`, `Change::Drop`). A new element's lines go directly
//! after the element before it (or the list's key line, for position 0), so
//! a comment above an element stays with it. A dropped element takes its own
//! lines; a comment on any of them refuses. An emptied list stays, as `[]`:
//! the loader reads that as its default, and no parent can empty. On a list's
//! key line every replaced span starts at the byte after the key's colon, so
//! the shown diff reads it as that field's value. Inline lists are edited by
//! one splice of the bytes already there, never rebuilt from parsed items.

use std::ops::Range;

use crate::yaml::{Mapping, Node, Shape, Value};

use super::shape::{self, Lines};
use super::{
    Change, ComputeRefusal, Element, FieldPath, GiveUp, Member, Segment, give_up, inline_list,
    unprovable, write_value,
};

/// A path's list and the position its last step names; `None` when the
/// last step is a key.
pub(super) fn split(path: &[Segment]) -> Option<(&[Segment], usize)> {
    match path.split_last()? {
        (Segment::Index(i), list) => Some((list, *i)),
        _ => None,
    }
}

/// The element as the loader reads it back.
pub(super) fn value(element: &Element) -> Value {
    let text = |s: &String| Value::from(s.as_str());
    match element {
        Element::Str(s) => text(s),
        Element::Map(members) => {
            let mut map = Mapping::new();
            for (name, member) in members {
                let v = match member {
                    Member::Str(s) => text(s),
                    Member::Strings(items) => Value::Sequence(items.iter().map(text).collect()),
                };
                map.insert(Value::from(name.as_str()), v);
            }
            Value::Mapping(map)
        }
    }
}

/// The element as one inline value: `"x"`, or `{k: v, ...}` (patch text).
pub(super) fn inline(element: &Element) -> String {
    match element {
        Element::Str(s) => crate::yaml::double_quoted(s),
        Element::Map(members) => {
            let parts: Vec<String> = members
                .iter()
                .map(|(name, member)| format!("{name}: {}", member_text(member)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

fn member_text(member: &Member) -> String {
    match member {
        Member::Str(s) => crate::yaml::double_quoted(s),
        Member::Strings(items) => inline_list(items),
    }
}

/// The element as block lines, its dash at column `dash`: a mapping's first
/// member on the dash line, each later one two columns in.
fn block_lines(element: &Element, dash: usize) -> Vec<String> {
    let pad = " ".repeat(dash);
    match element {
        Element::Str(s) => vec![format!("{pad}- {}", crate::yaml::double_quoted(s))],
        Element::Map(members) => members
            .iter()
            .enumerate()
            .map(|(k, (name, member))| {
                let lead = if k == 0 { "- " } else { "  " };
                format!("{pad}{lead}{name}: {}", member_text(member))
            })
            .collect(),
    }
}

/// The rules every insert and drop meets before any line is touched: it is
/// the only change in its list (member edits included); an insert names a
/// position up to the list's length, a drop one below it; the list carries
/// no anchor, tag or alias; a mapping element has members, each a plain key.
pub(super) fn checked(
    before: &[Node],
    changes: &[(FieldPath, Change)],
) -> Result<(), ComputeRefusal> {
    for (path, change) in changes {
        let element = match change {
            Change::Insert(element) => Some(element),
            Change::Drop => None,
            _ => continue,
        };
        let (list, i) = split(&path.0).ok_or_else(|| {
            give_up(
                GiveUp::SequenceShape,
                "an element change names a list position",
            )
        })?;
        if changes
            .iter()
            .filter(|(p, _)| p.0.starts_with(list))
            .count()
            != 1
        {
            return Err(give_up(
                GiveUp::SequenceShape,
                "an element change must be the save's only change in its list",
            ));
        }
        let node = shape::find(before, list);
        if node.is_some_and(|n| n.decorated) {
            return Err(give_up(
                GiveUp::Anchor,
                "the list has an anchor, a tag or an alias",
            ));
        }
        let len = node
            .filter(|n| n.shape == Shape::Sequence)
            .map_or(0, |n| shape::child_count(before, n));
        let fits = if element.is_some() { i <= len } else { i < len };
        if !fits {
            return Err(give_up(
                GiveUp::SequenceShape,
                "a position outside the list",
            ));
        }
        if let Some(Element::Map(members)) = element {
            if members.is_empty() {
                return Err(unprovable("a mapping element with no member"));
            }
            if !members.iter().all(|(name, _)| super::plain_key(name)) {
                return Err(give_up(
                    GiveUp::NotPlainKey,
                    "a member name is not a plain key",
                ));
            }
        }
    }
    Ok(())
}

/// The list's node and the byte of its key's colon, once the key is written
/// plain under a block mapping and the list is undecorated. `None` when the
/// file has no list there.
fn listed<'n>(
    text: &str,
    nodes: &'n [Node],
    list: &[Segment],
) -> Result<Option<(&'n Node, usize)>, ComputeRefusal> {
    let Some(node) = shape::find(nodes, list) else {
        return Ok(None);
    };
    let Some((Segment::Key(key), parent)) = list.split_last() else {
        return Err(unprovable("a list is reached by a key"));
    };
    let block = shape::find(nodes, parent)
        .is_some_and(|p| p.shape == Shape::Mapping && p.plain && !p.flow && !p.decorated);
    if !block {
        return Err(give_up(
            shape::refusal_code(nodes, parent),
            "the list's mapping cannot be edited in place",
        ));
    }
    if node.decorated {
        return Err(give_up(
            GiveUp::Anchor,
            "the list has an anchor, a tag or an alias",
        ));
    }
    // Plain as written: the key's own text, only indentation (or a dash)
    // before it on its line, its colon on that line.
    let plain = node.key.clone().filter(|k| {
        let line_start = text[..k.start].rfind('\n').map_or(0, |n| n + 1);
        text[k.clone()] == **key
            && text[line_start..k.start]
                .chars()
                .all(|c| c == ' ' || c == '-')
    });
    let colon = plain.and_then(|k| {
        let rest = &text[k.end..];
        let gap = rest.len() - rest.trim_start_matches([' ', '\t']).len();
        rest[gap..].starts_with(':').then_some(k.end + gap)
    });
    match colon {
        Some(colon) => Ok(Some((node, colon))),
        None => Err(give_up(
            GiveUp::NotPlainKey,
            "the list's key is not written plain",
        )),
    }
}

fn column(text: &str, at: usize) -> usize {
    at - text[..at].rfind('\n').map_or(0, |n| n + 1)
}

/// The byte of the `]` closing a one-line inline list: after the last item
/// (or the `[`), past spaces and commas, on the `[`'s line.
fn closing(text: &str, list: &Node, end_item: Option<&Node>) -> Result<usize, ComputeRefusal> {
    let from = end_item.map_or(list.bytes.end, |item| item.bytes.end);
    let rest = &text[from..];
    let at = from + rest.len() - rest.trim_start_matches([' ', ',']).len();
    if !text[list.bytes.start..at].contains('\n') && text[at..].starts_with(']') {
        Ok(at)
    } else {
        Err(give_up(
            GiveUp::Flow,
            "an inline list over more than one line",
        ))
    }
}

fn replace(lines: &mut Lines, span: Range<usize>, value: &str) -> Result<(), ComputeRefusal> {
    lines
        .replace(span, value)
        .ok_or_else(|| unprovable("the value runs past the end of its line"))
}

/// Insert `element` at `path` (its list and a position in it, as the file
/// holds the list).
pub(super) fn insert(
    lines: &mut Lines,
    path: &FieldPath,
    element: &Element,
) -> Result<(), ComputeRefusal> {
    let (list, i) = split(&path.0).ok_or_else(|| unprovable("no list position"))?;
    let text = lines.text();
    let nodes = shape::nodes(&text)?;
    let Some((node, colon)) = listed(&text, &nodes, list)? else {
        return absent(lines, list, element);
    };
    let kids: Vec<&Node> = shape::children(&nodes, node).collect();
    let after_colon = colon + 1;
    match (node.shape, element) {
        (Shape::Sequence, _) if !node.flow => {
            let first = kids
                .first()
                .ok_or_else(|| unprovable("an empty block list"))?;
            let dash = column(&text, first.bytes.start)
                .checked_sub(2)
                .ok_or_else(|| unprovable("a list item's dash"))?;
            let after = match i.checked_sub(1).map(|b| kids.get(b)) {
                None => lines.line_of(colon),
                Some(Some(previous)) => {
                    super::revoke::element_lines(&text, previous)
                        .ok_or_else(|| unprovable("a list element without its dash"))?
                        .end
                        - 1
                }
                Some(None) => return Err(unprovable("a position past the list's end")),
            };
            lines.insert(Some(after), &block_lines(element, dash));
            Ok(())
        }
        (Shape::Sequence, Element::Str(s)) => {
            let close = closing(&text, node, kids.last().copied())?;
            let quoted = crate::yaml::double_quoted(s);
            // One splice into the bytes already there: after the last item,
            // or between the brackets of an empty list.
            let spliced = match kids.last() {
                None => format!("{}{quoted}]", &text[after_colon..close]),
                Some(tail) if i == kids.len() => format!(
                    "{}, {quoted}{}",
                    &text[after_colon..tail.bytes.end],
                    &text[tail.bytes.end..=close]
                ),
                Some(_) => {
                    return Err(give_up(GiveUp::Flow, "a new item inside an inline list"));
                }
            };
            replace(lines, after_colon..close + 1, &spliced)
        }
        (Shape::Sequence, Element::Map(_)) if kids.is_empty() => {
            // Only the two bracket bytes go; then as `key:` alone.
            let close = closing(&text, node, None)?;
            let open = node.bytes.start;
            let without = format!("{}{}", &text[after_colon..open], &text[open + 1..close]);
            replace(lines, after_colon..close + 1, &without)?;
            absent(lines, list, element)
        }
        (Shape::Sequence, Element::Map(_)) => {
            Err(give_up(GiveUp::Flow, "a mapping into an inline list"))
        }
        (Shape::Scalar { empty: true }, Element::Str(s)) => replace(
            lines,
            after_colon..after_colon,
            &format!(" {}", inline_list(std::slice::from_ref(s))),
        ),
        (Shape::Scalar { empty: true }, Element::Map(_)) => absent(lines, list, element),
        (Shape::Scalar { .. }, _) if !is_null(&text, list)? => {
            Err(unprovable("the field is a scalar, not a list"))
        }
        (Shape::Scalar { .. }, Element::Str(s)) if !text[node.bytes.clone()].contains('\n') => {
            let lead = &text[after_colon..node.bytes.start];
            let new = format!("{lead}{}", inline_list(std::slice::from_ref(s)));
            replace(lines, after_colon..node.bytes.end, &new)
        }
        (Shape::Scalar { .. }, Element::Map(_)) => Err(give_up(
            GiveUp::NullSequence,
            "the list is written as a null value",
        )),
        _ => Err(unprovable("the field is not a list")),
    }
}

fn is_null(text: &str, list: &[Segment]) -> Result<bool, ComputeRefusal> {
    let doc: Value = crate::yaml::from_str(text)
        .map_err(|_| unprovable("the file is not one mapping the parser accepts"))?;
    Ok(super::list::value_at(&doc, list).is_null())
}

/// A list the file does not hold (or `key:` alone, for a mapping): a string
/// is written as `key: ["x"]`, a mapping member by member at `list[0]`, each
/// with any missing parents.
fn absent(lines: &mut Lines, list: &[Segment], element: &Element) -> Result<(), ComputeRefusal> {
    match element {
        Element::Str(s) => write_value(
            lines,
            &FieldPath(list.to_vec()),
            &inline_list(std::slice::from_ref(s)),
        ),
        Element::Map(members) => {
            for (name, member) in members {
                let mut at = list.to_vec();
                at.extend([Segment::Index(0), Segment::Key(name.clone())]);
                write_value(lines, &FieldPath(at), &member_text(member))?;
            }
            Ok(())
        }
    }
}

/// Drop the element at `path` (its list and a position in it).
pub(super) fn remove(lines: &mut Lines, path: &[Segment]) -> Result<(), ComputeRefusal> {
    let (list, i) = split(path).ok_or_else(|| unprovable("no list position"))?;
    let text = lines.text();
    let nodes = shape::nodes(&text)?;
    let missing = || give_up(GiveUp::SequenceShape, "no such list element");
    let (node, colon) = listed(&text, &nodes, list)?.ok_or_else(missing)?;
    let kids: Vec<&Node> = shape::children(&nodes, node).collect();
    let element = *kids.get(i).ok_or_else(missing)?;
    let decorated = nodes
        .iter()
        .any(|n| n.start >= element.start && n.start < element.end && n.decorated);
    if element.decorated || decorated {
        return Err(give_up(
            GiveUp::Anchor,
            "the element has an anchor, a tag or an alias",
        ));
    }
    let after_colon = colon + 1;
    if !node.flow {
        let range = super::revoke::element_lines(&text, element)
            .ok_or_else(|| unprovable("a list element without its dash"))?;
        // Operator text is never deleted here: refuse, citing the line
        // number in the file as read, not what the line says.
        if let Some(hit) = range.clone().find(|&n| lines.content(n).contains('#')) {
            let why = lines.original_line(hit).map_or_else(
                || "a deleted line carries a comment".to_owned(),
                |at| format!("a deleted line carries a comment (line {at})"),
            );
            return Err(give_up(GiveUp::Comment, &why));
        }
        lines.delete(range);
        // The lines went from below the key's line: its colon has not moved.
        if kids.len() == 1 {
            replace(lines, after_colon..after_colon, " []")?;
        }
        return Ok(());
    }
    if kids
        .iter()
        .any(|k| !matches!(k.shape, Shape::Scalar { .. }))
    {
        return Err(give_up(GiveUp::Flow, "an inline list holding a collection"));
    }
    let close = closing(&text, node, kids.last().copied())?;
    let cut = if kids.len() == 1 {
        node.bytes.end..close
    } else {
        with_comma(&text, element.bytes.clone())
    };
    let rebuilt = format!(
        "{}{}",
        &text[after_colon..cut.start],
        &text[cut.end..=close]
    );
    replace(lines, after_colon..close + 1, &rebuilt)
}

/// An inline item's bytes with one separating comma: the following comma
/// and the spaces after it, else the preceding comma and the spaces before.
fn with_comma(text: &str, item: Range<usize>) -> Range<usize> {
    let after = &text[item.end..];
    let gap = after.len() - after.trim_start_matches(' ').len();
    if let Some(rest) = after[gap..].strip_prefix(',') {
        let skip = rest.len() - rest.trim_start_matches(' ').len();
        return item.start..item.end + gap + 1 + skip;
    }
    let head = text[..item.start].trim_end_matches(' ');
    match head.strip_suffix(',') {
        Some(head) => head.trim_end_matches(' ').len()..item.end,
        None => item,
    }
}
