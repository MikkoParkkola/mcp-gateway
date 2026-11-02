// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Removing one `auth.api_keys` element in place: the web UI's API-key
//! revoke. The element's lines go with the comments on them, reported by
//! original line number; a list it empties goes too, and so does a parent it
//! empties. A shape the proofs cannot cover refuses with the revocation
//! instructions, expiry first. Comments on deleted lines never refuse a
//! revocation: a leaked key must always be revocable.

use std::collections::BTreeSet;
use std::ops::Range;

use super::shape::Lines;
use super::{ComputeRefusal, GiveUp, Segment};
use crate::yaml::Node;

/// `auth.api_keys[i]`: the one list whose element may be removed. Its
/// loader default is an empty list, so absent and empty mean the same; for
/// any other list nothing here proves that.
pub(super) fn revoked_index(path: &[Segment]) -> Option<usize> {
    match path {
        [Segment::Key(a), Segment::Key(k), Segment::Index(i)] if a == "auth" && k == "api_keys" => {
            Some(*i)
        }
        _ => None,
    }
}

/// Byte offsets where each line of `text` starts, and the line of a byte.
struct Starts(Vec<usize>);

impl Starts {
    fn of(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(at, _)| at + 1));
        if starts.last() == Some(&text.len()) && !text.is_empty() {
            starts.pop();
        }
        Self(starts)
    }

    fn line_of(&self, at: usize) -> usize {
        self.0.partition_point(|&s| s <= at).saturating_sub(1)
    }
}

fn content(text: &str, starts: &Starts, n: usize) -> String {
    let start = starts.0[n];
    let end = starts.0.get(n + 1).copied().unwrap_or(text.len());
    text[start..end].trim_end_matches(['\n', '\r']).to_owned()
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The element's whole lines (S1), 0-based and half-open: from the line of
/// the `-` that introduces it, whatever follows the dash, through the last
/// line holding a non-space byte of its span (a block scalar's span ends in
/// the next line's indentation, which is never taken), then the comment and
/// blank lines indented deeper than the dash that follow it.
pub(super) fn element_lines(text: &str, element: &Node) -> Option<Range<usize>> {
    let starts = Starts::of(text);
    let mut dash = starts.line_of(element.start);
    // The element's first line is its dash line unless the dash stands
    // above it, alone or with a comment, past comment, blank and
    // decoration-only (`&k`, `!tag`) lines.
    if !content(text, &starts, dash).trim_start().starts_with('-') {
        loop {
            if dash == 0 {
                return None;
            }
            dash -= 1;
            let line = content(text, &starts, dash);
            let trimmed = line.trim_start();
            if trimmed.starts_with('-') {
                break;
            }
            if !(trimmed.is_empty() || trimmed.starts_with('#') || decoration_only(trimmed)) {
                return None;
            }
        }
    }
    let dash_col = indent(&content(text, &starts, dash));
    let span = &text[element.start..element.end.min(text.len())];
    let last_byte = element.start + span.trim_end().len().max(1) - 1;
    let mut last = starts.line_of(last_byte).max(dash);
    // Blank lines wholly inside the span are the element's.
    let end = element.end.min(text.len());
    while last + 1 < starts.0.len()
        && content(text, &starts, last + 1).trim().is_empty()
        && starts.0.get(last + 2).copied().unwrap_or(text.len()) <= end
    {
        last += 1;
    }
    let mut next = last + 1;
    while next < starts.0.len() {
        let line = content(text, &starts, next);
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            next += 1;
            continue;
        }
        if !trimmed.starts_with('#') || indent(&line) <= dash_col {
            break;
        }
        last = next;
        next += 1;
    }
    Some(dash..last + 1)
}

/// A line holding only node properties, anchors and tags, before the node
/// they decorate; a trailing comment ends it (`&k # note`).
fn decoration_only(trimmed: &str) -> bool {
    trimmed
        .split_whitespace()
        .take_while(|token| !token.starts_with('#'))
        .all(|token| token.starts_with('&') || token.starts_with('!'))
}

/// Which hand deletion a refusal offers, once checked.
enum Deletion {
    /// The entry's own lines, then the lines its removal empties.
    Lines(Range<usize>, Emptied),
    /// One entry of a flow list, on the line it shares with others: the
    /// checked edit removes its `{...}` and one separating comma.
    OnLine(usize, Range<usize>),
}

/// The 1-based lines a hand deletion of the last entry must also take: the
/// `api_keys:` line, and the `auth:` line when that empties it too (each
/// would load as null and be refused).
#[derive(Clone, Copy)]
enum Emptied {
    Nothing,
    List(usize),
    ListAndAuth(usize, usize),
}

impl Emptied {
    /// The 0-based lines.
    fn lines(self) -> Vec<usize> {
        match self {
            Self::Nothing => Vec::new(),
            Self::List(list) => vec![list - 1],
            Self::ListAndAuth(list, auth) => vec![list - 1, auth - 1],
        }
    }

    fn text(self) -> String {
        match self {
            Self::Nothing => String::new(),
            Self::List(list) => format!(" and the `api_keys:` line {list}"),
            Self::ListAndAuth(list, auth) => {
                format!(" and the `api_keys:` line {list} and the `auth:` line {auth}")
            }
        }
    }
}

/// Whether the expiry edit checked out (S9: every offered edit is checked).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expiry {
    Checked,
    /// Its `expires_at` is shared through an anchor or alias: the one step
    /// that cannot be checked is labelled as such.
    Unchecked,
}

/// Any literal proves the same edit: the expiry check writes this one.
const EXPIRY_PROBE: &str = "2000-01-01T00:00:00Z";

/// Whether setting element `index`'s `expires_at` by hand changes that field
/// alone: the edit applied in memory must parse and equal the original with
/// only that field set. An anchor another key's alias names fails it.
fn expiry_checked(original: &str, nodes: &[Node], index: usize) -> bool {
    let element_path = [
        Segment::Key("auth".into()),
        Segment::Key("api_keys".into()),
        Segment::Index(index),
    ];
    let field = [&element_path[..], &[Segment::Key("expires_at".into())][..]].concat();
    let value = format!("\"{EXPIRY_PROBE}\"");
    let edited = if let Some(node) = super::shape::find(nodes, &field) {
        // Its value replaced, with any anchor or alias on it.
        let Some(key) = node.key.clone() else {
            return false;
        };
        format!(
            "{}: {value}{}",
            &original[..key.end],
            &original[node.bytes.end..]
        )
    } else {
        let Some(element) = super::shape::find(nodes, &element_path) else {
            return false;
        };
        if element.flow {
            if original.as_bytes().get(element.start) != Some(&b'{') {
                return false;
            }
            let (head, tail) = original.split_at(element.start + 1);
            format!("{head}expires_at: {value}, {tail}")
        } else {
            // A new line after the `name:` line, at its key's column.
            let name_path = [&element_path[..], &[Segment::Key("name".into())][..]].concat();
            let Some(key) = super::shape::find(nodes, &name_path).and_then(|n| n.key.clone())
            else {
                return false;
            };
            let starts = Starts::of(original);
            let line = starts.line_of(key.start);
            let col = key.start - starts.0[line];
            let at = starts.0.get(line + 1).copied().unwrap_or(original.len());
            let ending = if original[..at].ends_with('\n') {
                ""
            } else {
                "\n"
            };
            format!(
                "{}{ending}{}expires_at: {value}\n{}",
                &original[..at],
                " ".repeat(col),
                &original[at..]
            )
        }
    };
    let Ok(doc) = crate::yaml::from_str::<crate::yaml::Value>(original) else {
        return false;
    };
    let set = (
        super::FieldPath(field),
        super::Change::Set(super::Scalar::Str(EXPIRY_PROBE.into())),
    );
    let Some(want) = super::shape::expected(&doc, &[set]) else {
        return false;
    };
    crate::yaml::from_str::<crate::yaml::Value>(&edited).is_ok_and(|got| got == want)
}

/// What a refused revocation tells the operator (S9): expiry first, which a
/// reload always applies since the number of keys stays the same, then the
/// hand deletion when one was checked (`None`: expiry alone). Every edit it
/// offers was checked in memory; an expiry that could not be is said so,
/// with its one unchecked step labelled. Names the key and lines, never a
/// value.
fn instructions(name: &str, expiry: Expiry, deletion: Option<&Deletion>) -> String {
    let expiry = match expiry {
        Expiry::Checked => {
            format!("to revoke key `{name}`: set its `expires_at` to now and reload the gateway")
        }
        Expiry::Unchecked => format!(
            "to revoke key `{name}`: no hand edit of its `expires_at` could be checked here, \
             because that value is shared through an anchor (`&`) or alias (`*`). Unchecked \
             step: copy the value onto each alias that names it, then set this entry's \
             `expires_at` to now and reload the gateway"
        ),
    };
    let deletion = match deletion {
        None => return expiry,
        Some(Deletion::OnLine(line, _)) => {
            format!(
                "on line {line}, remove the entry with `name: {name}` and one comma next to it, \
                 keeping the others"
            )
        }
        Some(Deletion::Lines(lines, emptied)) => format!(
            "delete lines {} to {}{}",
            lines.start + 1,
            lines.end,
            emptied.text()
        ),
    };
    format!(
        "{expiry}; else {deletion} and reload. A deletion that changes whether the gateway \
         is multi-user needs a restart, not a reload"
    )
}

/// S9 proves its own instruction: the deletion applied to `original` must
/// parse and mean S10's value, the original without element `index`. A
/// shape where it does not (a surviving alias, a property line the range
/// misses) gets expiry alone.
fn checked(original: &str, index: usize, deletion: &Deletion) -> bool {
    let edited = match deletion {
        Deletion::Lines(lines, emptied) => {
            let gone: Vec<usize> = lines.clone().chain(emptied.lines()).collect();
            original
                .split_inclusive('\n')
                .enumerate()
                .filter(|(n, _)| !gone.contains(n))
                .map(|(_, line)| line)
                .collect::<String>()
        }
        Deletion::OnLine(_, span) => {
            format!("{}{}", &original[..span.start], &original[span.end..])
        }
    };
    let path = super::FieldPath(vec![
        Segment::Key("auth".into()),
        Segment::Key("api_keys".into()),
        Segment::Index(index),
    ]);
    super::meaning_holds(original, &[(path, super::Change::Remove)], &edited)
}

/// A flow-list entry's bytes with one separating comma: from the `{` at
/// `start` through its matching `}`, then a following `,` and spaces, or
/// else the preceding ones. `None` when the entry is not a `{...}`.
fn flow_entry_span(text: &str, start: usize) -> Option<Range<usize>> {
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&b'{') {
        return None;
    }
    let (mut depth, mut quote, mut at) = (0usize, None, start);
    while at < bytes.len() {
        let b = bytes[at];
        match quote {
            Some(q) if b == b'\\' && q == b'"' => at += 1,
            Some(q) if b == q => quote = None,
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'{' || b == b'[' => depth += 1,
            None if b == b'}' || b == b']' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        at += 1;
    }
    if at >= bytes.len() {
        return None;
    }
    let end = at + 1;
    let after = text[end..].trim_start_matches(' ');
    if let Some(rest) = after.strip_prefix(',') {
        let skip = text.len() - rest.trim_start_matches(' ').len();
        return Some(start..skip);
    }
    let before = text[..start].trim_end_matches(' ');
    before
        .strip_suffix(',')
        .map(|head| head.trim_end_matches(' ').len()..end)
}

/// Refuse a revocation the proofs cannot cover (S2), with the instructions:
/// a decorated element, a flow-style list, or an anchor anywhere inside the
/// element, the list or `auth` (a surviving alias may name it).
pub(super) fn refusal(original: &str, nodes: &[Node], index: usize) -> Option<ComputeRefusal> {
    let list_path = [Segment::Key("auth".into()), Segment::Key("api_keys".into())];
    let element_path = [
        list_path[0].clone(),
        list_path[1].clone(),
        Segment::Index(index),
    ];
    let element = super::shape::find(nodes, &element_path)?;
    let list = super::shape::find(nodes, &list_path)?;
    let name_path = [&element_path[..], &[Segment::Key("name".into())][..]].concat();
    // The name as written in the file, quotes and all: names are unique once
    // decoded, so two spellings cannot both load, and trimming quotes could
    // turn `"'ops'"` into another key's `ops`.
    let name = super::shape::find(nodes, &name_path).map_or_else(
        || format!("#{index}"),
        |n| original[n.bytes.clone()].to_owned(),
    );
    let starts = Starts::of(original);
    let auth = super::shape::find(nodes, &list_path[..1])?;
    let emptied = if super::shape::child_count(nodes, list) != 1 {
        Emptied::Nothing
    } else if super::shape::child_count(nodes, auth) == 1 {
        Emptied::ListAndAuth(
            starts.line_of(list.start) + 1,
            starts.line_of(auth.start) + 1,
        )
    } else {
        Emptied::List(starts.line_of(list.start) + 1)
    };
    let inner = nodes
        .iter()
        .any(|n| n.start >= element.start && n.start < element.end && n.decorated);
    let above = list.decorated || auth.decorated;
    let code = if list.flow || element.flow {
        GiveUp::Flow
    } else if element.decorated || inner || above {
        GiveUp::Anchor
    } else {
        return None;
    };
    // A shared line only in a flow list: a flow element of a block list
    // has its own lines, its dash among them.
    let deletion = if list.flow {
        flow_entry_span(original, element.start)
            .map(|span| Deletion::OnLine(starts.line_of(element.start) + 1, span))
    } else {
        element_lines(original, element).map(|lines| Deletion::Lines(lines, emptied))
    }
    .filter(|deletion| checked(original, index, deletion));
    let expiry = if expiry_checked(original, nodes, index) {
        Expiry::Checked
    } else {
        Expiry::Unchecked
    };
    let reason = instructions(&name, expiry, deletion.as_ref());
    Some(ComputeRefusal::Unprovable { code, reason })
}

/// Delete the element at `path` (S1) from the current text. A missing
/// element is a no-op (`Ok(false)`).
pub(super) fn remove_element(lines: &mut Lines, path: &[Segment]) -> Result<bool, ComputeRefusal> {
    let text = lines.text();
    let nodes = super::shape::nodes(&text)?;
    let Some(element) = super::shape::find(&nodes, path) else {
        return Ok(false);
    };
    let range = element_lines(&text, element)
        .ok_or_else(|| super::unprovable("a list element without its dash"))?;
    lines.delete(range);
    Ok(true)
}

/// Which node a guarded removal took.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Taken {
    /// A list element: its lines start at its dash.
    Element,
    /// A mapping entry: its lines start at its key.
    Entry,
    /// The lines under a mapping entry's key, its own line kept (a block
    /// list rewritten inline); comments count as under it when indented
    /// deeper than the key itself.
    Under,
}

/// S5: the original lines removing `node` may delete, from the original
/// text alone and apart from how the edit chose its lines: the dash or key
/// line through the last line holding a non-space byte of the node, then
/// comment lines indented deeper than the dash or key (blank lines between
/// them included). Under [`Taken::Under`] the key's own line is not taken.
pub(super) fn may_delete(original: &str, node: &Node, taken: Taken) -> BTreeSet<usize> {
    let starts = Starts::of(original);
    let line = |n: usize| content(original, &starts, n);
    let key_line = starts.line_of(node.start);
    let mut first = key_line;
    if taken == Taken::Element {
        while first > 0 && !line(first).trim_start().starts_with('-') {
            let above = line(first - 1);
            let above = above.trim_start();
            if !(above.is_empty()
                || above.starts_with('#')
                || above.starts_with('-')
                || decoration_only(above))
            {
                break;
            }
            first -= 1;
        }
    }
    // Comments count as the node's when indented deeper than its dash (an
    // element) or than its key itself (an entry), as `remove_entry` judges
    // them: a key's column, not its line's indent, which an explicit `? key`
    // or a key after a dash would shift.
    let key_col = node.start - starts.0[key_line];
    let col = match taken {
        Taken::Under => {
            first += 1;
            key_col
        }
        Taken::Entry => key_col,
        Taken::Element => indent(&line(first)),
    };
    let end = node.end.min(original.len());
    let last = original[node.start..end]
        .char_indices()
        .filter(|(_, c)| !c.is_whitespace())
        .map(|(at, _)| starts.line_of(node.start + at))
        .next_back()
        .unwrap_or(first);
    // Blank lines wholly inside the span are the node's.
    let mut last = last;
    while last + 1 < starts.0.len()
        && line(last + 1).trim().is_empty()
        && starts.0.get(last + 2).copied().unwrap_or(original.len()) <= end
    {
        last += 1;
    }
    let mut out: BTreeSet<usize> = (first..=last).collect();
    let mut pending = Vec::new();
    for n in last + 1..starts.0.len() {
        let text = line(n);
        let trimmed = text.trim_start();
        if trimmed.is_empty() {
            pending.push(n);
            continue;
        }
        if !trimmed.starts_with('#') || indent(&text) <= col {
            break;
        }
        out.extend(pending.drain(..));
        out.insert(n);
    }
    out
}
