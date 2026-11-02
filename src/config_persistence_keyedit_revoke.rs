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
use crate::yaml::{Node, Step};

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

fn steps(path: &[&str], index: Option<usize>) -> Vec<Step> {
    let mut out: Vec<Step> = path.iter().map(|k| Step::Key((*k).to_owned())).collect();
    if let Some(i) = index {
        out.push(Step::Index(i));
    }
    out
}

fn node<'n>(nodes: &'n [Node], path: &[Step]) -> Option<&'n Node> {
    nodes.iter().find(|n| n.path == path)
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
    // above it, alone or with a comment, past comment and blank lines.
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
            if !(trimmed.is_empty() || trimmed.starts_with('#')) {
                return None;
            }
        }
    }
    let dash_col = indent(&content(text, &starts, dash));
    let span = &text[element.start..element.end.min(text.len())];
    let last_byte = element.start + span.trim_end().len().max(1) - 1;
    let mut last = starts.line_of(last_byte).max(dash);
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

/// What a refused revocation tells the operator (S9): expiry first, which a
/// reload always applies since the number of keys stays the same, then the
/// hand deletion. Names the key and lines, never a value.
fn instructions(
    name: &str,
    lines: &Range<usize>,
    shared: Option<usize>,
    list_line: Option<usize>,
) -> String {
    let deletion = if let Some(line) = shared {
        format!("on line {line}, remove the entry with `name: {name}`, keeping the others")
    } else {
        let mut d = format!("delete lines {} to {}", lines.start + 1, lines.end);
        if let Some(list) = list_line {
            std::fmt::Write::write_fmt(&mut d, format_args!(" and the `api_keys:` line {list}"))
                .ok();
        }
        d
    };
    format!(
        "to revoke key `{name}`: set its `expires_at` to now and reload the gateway; \
         else {deletion} and reload. A deletion that changes whether the gateway is \
         multi-user needs a restart, not a reload"
    )
}

/// Refuse a revocation the proofs cannot cover (S2), with the instructions:
/// a decorated element, a flow-style list, or an anchor anywhere inside the
/// element (a surviving alias may name it).
pub(super) fn refusal(original: &str, nodes: &[Node], index: usize) -> Option<ComputeRefusal> {
    let element = node(nodes, &steps(&["auth", "api_keys"], Some(index)))?;
    let list = node(nodes, &steps(&["auth", "api_keys"], None))?;
    let name = node(nodes, &{
        let mut p = steps(&["auth", "api_keys"], Some(index));
        p.push(Step::Key("name".into()));
        p
    })
    .map_or_else(
        || format!("#{index}"),
        |n| {
            original[n.bytes.clone()]
                .trim_matches(['"', '\''])
                .to_owned()
        },
    );
    let starts = Starts::of(original);
    let only = nodes
        .iter()
        .filter(|n| n.path.len() == 3 && n.path[..2] == steps(&["auth", "api_keys"], None)[..])
        .count()
        == 1;
    let list_line = only.then(|| starts.line_of(list.start) + 1);
    if element.flow || list.flow {
        let line = starts.line_of(element.start) + 1;
        let reason = instructions(&name, &(line - 1..line), Some(line), None);
        return Some(ComputeRefusal::Unprovable {
            code: GiveUp::Flow,
            reason,
        });
    }
    let inner = nodes
        .iter()
        .any(|n| n.start >= element.start && n.start < element.end && n.decorated);
    if element.decorated || inner {
        let lines = element_lines(original, element)
            .unwrap_or(starts.line_of(element.start)..starts.line_of(element.start) + 1);
        let reason = instructions(&name, &lines, None, list_line);
        return Some(ComputeRefusal::Unprovable {
            code: GiveUp::Anchor,
            reason,
        });
    }
    None
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
}

/// S5: the original lines removing `node` may delete, from the original
/// text alone and apart from how the edit chose its lines: the dash or key
/// line through the last line holding a non-space byte of the node, then
/// comment lines indented deeper than the dash or key (blank lines between
/// them included).
pub(super) fn may_delete(original: &str, node: &Node, taken: Taken) -> BTreeSet<usize> {
    let starts = Starts::of(original);
    let line = |n: usize| content(original, &starts, n);
    let mut first = starts.line_of(node.start);
    if taken == Taken::Element {
        while first > 0 && !line(first).trim_start().starts_with('-') {
            let above = line(first - 1);
            let above = above.trim_start();
            if !(above.is_empty() || above.starts_with('#') || above.starts_with('-')) {
                break;
            }
            first -= 1;
        }
    }
    let col = indent(&line(first));
    let end = node.end.min(original.len());
    let last = original[node.start..end]
        .char_indices()
        .filter(|(_, c)| !c.is_whitespace())
        .map(|(at, _)| starts.line_of(node.start + at))
        .next_back()
        .unwrap_or(first);
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
