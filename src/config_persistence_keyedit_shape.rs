// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Inserting and removing whole entries for the key editor: the line edits
//! themselves, the record of where every line came from (for the bytes
//! proof), and the document the edit must mean (for the meaning proof).

use crate::yaml::{Mapping, Value};

use super::super::eol::split_ending;

use super::{Change, FieldPath, Segment};

/// The document `original` means with `changes` applied: missing mappings
/// and a new sequence element created on the way, a removed key gone, and a
/// mapping the removals emptied gone with it. `None` when a change cannot
/// apply to this document at all.
pub(super) fn expected(original: &Value, changes: &[(FieldPath, Change)]) -> Option<Value> {
    let mut want = match original {
        Value::Null => Value::Mapping(Mapping::new()),
        other => other.clone(),
    };
    for (path, change) in changes.iter().filter(|(_, c)| *c != Change::Remove) {
        let value = super::expected_value(change)?;
        *slot_mut(&mut want, &path.0)? = value;
    }
    for (path, _) in changes.iter().filter(|(_, c)| *c == Change::Remove) {
        remove(&mut want, &path.0);
    }
    Some(want)
}

/// The node at `path`, creating missing mapping keys and one element past a
/// sequence's end on the way. `None` when a step meets the wrong shape.
fn slot_mut<'v>(node: &'v mut Value, path: &[Segment]) -> Option<&'v mut Value> {
    let Some((first, rest)) = path.split_first() else {
        return Some(node);
    };
    let child = match first {
        Segment::Key(key) => {
            if node.is_null() {
                *node = Value::Mapping(Mapping::new());
            }
            let map = node.as_mapping_mut()?;
            if map.get_mut(key.as_str()).is_none() {
                map.insert(Value::from(key.as_str()), Value::Null);
            }
            map.get_mut(key.as_str())?
        }
        Segment::Index(at) => {
            if node.is_null() {
                *node = Value::Sequence(Vec::new());
            }
            let seq = node.as_sequence_mut()?;
            if *at == seq.len() {
                seq.push(Value::Null);
            }
            seq.get_mut(*at)?
        }
    };
    slot_mut(child, rest)
}

/// Remove the key at `path`, if present, then every mapping on the way that
/// this left empty. A missing key, or a path into a sequence element that
/// does not exist, changes nothing.
fn remove(node: &mut Value, path: &[Segment]) -> bool {
    let Some((first, rest)) = path.split_first() else {
        return false;
    };
    match first {
        Segment::Key(key) => {
            let Some(map) = node.as_mapping_mut() else {
                return false;
            };
            if rest.is_empty() {
                return map.shift_remove(key.as_str()).is_some();
            }
            let Some(child) = map.get_mut(key.as_str()) else {
                return false;
            };
            let removed = remove(child, rest);
            if removed && child.as_mapping().is_some_and(Mapping::is_empty) {
                map.shift_remove(key.as_str());
            }
            removed
        }
        Segment::Index(at) => node
            .as_sequence_mut()
            .and_then(|seq| seq.get_mut(*at))
            .is_some_and(|child| remove(child, rest)),
    }
}

/// Where a line of the edited text came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Origin {
    /// Original line `0`, unchanged.
    Kept(usize),
    /// Original line `line` with only its value replaced: the first `before`
    /// and last `after` bytes of its text (its ending aside) are the
    /// original's.
    Replaced {
        line: usize,
        before: usize,
        after: usize,
    },
    /// A new line.
    Inserted,
}

/// The text being edited, line by line, each line with its ending and its
/// origin.
pub(super) struct Lines {
    lines: Vec<(String, Origin)>,
}

impl Lines {
    pub(super) fn new(original: &str) -> Self {
        Self {
            lines: original
                .split_inclusive('\n')
                .enumerate()
                .map(|(at, line)| (line.to_owned(), Origin::Kept(at)))
                .collect(),
        }
    }

    pub(super) fn text(&self) -> String {
        self.lines.iter().map(|(line, _)| line.as_str()).collect()
    }

    pub(super) fn len(&self) -> usize {
        self.lines.len()
    }

    /// The line holding byte `at` of [`Self::text`].
    pub(super) fn line_of(&self, at: usize) -> usize {
        let mut start = 0;
        for (n, (line, _)) in self.lines.iter().enumerate() {
            start += line.len();
            if at < start {
                return n;
            }
        }
        self.lines.len().saturating_sub(1)
    }

    pub(super) fn line_start(&self, n: usize) -> usize {
        self.lines[..n].iter().map(|(line, _)| line.len()).sum()
    }

    /// Line `n` without its ending.
    pub(super) fn content(&self, n: usize) -> &str {
        self.lines[n].0.trim_end_matches(['\n', '\r'])
    }

    /// Replace bytes `range` of [`Self::text`], all on one unedited line and
    /// before its ending, with `value`. `None` when they are not.
    pub(super) fn replace(&mut self, range: std::ops::Range<usize>, value: &str) -> Option<()> {
        let n = self.line_of(range.start);
        let start = self.line_start(n);
        let (line, origin) = &self.lines[n];
        let Origin::Kept(orig) = *origin else {
            return None;
        };
        let (from, to) = (range.start - start, range.end - start);
        let content = line.trim_end_matches(['\n', '\r']).len();
        if to > content {
            return None;
        }
        let after = content - to;
        let text = format!("{}{value}{}", &line[..from], &line[to..]);
        self.lines[n] = (
            text,
            Origin::Replaced {
                line: orig,
                before: from,
                after,
            },
        );
        Some(())
    }

    /// Insert `new` (without endings) after line `after`, or at the start
    /// when `None`. Each new line takes the ending of the line before it; a
    /// file without a final newline keeps none.
    pub(super) fn insert(&mut self, after: Option<usize>, new: &[String]) {
        let ending = after
            .map(|n| split_ending(&self.lines[n].0).1)
            .filter(|e| !e.is_empty())
            .or_else(|| {
                self.lines
                    .iter()
                    .map(|(l, _)| split_ending(l).1)
                    .find(|e| !e.is_empty())
            })
            .unwrap_or("\n")
            .to_owned();
        let at = after.map_or(0, |n| n + 1);
        let unterminated_tail =
            at == self.lines.len() && self.lines.last().is_some_and(|(l, _)| !l.ends_with('\n'));
        if unterminated_tail && let Some((last, _)) = self.lines.last_mut() {
            last.push_str(&ending);
        }
        let count = new.len();
        for (k, line) in new.iter().enumerate() {
            let end = if unterminated_tail && k + 1 == count {
                ""
            } else {
                ending.as_str()
            };
            self.lines
                .insert(at + k, (format!("{line}{end}"), Origin::Inserted));
        }
    }

    /// Delete lines `range`. When they include the last line of a file
    /// without a final newline, the new last line loses its ending.
    pub(super) fn delete(&mut self, range: std::ops::Range<usize>) {
        let unterminated = self.lines.last().is_some_and(|(l, _)| !l.ends_with('\n'));
        let through_end = range.end == self.lines.len();
        self.lines.drain(range);
        if unterminated
            && through_end
            && let Some((last, _)) = self.lines.last_mut()
        {
            let kept = last.trim_end_matches(['\n', '\r']).len();
            last.truncate(kept);
        }
    }

    /// Proof 2: original lines appear in order; a kept line is byte-identical
    /// (the file's last line may only gain or lose the ending a file without
    /// a final newline needs); a replaced line keeps everything around its
    /// value.
    pub(super) fn bytes_hold(&self, original: &str) -> bool {
        let orig: Vec<&str> = original.split_inclusive('\n').collect();
        // The ending an insert gives a file's unterminated last line: the
        // file's own, else `\n` (as `insert` picks it).
        let own = orig
            .iter()
            .map(|l| split_ending(l).1)
            .find(|e| !e.is_empty())
            .unwrap_or("\n");
        let mut last: Option<usize> = None;
        let count = self.lines.len();
        self.lines.iter().enumerate().all(|(n, (text, origin))| {
            let index = match origin {
                Origin::Inserted => return true,
                Origin::Kept(i) | Origin::Replaced { line: i, .. } => *i,
            };
            if last.is_some_and(|l| index <= l) || index >= orig.len() {
                return false;
            }
            last = Some(index);
            let ((text, ending), (was, was_ending)) =
                (split_ending(text), split_ending(orig[index]));
            // Endings are compared apart from content: only a file without
            // a final newline may see its last line gain one (something was
            // inserted after it) or its new last line lose one.
            let ending_holds = ending == was_ending
                || (index + 1 == orig.len() && was_ending.is_empty() && ending == own)
                || (n + 1 == count && !original.ends_with('\n') && ending.is_empty());
            ending_holds
                && match origin {
                    Origin::Kept(_) => text == was,
                    Origin::Replaced { before, after, .. } => {
                        was.len() >= before + after
                            && was.get(..*before).is_some_and(|p| text.starts_with(p))
                            && was
                                .get(was.len() - after..)
                                .is_some_and(|s| text.ends_with(s))
                    }
                    Origin::Inserted => true,
                }
        })
    }
}

use crate::yaml::{Node, Shape, Step};

use super::{ComputeRefusal, GiveUp, give_up, unprovable};

/// A file with no content: blank lines and comments only.
pub(super) fn no_content(text: &str) -> bool {
    text.lines().all(|l| {
        let l = l.trim();
        l.is_empty() || l.starts_with('#')
    })
}

/// The stable code for a field the parser refused to edit in place.
pub(super) fn refusal_code(nodes: &[Node], path: &[Segment]) -> GiveUp {
    match find(nodes, path) {
        Some(node) if node.decorated => GiveUp::Anchor,
        Some(node) if node.flow => GiveUp::Flow,
        Some(node) if !node.plain => GiveUp::NotPlainKey,
        _ => GiveUp::Other,
    }
}

/// The nodes of `text`; none for a file with no content.
pub(super) fn nodes(text: &str) -> Result<Vec<Node>, ComputeRefusal> {
    if no_content(text) {
        return Ok(Vec::new());
    }
    crate::yaml::block_nodes(text)
        .map_err(|_| unprovable("the parser gives no node positions for this file"))
}

fn same(steps: &[Step], path: &[Segment]) -> bool {
    steps.len() == path.len()
        && steps
            .iter()
            .zip(path)
            .all(|(step, segment)| match (step, segment) {
                (Step::Key(a), Segment::Key(b)) => a == b,
                (Step::Index(a), Segment::Index(b)) => a == b,
                _ => false,
            })
}

pub(super) fn find<'n>(nodes: &'n [Node], path: &[Segment]) -> Option<&'n Node> {
    let mut found = nodes.iter().filter(|n| same(&n.path, path));
    match (found.next(), found.next()) {
        (Some(node), None) => Some(node),
        _ => None,
    }
}

/// How many direct children `parent` has.
pub(super) fn child_count(nodes: &[Node], parent: &Node) -> usize {
    children(nodes, parent).count()
}

/// The direct children of `parent`, in document order.
fn children<'n>(nodes: &'n [Node], parent: &Node) -> impl Iterator<Item = &'n Node> {
    let depth = parent.path.len();
    let prefix = parent.path.clone();
    nodes
        .iter()
        .filter(move |n| n.path.len() == depth + 1 && n.path[..depth] == prefix[..])
}

/// The column of byte `at` within its line.
fn column(text: &str, at: usize) -> usize {
    at - text[..at].rfind('\n').map_or(0, |n| n + 1)
}

/// Why `node` cannot take a new child.
fn closed(nodes: &[Node], node: &Node, next: &Segment) -> Option<ComputeRefusal> {
    let empty = children(nodes, node).next().is_none();
    let refusal = match node.shape {
        _ if node.decorated => give_up(GiveUp::Anchor, "a node on the path has an anchor or a tag"),
        Shape::Sequence if node.flow && empty => {
            give_up(GiveUp::NullSequence, "the list is written empty inline")
        }
        Shape::Mapping if node.flow && empty => {
            give_up(GiveUp::InlineEmpty, "the mapping is written empty inline")
        }
        _ if node.flow => give_up(GiveUp::Flow, "a flow collection is on the path"),
        Shape::Mapping if matches!(next, Segment::Index(_)) => {
            unprovable("a list position under a mapping")
        }
        Shape::Sequence if matches!(next, Segment::Key(_)) => unprovable("a key under a list"),
        _ if !node.plain => give_up(GiveUp::NotPlainKey, "a key on the path is not a plain key"),
        _ => return None,
    };
    Some(refusal)
}

/// The new lines for `rest` under a node whose content starts at column
/// `col`: keys, then `- ` for a list position, the value on the last line.
fn new_lines(rest: &[Segment], mut col: usize, value: &str) -> Result<Vec<String>, ComputeRefusal> {
    let mut out = Vec::new();
    let mut dash = false;
    for (j, segment) in rest.iter().enumerate() {
        let last = j + 1 == rest.len();
        match segment {
            Segment::Index(_) => {
                if last || dash {
                    return Err(unprovable("a list item that is not a mapping"));
                }
                dash = true;
                col += 2;
            }
            Segment::Key(key) => {
                let lead = if dash {
                    format!("{}- ", " ".repeat(col - 2))
                } else {
                    " ".repeat(col)
                };
                dash = false;
                out.push(if last {
                    format!("{lead}{key}: {value}")
                } else {
                    format!("{lead}{key}:")
                });
                col += 2;
            }
        }
    }
    Ok(out)
}

/// Set the field at `path` to the rendered `value`: in place when it exists,
/// else inserted with its missing parents.
pub(super) fn place(
    lines: &mut Lines,
    path: &[Segment],
    value: &str,
) -> Result<(), ComputeRefusal> {
    let text = lines.text();
    let nodes = nodes(&text)?;
    if let Some(node) = find(&nodes, path) {
        return match node.shape {
            Shape::Scalar { empty: false } if node.plain && !node.decorated => lines
                .replace(node.bytes.clone(), value)
                .ok_or_else(|| unprovable("the value runs past the end of its line")),
            _ if node.decorated => Err(give_up(
                GiveUp::Anchor,
                "the value has an anchor, a tag or an alias",
            )),
            _ if node.flow => Err(give_up(
                GiveUp::Flow,
                "the field is inside a flow collection",
            )),
            Shape::Scalar { .. } => Err(unprovable("the field is not one plain scalar")),
            _ => Err(unprovable("the field is a collection, not a value")),
        };
    }
    // The deepest existing node on the path (the root, when there is one).
    let (depth, anchor) = (0..path.len())
        .rev()
        .find_map(|d| find(&nodes, &path[..d]).map(|n| (d, Some(n))))
        .unwrap_or((0, None));
    let rest = &path[depth..];
    let (col, after) = match anchor {
        // An empty file: the root mapping starts at column 0.
        None if nodes.is_empty() => (0, lines.len().checked_sub(1)),
        None => return Err(unprovable("the file has no root mapping")),
        Some(node) => {
            if let Some(refusal) = attach_refusal(&nodes, node, &rest[0]) {
                return Err(refusal);
            }
            if let Shape::Scalar { .. } = node.shape {
                let key = node
                    .key
                    .clone()
                    .ok_or_else(|| unprovable("an empty list item"))?;
                (column(&text, key.start) + 2, Some(lines.line_of(key.start)))
            } else {
                let first = children(&nodes, node)
                    .next()
                    .ok_or_else(|| unprovable("an empty collection"))?;
                let col = if node.shape == Shape::Sequence {
                    let Segment::Index(at) = rest[0] else {
                        return Err(unprovable("a key under a list"));
                    };
                    if at != children(&nodes, node).count() {
                        return Err(give_up(
                            GiveUp::SequenceShape,
                            "a new list position past the end",
                        ));
                    }
                    // The dash sits two columns before the element's content.
                    column(&text, first.bytes.start)
                        .checked_sub(2)
                        .ok_or_else(|| unprovable("a list item's dash"))?
                } else {
                    column(&text, first.start)
                };
                (col, Some(lines.line_of(node.end.saturating_sub(1))))
            }
        }
    };
    let new = new_lines(rest, col, value)?;
    lines.insert(after, &new);
    Ok(())
}

/// Why nothing can be attached under `node` for step `next`.
fn attach_refusal(nodes: &[Node], node: &Node, next: &Segment) -> Option<ComputeRefusal> {
    match node.shape {
        Shape::Scalar { empty: true } if node.plain => None,
        Shape::Scalar { .. } if matches!(next, Segment::Index(_)) => Some(give_up(
            GiveUp::NullSequence,
            "the list is written as a null value",
        )),
        Shape::Scalar { .. } => Some(unprovable("a value is in the way")),
        _ => closed(nodes, node, next),
    }
}

/// Delete the entry at `path` and the lines under it. A missing entry is a
/// no-op (`Ok(false)`). Gives up rather than delete operator text: a `#`
/// anywhere in the deleted lines, or a comment line indented under the
/// entry right after them.
pub(super) fn remove_entry(lines: &mut Lines, path: &[Segment]) -> Result<bool, ComputeRefusal> {
    let text = lines.text();
    let nodes = nodes(&text)?;
    let Some(node) = find(&nodes, path) else {
        return Ok(false);
    };
    if node.decorated {
        return Err(give_up(
            GiveUp::Anchor,
            "the entry has an anchor, a tag or an alias",
        ));
    }
    if node.flow {
        return Err(give_up(
            GiveUp::Flow,
            "the entry is inside a flow collection",
        ));
    }
    let Some(key) = node.key.clone() else {
        return Err(give_up(
            GiveUp::SequenceShape,
            "a list element would be removed",
        ));
    };
    let first = lines.line_of(key.start);
    let key_col = column(&text, key.start);
    if lines.content(first)[..key_col].trim_end().ends_with('-') {
        return Err(give_up(
            GiveUp::DashLine,
            "the key sits on its element's dash line",
        ));
    }
    let mut last = lines.line_of(node.end.saturating_sub(1).max(key.start));
    // Comment and blank lines indented under the entry belong to it.
    // Blank lines between them do not end that.
    let mut next = last + 1;
    while next < lines.len() {
        let line = lines.content(next);
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            next += 1;
            continue;
        }
        if !trimmed.starts_with('#') || line.len() - trimmed.len() <= key_col {
            break;
        }
        last = next;
        next += 1;
    }
    if (first..=last).any(|n| lines.content(n).contains('#')) {
        return Err(give_up(GiveUp::Comment, "a deleted line carries a comment"));
    }
    lines.delete(first..last + 1);
    Ok(true)
}

/// After the removals: every mapping on a removed path's way that was a
/// mapping in `before` and is now empty goes too, deepest first.
pub(super) fn drop_emptied(
    lines: &mut Lines,
    before: &[Node],
    removed: &[&[Segment]],
) -> Result<(), ComputeRefusal> {
    let mut parents: Vec<&[Segment]> = removed
        .iter()
        .flat_map(|path| (1..path.len()).map(move |d| &path[..d]))
        .filter(|p| matches!(p.last(), Some(Segment::Key(_))))
        .collect();
    parents.sort_by_key(|p| std::cmp::Reverse(p.len()));
    parents.dedup();
    for parent in parents {
        let was_mapping = find(before, parent).is_some_and(|n| n.shape == Shape::Mapping);
        let now = nodes(&lines.text())?;
        let emptied = find(&now, parent).is_some_and(|n| n.shape == Shape::Scalar { empty: true });
        if was_mapping && emptied {
            remove_entry(lines, parent)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "config_persistence_keyedit_shape_tests.rs"]
mod tests;
