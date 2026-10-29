// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Editing existing scalar fields of `gateway.yaml` in place, so a UI save
//! keeps every comment and untouched byte (ADR-024). Each change rewrites the
//! value of one key that already exists; anything this cannot prove right is
//! `Unprovable`, and nothing is written. Creating keys and removing them come
//! later, with their own design.
//!
//! A secret field is written as a slot: a placeholder the byte writer fills
//! with the store reference it creates, after this edit has been proven.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "first callers: the byte writer's secret step and the web UI save core"
    )
)]

use std::collections::BTreeMap;
use std::ops::Range;

use crate::yaml::{Value, ValueSpan};

use super::eol::{Line, render};

/// One step from a node to a child: a mapping key, or a position in a block
/// sequence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Segment {
    Key(String),
    Index(usize),
}

/// The field a secret slot belongs to: its path from the root. The one path
/// type for slots, secret-step fields and patches.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SlotId(pub(crate) Vec<Segment>);

impl SlotId {
    /// The one string form, the secret's `NewSecretOwned::field`: keys joined
    /// by `.`, a position as `[n]`. Unambiguous because every key segment is
    /// a plain key (letters, digits, `_`, `-`); nothing parses it back.
    pub(crate) fn display(&self) -> String {
        let mut out = String::new();
        for segment in &self.0 {
            match segment {
                Segment::Key(key) => {
                    if !out.is_empty() {
                        out.push('.');
                    }
                    out.push_str(key);
                }
                Segment::Index(at) => out.push_str(&format!("[{at}]")),
            }
        }
        out
    }
}

/// The path from the document root to one field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldPath(pub(crate) Vec<Segment>);

impl FieldPath {
    /// The slot a secret at this path fills.
    pub(crate) fn slot(&self) -> SlotId {
        SlotId(self.0.clone())
    }

    /// The path as mapping keys alone, or `None` when it steps into a
    /// sequence.
    fn keys(&self) -> Option<Vec<String>> {
        self.0
            .iter()
            .map(|segment| match segment {
                Segment::Key(key) => Some(key.clone()),
                Segment::Index(_) => None,
            })
            .collect()
    }
}

/// A finite float: NaN and the infinities have no YAML form a reload reads
/// back as the same number.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct FiniteF64(f64);

impl FiniteF64 {
    pub(crate) fn new(value: f64) -> Option<Self> {
        value.is_finite().then_some(Self(value))
    }
}

// No NaN is ever held, so equality is total.
impl Eq for FiniteF64 {}

/// A value a field is set to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Scalar {
    Str(String),
    Int(i64),
    Bool(bool),
    Num(FiniteF64),
}

/// One change to one field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Change {
    Set(Scalar),
    /// The field becomes a slot the byte writer fills with a store reference.
    Secret(SlotId),
    /// The field's key is deleted.
    Remove,
}

/// Why an edit was refused. Nothing is written for any of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ComputeRefusal {
    /// The edit cannot be proven in place: the caller offers a patch instead.
    Unprovable { code: GiveUp, reason: String },
    /// The template's slots and the save's secret values name different fields.
    SlotMismatch,
}

/// A stable, machine-readable cause for `Unprovable`, carried into the patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GiveUp {
    /// A line the edit would delete carries operator text.
    Comment,
    /// A flow collection where a block one is needed.
    Flow,
    /// An anchor, alias or tag on a node the edit touches.
    Anchor,
    /// A parent written as an inline empty collection (`{}`, `[]`).
    InlineEmpty,
    /// A sequence written as `~`, `null` or `[]`.
    NullSequence,
    /// A key on an element's dash line would be removed.
    DashLine,
    /// Reordering, deleting, or skipping sequence elements.
    SequenceShape,
    /// A path segment is not a plain key.
    NotPlainKey,
    /// The file or the edit is outside what the proofs cover.
    Other,
}

impl GiveUp {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Comment => "comment",
            Self::Flow => "flow",
            Self::Anchor => "anchor",
            Self::InlineEmpty => "inline_empty",
            Self::NullSequence => "null_sequence",
            Self::DashLine => "dash_line",
            Self::SequenceShape => "sequence_shape",
            Self::NotPlainKey => "not_plain_key",
            Self::Other => "other",
        }
    }
}

/// New file bytes, with the byte range of each secret slot still to fill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Template {
    bytes: Vec<u8>,
    slots: Vec<(SlotId, Range<usize>)>,
}

impl Template {
    /// A template whose every slot range holds exactly its own field's
    /// placeholder, in order and disjoint; anything else is refused, so a
    /// slot can never be filled with another field's reference.
    fn checked(bytes: Vec<u8>, slots: Vec<(SlotId, Range<usize>)>) -> Result<Self, ComputeRefusal> {
        let text = std::str::from_utf8(&bytes).map_err(|_| ComputeRefusal::SlotMismatch)?;
        let mut end = 0;
        let mut seen = std::collections::BTreeSet::new();
        for (id, range) in &slots {
            let holds_own = range.start >= end
                && text.get(range.clone()) == Some(quoted_placeholder(id).as_str());
            if !holds_own || !seen.insert(id) {
                return Err(ComputeRefusal::SlotMismatch);
            }
            end = range.end;
        }
        Ok(Self { bytes, slots })
    }

    /// The bytes as they stand, slots still holding their placeholders.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The bytes with each slot replaced by the reference made for its own
    /// field, written as a double-quoted scalar. `SlotMismatch` when `refs`
    /// does not name exactly the template's slots; the writer checks that
    /// before any entry exists, so it is never reached after one.
    pub(crate) fn fill(self, refs: &BTreeMap<SlotId, String>) -> Result<Vec<u8>, ComputeRefusal> {
        if refs.len() != self.slots.len() || self.slots.iter().any(|(id, _)| !refs.contains_key(id))
        {
            return Err(ComputeRefusal::SlotMismatch);
        }
        let mut out = Vec::with_capacity(self.bytes.len());
        let mut at = 0;
        for (id, range) in &self.slots {
            out.extend_from_slice(&self.bytes[at..range.start]);
            out.extend_from_slice(crate::yaml::double_quoted(&refs[id]).as_bytes());
            at = range.end;
        }
        out.extend_from_slice(&self.bytes[at..]);
        // Re-read: each reference must be the value at its own path.
        let text = String::from_utf8(out).map_err(|_| ComputeRefusal::SlotMismatch)?;
        let doc: Value = crate::yaml::from_str(&text).map_err(|_| ComputeRefusal::SlotMismatch)?;
        for (id, _) in &self.slots {
            let at_path = id.0.iter().fold(&doc, |node, segment| match segment {
                Segment::Key(key) => &node[key.as_str()],
                Segment::Index(at) => &node[*at],
            });
            if at_path.as_str() != Some(refs[id].as_str()) {
                return Err(ComputeRefusal::SlotMismatch);
            }
        }
        Ok(text.into_bytes())
    }
}

/// `original` with each change applied in place, or why it cannot be.
pub(crate) fn edit_in_place(
    original: &str,
    changes: &[(FieldPath, Change)],
) -> Result<Template, ComputeRefusal> {
    whole_file_is_plain(original)?;
    no_overlap(changes)?;
    let spans = crate::yaml::mapping_values(original)
        .map_err(|_| unprovable("the parser gives no value positions for this file"))?;
    let lines: Vec<&str> = original
        .split('\n')
        .map(|l| l.trim_end_matches('\r'))
        .collect();
    let mut out: Vec<Line> = (0..original.split_inclusive('\n').count())
        .map(Line::Kept)
        .collect();
    let mut edits = Vec::with_capacity(changes.len());
    for (path, change) in changes {
        // A slot is named by its own field's path, never another's.
        if let Change::Secret(id) = change
            && *id != path.slot()
        {
            return Err(ComputeRefusal::SlotMismatch);
        }
        let field = locate(original, &lines, &spans, path)?;
        let new_value = match change {
            Change::Set(Scalar::Str(s)) => crate::yaml::double_quoted(s),
            Change::Set(Scalar::Int(n)) => n.to_string(),
            Change::Set(Scalar::Bool(b)) => b.to_string(),
            Change::Secret(id) => quoted_placeholder(id),
            Change::Set(Scalar::Num(_)) | Change::Remove => {
                return Err(unprovable("not supported yet"));
            }
        };
        let line = lines[field.line];
        let text = format!(
            "{}{new_value}{}",
            &line[..field.value.start],
            &line[field.value.end..]
        );
        out[field.line] = Line::Replaced(field.line, text);
        edits.push(field);
    }
    let edited = render(original, &out);
    if !bytes_hold(original, &edited, &edits) {
        return Err(unprovable("an untouched line changed"));
    }
    if !meaning_holds(original, changes, &edited) {
        return Err(unprovable(
            "the edited file does not mean the original plus the changes",
        ));
    }
    let mut slots = Vec::new();
    for (_, change) in changes {
        if let Change::Secret(id) = change {
            let quoted = quoted_placeholder(id);
            let mut found = edited.match_indices(quoted.as_str());
            match (found.next(), found.next()) {
                (Some((at, _)), None) => slots.push((id.clone(), at..at + quoted.len())),
                // The file already held this placeholder text: refuse.
                _ => return Err(unprovable("the file already holds a slot placeholder")),
            }
        }
    }
    slots.sort_by_key(|(_, range)| range.start);
    Template::checked(edited.into_bytes(), slots)
}

fn unprovable(reason: &str) -> ComputeRefusal {
    give_up(GiveUp::Other, reason)
}

fn give_up(code: GiveUp, reason: &str) -> ComputeRefusal {
    ComputeRefusal::Unprovable {
        code,
        reason: reason.to_owned(),
    }
}

/// One located field: its line, and the byte range of its value text on
/// that line (an inline comment after it stays outside the range).
struct Located {
    line: usize,
    value: Range<usize>,
}

/// One block-mapping document this module can reason about: no byte order
/// mark, no directive or document marker, no duplicate key (the parser
/// refuses those), and a mapping at the root.
fn whole_file_is_plain(original: &str) -> Result<(), ComputeRefusal> {
    if original.starts_with('\u{feff}') {
        return Err(unprovable("the file starts with a byte order mark"));
    }
    let marker = |l: &str| l.starts_with("---") || l.starts_with("...") || l.starts_with('%');
    if original.lines().any(marker) {
        return Err(unprovable("the file has a document marker or directive"));
    }
    match crate::yaml::from_str::<Value>(original) {
        Ok(Value::Mapping(_)) => Ok(()),
        _ => Err(unprovable("the file is not one mapping the parser accepts")),
    }
}

/// No change touches a field another change also touches, or one inside it.
fn no_overlap(changes: &[(FieldPath, Change)]) -> Result<(), ComputeRefusal> {
    for (i, (a, _)) in changes.iter().enumerate() {
        for (b, _) in &changes[i + 1..] {
            if a.0.starts_with(&b.0) || b.0.starts_with(&a.0) {
                return Err(unprovable("two changes touch the same field"));
            }
        }
    }
    Ok(())
}

/// Proof 2, on the rendered bytes: the same number of lines; every line no
/// change touched is byte-identical, ending included; and an edited line
/// keeps everything before and after its value.
fn bytes_hold(original: &str, edited: &str, edits: &[Located]) -> bool {
    let before: Vec<&str> = original.split_inclusive('\n').collect();
    let after: Vec<&str> = edited.split_inclusive('\n').collect();
    if before.len() != after.len() {
        return false;
    }
    before
        .iter()
        .zip(&after)
        .enumerate()
        .all(
            |(at, (old, new))| match edits.iter().find(|e| e.line == at) {
                None => old == new,
                Some(e) => {
                    new.starts_with(&old[..e.value.start]) && new.ends_with(&old[e.value.end..])
                }
            },
        )
}

/// A segment this module can address: letters, digits, `_` and `-`, read by
/// YAML as that same string (not a number, a bool or null).
fn plain_key(segment: &str) -> bool {
    segment
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && crate::yaml::from_str::<Value>(segment).is_ok_and(|v| v.as_str() == Some(segment))
}

/// The line and in-line byte range of `path`'s value, as the parser placed
/// it: exactly one scalar value at that path, one the parser's spans allow
/// replacing in place.
fn locate(
    original: &str,
    lines: &[&str],
    spans: &[ValueSpan],
    path: &FieldPath,
) -> Result<Located, ComputeRefusal> {
    let Some(keys) = path.keys() else {
        return Err(unprovable("not supported yet"));
    };
    if !keys.iter().all(|s| plain_key(s)) {
        return Err(give_up(
            GiveUp::NotPlainKey,
            "a path segment is not a plain key",
        ));
    }
    let mut found = spans.iter().filter(|s| s.path == keys);
    let (Some(span), None) = (found.next(), found.next()) else {
        return Err(unprovable("the field is not one scalar value in the file"));
    };
    if let Some(why) = span.refused {
        return Err(unprovable(why));
    }
    // Byte accounting over the raw lines, endings included; the length
    // check over the same line without its ending.
    let mut line_start = 0;
    for (line, raw) in original.split_inclusive('\n').enumerate() {
        let text = lines[line];
        let next = line_start + raw.len();
        if span.bytes.start < next {
            let value = span.bytes.start - line_start..span.bytes.end - line_start;
            if value.end > text.len() {
                return Err(unprovable("the value runs past the end of its line"));
            }
            return Ok(Located { line, value });
        }
        line_start = next;
    }
    Err(unprovable("the value lies outside the file"))
}

/// The text a secret slot holds until the writer fills it: unique per path,
/// so a slot can only ever be read back under its own field.
fn placeholder(id: &SlotId) -> String {
    format!("__mcpgw_slot_{}__", id.display())
}

/// The placeholder as the scalar text written into the file.
fn quoted_placeholder(id: &SlotId) -> String {
    crate::yaml::double_quoted(&placeholder(id))
}

/// The value `change` gives its field in the expected document; `None` for
/// a removal.
fn expected_value(change: &Change) -> Option<Value> {
    Some(match change {
        Change::Set(Scalar::Str(s)) => Value::from(s.as_str()),
        Change::Set(Scalar::Int(n)) => Value::from(*n),
        Change::Set(Scalar::Bool(b)) => Value::from(*b),
        Change::Set(Scalar::Num(n)) => Value::from(n.0),
        Change::Secret(id) => Value::from(placeholder(id)),
        Change::Remove => return None,
    })
}

/// Proof 1: `edited` parses to `original` with exactly `changes` applied,
/// each secret slot holding its own placeholder. Value equality only: the
/// parser's spans refuse anchors, aliases and tags before this runs.
fn meaning_holds(original: &str, changes: &[(FieldPath, Change)], edited: &str) -> bool {
    let Ok(mut want) = crate::yaml::from_str::<Value>(original) else {
        return false;
    };
    for (path, change) in changes {
        let Some(keys) = path.keys() else {
            return false;
        };
        let mut node = &mut want;
        for key in &keys {
            let Some(next) = node.as_mapping_mut().and_then(|m| m.get_mut(key.as_str())) else {
                return false;
            };
            node = next;
        }
        let Some(value) = expected_value(change) else {
            return false;
        };
        *node = value;
    }
    crate::yaml::from_str::<Value>(edited).is_ok_and(|got| got == want)
}

#[cfg(test)]
#[path = "config_persistence_keyedit_tests.rs"]
mod tests;
