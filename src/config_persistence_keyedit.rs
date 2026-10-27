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

/// The field a secret slot belongs to: its dotted path, the same text as the
/// secret's `NewSecretOwned::field`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SlotId(pub(crate) String);

/// The keys from the document root to one existing scalar field. Each segment
/// is a key the file already holds, so a runtime backend name is a segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldPath(pub(crate) Vec<String>);

/// A value a field is set to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Scalar {
    Str(String),
    Int(i64),
    Bool(bool),
}

/// One change to one existing field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Change {
    Set(Scalar),
    /// The field becomes a slot the byte writer fills with a store reference.
    Secret(SlotId),
}

/// Why an edit was refused. Nothing is written for any of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ComputeRefusal {
    /// The edit cannot be proven in place: the caller offers a patch instead.
    Unprovable { reason: String },
    /// The template's slots and the save's secret values name different fields.
    SlotMismatch,
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
            let at_path = id.0.split('.').fold(&doc, |node, key| &node[key]);
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
            && id.0 != path.0.join(".")
        {
            return Err(ComputeRefusal::SlotMismatch);
        }
        let field = locate(original, &lines, &spans, path)?;
        let new_value = match change {
            Change::Set(Scalar::Str(s)) => crate::yaml::double_quoted(s),
            Change::Set(Scalar::Int(n)) => n.to_string(),
            Change::Set(Scalar::Bool(b)) => b.to_string(),
            Change::Secret(id) => quoted_placeholder(id),
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
                _ => return Err(ComputeRefusal::SlotMismatch),
            }
        }
    }
    slots.sort_by_key(|(_, range)| range.start);
    Template::checked(edited.into_bytes(), slots)
}

fn unprovable(reason: &str) -> ComputeRefusal {
    ComputeRefusal::Unprovable {
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
    if !path.0.iter().all(|s| plain_key(s)) {
        return Err(unprovable("a path segment is not a plain key"));
    }
    let mut found = spans.iter().filter(|s| s.path == path.0);
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
    format!("__mcpgw_slot_{}__", id.0)
}

/// The placeholder as the scalar text written into the file.
fn quoted_placeholder(id: &SlotId) -> String {
    crate::yaml::double_quoted(&placeholder(id))
}

/// The value `change` gives its field in the expected document.
fn expected_value(change: &Change) -> Value {
    match change {
        Change::Set(Scalar::Str(s)) => Value::from(s.as_str()),
        Change::Set(Scalar::Int(n)) => Value::from(*n),
        Change::Set(Scalar::Bool(b)) => Value::from(*b),
        Change::Secret(id) => Value::from(placeholder(id)),
    }
}

/// Proof 1: `edited` parses to `original` with exactly `changes` applied,
/// each secret slot holding its own placeholder. Value equality only: the
/// parser's spans refuse anchors, aliases and tags before this runs.
fn meaning_holds(original: &str, changes: &[(FieldPath, Change)], edited: &str) -> bool {
    let Ok(mut want) = crate::yaml::from_str::<Value>(original) else {
        return false;
    };
    for (path, change) in changes {
        let mut node = &mut want;
        for key in &path.0 {
            let Some(next) = node.as_mapping_mut().and_then(|m| m.get_mut(key.as_str())) else {
                return false;
            };
            node = next;
        }
        *node = expected_value(change);
    }
    crate::yaml::from_str::<Value>(edited).is_ok_and(|got| got == want)
}

#[cfg(test)]
#[path = "config_persistence_keyedit_tests.rs"]
mod tests;
