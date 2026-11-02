// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Editing `gateway.yaml` in place, so a UI save keeps every comment and
//! untouched byte (ADR-024). A change sets a field's value (inserting the key,
//! and any missing parents, when it is absent), makes it a secret slot, or
//! removes the key; a list may gain one new element, at its end, which also
//! creates a missing list. One `auth.api_keys` element may be removed (the
//! web UI's key revoke): its lines go, with the comments on them reported by
//! original line number, and so do a list and parent it empties. Anything
//! the meaning and bytes proofs cannot cover is `Unprovable`, and nothing is
//! written: among those, removing any other list element, reordering list
//! elements, removing a key that sits on its element's dash line, and
//! deleting a line that carries a comment outside a revocation.
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

use crate::yaml::Value;

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
                Segment::Index(at) => {
                    out.push('[');
                    out.push_str(&at.to_string());
                    out.push(']');
                }
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
    /// The original 1-based lines whose comment the edit dropped.
    dropped: Vec<usize>,
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
            let held = text.get(range.clone());
            let holds_own = range.start >= end
                && (held == Some(quoted_placeholder(id).as_str())
                    || held == Some(placeholder(id).as_str()));
            if !holds_own || !seen.insert(id) {
                return Err(ComputeRefusal::SlotMismatch);
            }
            end = range.end;
        }
        Ok(Self {
            bytes,
            slots,
            dropped: Vec::new(),
        })
    }

    /// The original 1-based line numbers of the comment lines this edit
    /// dropped, sorted: a list element's removal takes its comments with it.
    /// Line numbers only, never text: a `#` in a value can be a secret.
    pub(crate) fn dropped_comments(&self) -> &[usize] {
        &self.dropped
    }

    /// The bytes as they stand, slots still holding their placeholders.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Bytes with no secret slot: what a writer with no secret entries
    /// returns.
    pub(crate) fn plain(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            slots: Vec::new(),
            dropped: Vec::new(),
        }
    }

    /// The fields this template's slots belong to.
    pub(crate) fn slot_ids(&self) -> impl Iterator<Item = &SlotId> {
        self.slots.iter().map(|(id, _)| id)
    }

    /// A template from bytes another writer produced (the backend splice)
    /// that hold each of `ids`' placeholders exactly once, quoted or bare;
    /// `SlotMismatch` otherwise.
    pub(crate) fn from_placeholders(
        bytes: Vec<u8>,
        ids: &[SlotId],
    ) -> Result<Self, ComputeRefusal> {
        let text = std::str::from_utf8(&bytes).map_err(|_| ComputeRefusal::SlotMismatch)?;
        let once = |needle: &str| {
            let mut found = text.match_indices(needle);
            match (found.next(), found.next()) {
                (Some((at, _)), None) => Some(at..at + needle.len()),
                _ => None,
            }
        };
        let mut slots = Vec::with_capacity(ids.len());
        for id in ids {
            let range = once(&quoted_placeholder(id))
                .or_else(|| once(&placeholder(id)))
                .ok_or(ComputeRefusal::SlotMismatch)?;
            slots.push((id.clone(), range));
        }
        slots.sort_by_key(|(_, range)| range.start);
        Self::checked(bytes, slots)
    }

    /// The text a slot holds until it is filled, for a writer that builds
    /// its bytes another way.
    pub(crate) fn placeholder_for(id: &SlotId) -> String {
        placeholder(id)
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

/// `original` with each change applied in place, or why it cannot be. All
/// changes apply to one evolving text: values set and keys inserted first,
/// in order, then removals, then the mappings the removals emptied; the two
/// proofs then compare the final text with the original.
pub(crate) fn edit_in_place(
    original: &str,
    changes: &[(FieldPath, Change)],
) -> Result<Template, ComputeRefusal> {
    whole_file_is_plain(original)?;
    no_overlap(changes)?;
    for (path, change) in changes {
        // A slot is named by its own field's path, never another's.
        if let Change::Secret(id) = change
            && *id != path.slot()
        {
            return Err(ComputeRefusal::SlotMismatch);
        }
        let plain = path.0.iter().all(|segment| match segment {
            Segment::Key(key) => plain_key(key),
            Segment::Index(_) => true,
        });
        if !plain {
            return Err(give_up(
                GiveUp::NotPlainKey,
                "a path segment is not a plain key",
            ));
        }
    }
    let before = shape::nodes(original)?;
    let revoked = one_revocation(changes)?;
    if let Some(path) = revoked
        && let Some(i) = revoke::revoked_index(path)
        && let Some(refusal) = revoke::refusal(original, &before, i)
    {
        return Err(refusal);
    }
    one_new_element(&before, changes)?;
    let mut lines = shape::Lines::new(original);
    for (path, change) in changes {
        let Some(value) = rendered(change) else {
            continue;
        };
        match path.keys() {
            Some(keys) => set_keyed(&mut lines, path, &keys, &value)?,
            None => shape::place(&mut lines, &path.0, &value)?,
        }
    }
    let mut removed: Vec<&[Segment]> = Vec::new();
    for (path, change) in changes {
        if *change != Change::Remove {
            continue;
        }
        let gone = if revoked == Some(path.0.as_slice()) {
            revoke::remove_element(&mut lines, &path.0)?
        } else {
            shape::remove_entry(&mut lines, &path.0, shape::CommentRule::Refuse)?
        };
        if gone {
            removed.push(&path.0);
        }
    }
    shape::drop_emptied(&mut lines, &before, &removed, revoked)?;
    let edited = lines.text();
    let dropped = match revoked {
        Some(path) => deleted_as_planned(original, &before, &removed, path, &lines, &edited)?,
        None => Vec::new(),
    };
    if !lines.bytes_hold(original) {
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
    let mut template = Template::checked(edited.into_bytes(), slots)?;
    template.dropped = dropped;
    Ok(template)
}

/// The one list-element removal a save may hold (S7, S8): of
/// `auth.api_keys`, with no other change in that list. `None` when the
/// save removes no element.
fn one_revocation(changes: &[(FieldPath, Change)]) -> Result<Option<&[Segment]>, ComputeRefusal> {
    let mut elements = changes
        .iter()
        .filter(|(p, c)| *c == Change::Remove && matches!(p.0.last(), Some(Segment::Index(_))));
    let Some((path, _)) = elements.next() else {
        return Ok(None);
    };
    if revoke::revoked_index(&path.0).is_none() {
        return Err(give_up(
            GiveUp::SequenceShape,
            "only an `auth.api_keys` element may be removed",
        ));
    }
    let list = &path.0[..2];
    // Counted by occurrence: the revocation is the one change under the list.
    let alone = elements.next().is_none()
        && changes
            .iter()
            .filter(|(p, _)| p.0.starts_with(list))
            .count()
            == 1;
    if !alone {
        return Err(give_up(
            GiveUp::SequenceShape,
            "a removed list element must be the save's only change in its list",
        ));
    }
    Ok(Some(path.0.as_slice()))
}

/// S5 and S4 for a save holding a revocation: the original lines the edit
/// deleted are exactly the lines its removals may delete, judged on the original text apart
/// from the edit (the element, each removed key, each entry the cascade
/// emptied); else `Unprovable`. Returns the deleted lines that carried a
/// comment, 1-based.
fn deleted_as_planned(
    original: &str,
    before: &[crate::yaml::Node],
    removed: &[&[Segment]],
    revoked: &[Segment],
    lines: &shape::Lines,
    edited: &str,
) -> Result<Vec<usize>, ComputeRefusal> {
    let after = shape::nodes(edited)?;
    let mut allowed = std::collections::BTreeSet::new();
    let mut take = |path: &[Segment], taken| {
        if let Some(node) = shape::find(before, path) {
            allowed.extend(revoke::may_delete(original, node, taken));
        }
    };
    for &path in removed {
        let taken = if path == revoked {
            revoke::Taken::Element
        } else {
            revoke::Taken::Entry
        };
        take(path, taken);
        // A parent the removal emptied went with it.
        for d in 1..path.len() {
            let parent = &path[..d];
            if matches!(parent.last(), Some(Segment::Key(_)))
                && shape::find(&after, parent).is_none()
            {
                take(parent, revoke::Taken::Entry);
            }
        }
    }
    let surviving = lines.surviving();
    let deleted: std::collections::BTreeSet<usize> = (0..original.split_inclusive('\n').count())
        .filter(|n| !surviving.contains(n))
        .collect();
    // Equal, not a subset: a deletion one comment line short keeps the
    // meaning, so only this comparison sees it.
    if deleted != allowed {
        return Err(unprovable(
            "the deleted lines are not the removed entries' lines",
        ));
    }
    Ok(super::comments::comment_line_numbers(original, &deleted))
}

/// The value text `change` writes; `None` for a removal.
fn rendered(change: &Change) -> Option<String> {
    Some(match change {
        Change::Set(Scalar::Str(s)) => crate::yaml::double_quoted(s),
        Change::Set(Scalar::Int(n)) => n.to_string(),
        Change::Set(Scalar::Bool(b)) => b.to_string(),
        Change::Set(Scalar::Num(n)) => float_text(n.0),
        Change::Secret(id) => quoted_placeholder(id),
        Change::Remove => return None,
    })
}

/// A float always written with a decimal point, so it reads back as a
/// float: `2.0`, `1.0e300`.
fn float_text(value: f64) -> String {
    let shortest = format!("{value:?}");
    if shortest.contains('.') {
        return shortest;
    }
    match shortest.split_once('e') {
        Some((mantissa, exponent)) => format!("{mantissa}.0e{exponent}"),
        None => format!("{shortest}.0"),
    }
}

/// Set a field reached through mapping keys alone: in place, by the
/// parser's own span, when it exists; inserted otherwise.
fn set_keyed(
    lines: &mut shape::Lines,
    path: &FieldPath,
    keys: &[String],
    value: &str,
) -> Result<(), ComputeRefusal> {
    let text = lines.text();
    if shape::no_content(&text) {
        return shape::place(lines, &path.0, value);
    }
    let spans = crate::yaml::mapping_values(&text)
        .map_err(|_| unprovable("the parser gives no value positions for this file"))?;
    let mut found = spans.iter().filter(|s| s.path == keys);
    match (found.next(), found.next()) {
        (Some(span), None) => {
            if let Some(why) = span.refused {
                let code = shape::refusal_code(&shape::nodes(&text)?, &path.0);
                return Err(give_up(code, why));
            }
            lines
                .replace(span.bytes.clone(), value)
                .ok_or_else(|| unprovable("the value runs past the end of its line"))
        }
        (None, _) => shape::place(lines, &path.0, value),
        _ => Err(unprovable("the field is not one scalar value in the file")),
    }
}

/// A save appends at most one new element to a list, at its end: every new
/// position names the list's length as the file holds it.
fn one_new_element(
    before: &[crate::yaml::Node],
    changes: &[(FieldPath, Change)],
) -> Result<(), ComputeRefusal> {
    let mut new: BTreeMap<Vec<Segment>, usize> = BTreeMap::new();
    // A removal past a list's end is a no-op, never a new element.
    for (path, _) in changes.iter().filter(|(_, c)| *c != Change::Remove) {
        for (d, segment) in path.0.iter().enumerate() {
            let Segment::Index(at) = segment else {
                continue;
            };
            let list = &path.0[..d];
            let len = shape::find(before, list).map_or(0, |n| shape::child_count(before, n));
            if *at < len {
                continue;
            }
            let earlier = new.insert(list.to_vec(), *at);
            if *at != len || earlier.is_some_and(|e| e != *at) {
                return Err(give_up(
                    GiveUp::SequenceShape,
                    "only one new list element, at the list's end",
                ));
            }
        }
    }
    Ok(())
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
    // A carriage return ends a line only before a line feed here; a bare one
    // would let a "line" hold two keys.
    if original
        .split('\r')
        .skip(1)
        .any(|rest| !rest.starts_with('\n'))
    {
        return Err(unprovable(
            "an untouched line changed: a bare carriage return",
        ));
    }
    match crate::yaml::from_str::<Value>(original) {
        Ok(Value::Mapping(_)) => Ok(()),
        // An empty file, or one of comments only, is an empty root mapping.
        Ok(Value::Null) if shape::no_content(original) => Ok(()),
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

/// A segment this module can address: letters, digits, `_` and `-`, not
/// starting with `-` (which reads as a list item's dash), read by YAML as
/// that same string (not a number, a bool or null).
fn plain_key(segment: &str) -> bool {
    !segment.starts_with('-')
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && crate::yaml::from_str::<Value>(segment).is_ok_and(|v| v.as_str() == Some(segment))
}

/// The text a secret slot holds until the writer fills it: unique per path,
/// so a slot can only ever be read back under its own field.
/// Only plain-scalar bytes, so a serializer writes it bare or
/// double-quoted, never single-quoted around the reference; any other byte
/// of the field is written as `~xx`.
fn placeholder(id: &SlotId) -> String {
    let mut out = String::from("__mcpgw_slot_");
    for byte in id.display().bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            out.push(char::from(byte));
        } else {
            std::fmt::Write::write_fmt(&mut out, format_args!("~{byte:02x}")).ok();
        }
    }
    out.push_str("__");
    out
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
/// parser refuses anchors, aliases and tags on any node an edit touches
/// before this runs.
fn meaning_holds(original: &str, changes: &[(FieldPath, Change)], edited: &str) -> bool {
    let Ok(doc) = crate::yaml::from_str::<Value>(original) else {
        return false;
    };
    let Some(want) = shape::expected(&doc, changes) else {
        return false;
    };
    // An edit that removed every key leaves an empty file: an empty root.
    let got = match crate::yaml::from_str::<Value>(edited) {
        Ok(Value::Null) if shape::no_content(edited) => Value::Mapping(crate::yaml::Mapping::new()),
        Ok(got) => got,
        Err(_) => return false,
    };
    got == want
}

#[path = "config_persistence_keyedit_shape.rs"]
mod shape;

#[path = "config_persistence_keyedit_revoke.rs"]
mod revoke;

#[cfg(test)]
#[path = "config_persistence_keyedit_tests.rs"]
mod tests;
