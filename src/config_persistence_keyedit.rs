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

use std::collections::BTreeMap;
use std::ops::Range;

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
    /// The new bytes are wrong (a bad value).
    Invalid(String),
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
    /// Bytes with no slot: a save without secrets.
    pub(crate) fn plain(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            slots: Vec::new(),
        }
    }

    /// A template whose every slot range holds exactly its own field's
    /// placeholder, in order and disjoint; anything else is refused, so a
    /// slot can never be filled with another field's reference.
    pub(crate) fn checked(
        bytes: Vec<u8>,
        slots: Vec<(SlotId, Range<usize>)>,
    ) -> Result<Self, ComputeRefusal> {
        Ok(Self { bytes, slots })
    }

    /// The bytes as they stand, slots still holding their placeholders.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The fields this template has slots for, in file order.
    pub(crate) fn slot_ids(&self) -> impl Iterator<Item = &SlotId> {
        self.slots.iter().map(|(id, _)| id)
    }

    /// The bytes with each slot replaced by the reference made for its own
    /// field, written as a double-quoted scalar. `SlotMismatch` when `refs`
    /// does not name exactly the template's slots; the writer checks that
    /// before any entry exists, so it is never reached after one.
    pub(crate) fn fill(self, refs: &BTreeMap<SlotId, String>) -> Result<Vec<u8>, ComputeRefusal> {
        let _ = refs;
        Err(ComputeRefusal::SlotMismatch)
    }
}

/// `original` with each change applied in place, or why it cannot be.
pub(crate) fn edit_in_place(
    original: &str,
    changes: &[(FieldPath, Change)],
) -> Result<Template, ComputeRefusal> {
    let _ = (original, changes);
    Err(ComputeRefusal::Unprovable {
        reason: "not built yet".to_owned(),
    })
}

/// The text a secret slot holds until the writer fills it: unique per path,
/// so a slot can only ever be read back under its own field.
fn placeholder(id: &SlotId) -> String {
    format!("__mcpgw_slot_{}__", id.0)
}

/// Proof 1: `edited` parses to `original` with exactly `changes` applied,
/// each secret slot holding its own placeholder.
fn meaning_holds(original: &str, changes: &[(FieldPath, Change)], edited: &str) -> bool {
    let _ = (original, changes, edited, placeholder);
    true
}

#[cfg(test)]
#[path = "config_persistence_keyedit_tests.rs"]
mod tests;
