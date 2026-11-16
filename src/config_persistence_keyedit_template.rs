// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A built [`Template`]: its bytes, hunks and slots, building one from placeholders, filling slots.

use super::{
    BTreeMap, ComputeRefusal, Hunk, SlotId, Template, Value, list, placeholder, quoted_placeholder,
};

impl Template {
    /// The original 1-based line numbers of the comment lines this edit
    /// dropped, sorted: a list element's removal takes its comments with it.
    /// Line numbers only, never text: a `#` in a value can be a secret.
    pub(crate) fn dropped_comments(&self) -> &[usize] {
        &self.dropped
    }

    /// The changed lines of an in-place edit, in order.
    pub(crate) fn hunks(&self) -> &[Hunk] {
        &self.hunks
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
            hunks: Vec::new(),
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
            let at_path = list::value_at(&doc, &id.0);
            if at_path.as_str() != Some(refs[id].as_str()) {
                return Err(ComputeRefusal::SlotMismatch);
            }
        }
        Ok(text.into_bytes())
    }
}
