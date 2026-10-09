// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The delivered text a plan's step receipts are kept against (moved from
//! `collusion_digest.rs`).

use std::cell::OnceCell;
use std::collections::HashSet;

use serde_json::Value;

use super::super::collusion::CollusionDetector;
use super::{DELIVERED_SET_CAP, Segment};

/// The string leaves of a plan's final answer, and every k-gram hash in them,
/// taken leaf by leaf when first needed. With the kept runs' own k-grams they
/// decide which fingerprints a receipt keeps.
pub(crate) struct Delivered<'v> {
    values: HashSet<&'v str>,
    keys: HashSet<&'v str>,
    pub(super) all: Vec<&'v str>,
    /// How many of `all`, from the front, are values (the rest are keys).
    pub(super) values_len: usize,
    found: OnceCell<HashSet<u64>>,
    /// The answer itself, for its key-path joins (`MIK-8209` K3).
    answer: Option<&'v Value>,
}

impl<'v> Delivered<'v> {
    /// [`Self::of_parts`] with every leaf a value (tests only).
    #[cfg(test)]
    pub(in super::super) fn of_leaves(all: Vec<&'v str>) -> Option<Self> {
        let values = all.len();
        Self::of_parts(all, values)
    }

    /// `all` as [`super::delivery_parts`] returns it, the first `values` of them
    /// values and the rest keys. `None` over [`DELIVERED_SET_CAP`] of text
    /// plus one segment per leaf: a deferred receipt kept to it owns a
    /// segment per delivered leaf it matches, so many empty leaves must not
    /// pass as free.
    pub(in super::super) fn of_parts(all: Vec<&'v str>, values: usize) -> Option<Self> {
        let per_leaf = std::mem::size_of::<Segment>();
        let total: usize = all.iter().map(|l| l.len() + per_leaf).sum();
        (total <= DELIVERED_SET_CAP).then(|| Self {
            values: all[..values].iter().copied().collect(),
            keys: all[values..].iter().copied().collect(),
            all,
            values_len: values,
            found: OnceCell::new(),
            answer: None,
        })
    }

    /// Whether `segment` is a whole leaf delivered verbatim as the same kind:
    /// a value the answer carries only as a key is not, as egress never runs
    /// keys together (MIK-7773).
    pub(super) fn holds(&self, segment: &Segment) -> bool {
        let leaves = if segment.key {
            &self.keys
        } else {
            &self.values
        };
        segment.whole && leaves.contains(segment.text.as_str())
    }

    /// This answer, read also for its key-path joins (`MIK-8209` K3).
    pub(in super::super) fn with_answer(mut self, answer: &'v Value) -> Self {
        self.answer = Some(answer);
        self
    }

    /// Every k-gram hash of each leaf, and (`MIK-8209` K3) of the values
    /// newline-joined, the values run together, and each key-path join of the
    /// answer alone: forms a delivery records, so a step whose copy the answer
    /// splits keeps its run-together fingerprints. The forms are built when
    /// first needed and only their hashes kept, so the bound is unchanged.
    pub(super) fn kgrams(&self, detector: &CollusionDetector) -> &HashSet<u64> {
        self.found.get_or_init(|| {
            let values = &self.all[..self.values_len.min(self.all.len())];
            let mut forms = vec![values.join("\n")];
            if values.len() > 1 {
                forms.push(values.concat());
            }
            forms.extend(self.answer.map(super::key_path_joins).unwrap_or_default());
            self.all
                .iter()
                .copied()
                .chain(forms.iter().map(String::as_str))
                .flat_map(|text| detector.kgram_hashes(text))
                .collect()
        })
    }
}
