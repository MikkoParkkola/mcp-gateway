// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a staged relay receipt holds (MIK-7887.RECEIPT.2): the delivered
//! text as segments, one per string leaf (or long key), fingerprinted run by
//! run. A run never crosses a seam, which is a cap cut, a dropped middle leaf,
//! or a leaf a later change removed, so no fingerprint joins text the source
//! never produced contiguously. A plan step's receipt is then kept to what the
//! plan's final answer delivered: leaves delivered verbatim stay whole, and any
//! other leaf keeps only the fingerprints whose k-gram a delivered leaf holds.

use std::cell::OnceCell;
use std::collections::HashSet;

use serde_json::Value;

use super::collusion::{CollusionDetector, K};
use super::collusion_gate::RECORD_CAP;

/// The delivered text a plan's receipts are kept against, at most. A larger
/// answer drops them, as before this check existed (under-receipt, never a
/// false excuse).
pub(super) const DELIVERED_SET_CAP: usize = 1024 * 1024;

/// One piece of delivered text.
struct Segment {
    text: String,
    /// The whole leaf, not a piece the cap cut from it.
    whole: bool,
    /// A seam lies before it: never fingerprinted together with the previous one.
    gap_before: bool,
}

/// A delivery reduced to what recording it needs, so a staged receipt holds
/// at most [`RECORD_CAP`] of text rather than the whole result.
#[derive(Default)]
pub(crate) struct DeliveryDigest {
    segments: Vec<Segment>,
    /// Fingerprints kept from leaves a change removed (plans only).
    retained: Vec<u64>,
    pub(super) sensitive: bool,
}

impl DeliveryDigest {
    /// `leaves` in walk order, capped by leaf: leaves from the head and from
    /// the tail up to half of [`RECORD_CAP`] each, a leaf at a boundary cut on
    /// a char boundary, and the middle dropped behind a seam. Also whether
    /// anything was cut.
    pub(super) fn of_leaves(leaves: &[&str], sensitive: bool) -> (Self, bool) {
        let total = leaves
            .iter()
            .map(|l| l.len() + 1)
            .sum::<usize>()
            .saturating_sub(1);
        let whole = |text: &str, gap_before| Segment {
            text: text.to_owned(),
            whole: true,
            gap_before,
        };
        let cut = total > RECORD_CAP;
        let segments = if cut {
            let half = RECORD_CAP / 2;
            let mut head = Vec::new();
            let mut room = half;
            for leaf in leaves {
                if leaf.len() <= room {
                    head.push(whole(leaf, false));
                    room -= (leaf.len() + 1).min(room);
                } else {
                    let end = leaf.floor_char_boundary(room);
                    if end > 0 {
                        head.push(Segment {
                            text: leaf[..end].to_owned(),
                            whole: false,
                            gap_before: false,
                        });
                    }
                    break;
                }
            }
            let mut tail = Vec::new();
            let mut room = half;
            for leaf in leaves.iter().rev() {
                if leaf.len() <= room {
                    tail.push(whole(leaf, false));
                    room -= (leaf.len() + 1).min(room);
                } else {
                    let start = leaf.ceil_char_boundary(leaf.len() - room);
                    if start < leaf.len() {
                        tail.push(Segment {
                            text: leaf[start..].to_owned(),
                            whole: false,
                            gap_before: false,
                        });
                    }
                    break;
                }
            }
            tail.reverse();
            if let Some(first) = tail.first_mut() {
                first.gap_before = true;
            }
            head.extend(tail);
            head
        } else {
            leaves.iter().map(|leaf| whole(leaf, false)).collect()
        };
        let digest = Self {
            segments,
            retained: Vec::new(),
            sensitive,
        };
        (digest, cut)
    }

    /// Each segment's text and whether a seam lies before it (tests only).
    #[cfg(test)]
    pub(super) fn segment_texts(&self) -> Vec<(&str, bool)> {
        self.segments
            .iter()
            .map(|s| (s.text.as_str(), s.gap_before))
            .collect()
    }

    /// This digest, as sensitive as `earlier` was: a rebuild from a redacted
    /// copy must not lose the verdict the original delivery carried.
    pub(crate) fn keeping_sensitivity_of(mut self, earlier: &Self) -> Self {
        self.sensitive |= earlier.sensitive;
        self
    }

    /// The fingerprints to record: each run's, newline-joined as a delivery
    /// walk joins leaves, in walk order, then the retained ones; distinct.
    pub(super) fn fingerprints(&self, detector: &CollusionDetector) -> Vec<u64> {
        let mut runs: Vec<Vec<&str>> = Vec::new();
        for segment in &self.segments {
            match runs.last_mut() {
                Some(run) if !segment.gap_before => run.push(&segment.text),
                _ => runs.push(vec![&segment.text]),
            }
        }
        let mut seen = HashSet::new();
        runs.iter()
            .flat_map(|run| detector.fingerprints(&run.join("\n")))
            .chain(self.retained.iter().copied())
            .filter(|fp| seen.insert(*fp))
            .collect()
    }

    /// Kept to what `delivered` carries (a plan step's receipt against the
    /// plan's final answer): a whole leaf delivered verbatim stays in its run;
    /// any other segment leaves its run behind a seam and keeps only those of
    /// its fingerprints whose k-gram occurs in a delivered leaf, as do earlier
    /// retained ones.
    pub(super) fn retaining(self, detector: &CollusionDetector, delivered: &Delivered<'_>) -> Self {
        let mut segments = Vec::with_capacity(self.segments.len());
        let mut retained = Vec::new();
        let mut gap = false;
        for segment in self.segments {
            if segment.whole && delivered.leaves.contains(segment.text.as_str()) {
                segments.push(Segment {
                    gap_before: gap || segment.gap_before,
                    ..segment
                });
                gap = false;
            } else {
                let found = delivered.kgrams(detector);
                retained.extend(
                    detector
                        .fingerprints(&segment.text)
                        .into_iter()
                        .filter(|fp| found.contains(fp)),
                );
                gap = true;
            }
        }
        if !self.retained.is_empty() {
            let found = delivered.kgrams(detector);
            retained.extend(self.retained.into_iter().filter(|fp| found.contains(fp)));
        }
        Self {
            segments,
            retained,
            sensitive: self.sensitive,
        }
    }
}

/// The string leaves of a plan's final answer, and every k-gram hash in them,
/// taken leaf by leaf when first needed: a retained fingerprint is a k-gram
/// the source produced that the caller was delivered, whichever window
/// selected it on either side.
pub(crate) struct Delivered<'v> {
    leaves: HashSet<&'v str>,
    all: Vec<&'v str>,
    found: OnceCell<HashSet<u64>>,
}

impl<'v> Delivered<'v> {
    /// `None` over [`DELIVERED_SET_CAP`].
    pub(super) fn of_leaves(all: Vec<&'v str>) -> Option<Self> {
        let total: usize = all.iter().map(|l| l.len()).sum();
        (total <= DELIVERED_SET_CAP).then(|| Self {
            leaves: all.iter().copied().collect(),
            all,
            found: OnceCell::new(),
        })
    }

    fn kgrams(&self, detector: &CollusionDetector) -> &HashSet<u64> {
        self.found.get_or_init(|| {
            self.all
                .iter()
                .flat_map(|leaf| detector.kgram_hashes(leaf))
                .collect()
        })
    }
}

/// The string leaves of `value` a delivery walk reads, in walk order: every
/// string, leaving out a top-level `_context_integrity`, then each object key
/// of at least `K` chars.
pub(super) fn delivery_leaves(value: &Value) -> Vec<&str> {
    fn visit<'v>(value: &'v Value, leaves: &mut Vec<&'v str>, keys: &mut Vec<&'v str>) {
        match value {
            Value::String(s) => leaves.push(s),
            Value::Array(items) => items.iter().for_each(|v| visit(v, leaves, keys)),
            Value::Object(map) => map.iter().for_each(|(k, v)| {
                keys.push(k);
                visit(v, leaves, keys);
            }),
            _ => {}
        }
    }
    let (mut leaves, mut keys) = (Vec::new(), Vec::new());
    match value {
        Value::Object(map) => map
            .iter()
            .filter(|(k, _)| k.as_str() != "_context_integrity")
            .for_each(|(k, v)| {
                keys.push(k.as_str());
                visit(v, &mut leaves, &mut keys);
            }),
        _ => visit(value, &mut leaves, &mut keys),
    }
    leaves.extend(keys.into_iter().filter(|k| k.chars().count() >= K));
    leaves
}
