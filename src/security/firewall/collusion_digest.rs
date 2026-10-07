// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a staged relay receipt holds (MIK-7887.RECEIPT.2): the delivered
//! text as segments, one per string leaf (or long key), fingerprinted run by
//! run. A run never crosses a seam, which is a cap cut, a dropped middle leaf,
//! or a leaf a later change removed, so no fingerprint joins text the source
//! never produced contiguously. A plan step's receipt is then kept to what the
//! plan's final answer delivered: leaves delivered verbatim stay whole, any
//! other leaf keeps only the fingerprints whose k-gram a delivered leaf holds,
//! and the original runs' fingerprints stay where their k-gram is in a
//! delivered leaf or across adjacent kept leaves.

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
#[derive(Clone)]
struct Segment {
    text: String,
    /// The whole leaf, not a piece the cap cut from it.
    whole: bool,
    /// A seam lies before it: never fingerprinted together with the previous one.
    gap_before: bool,
}

/// A delivery reduced to what recording it needs, so a staged receipt holds
/// at most [`RECORD_CAP`] of text rather than the whole result.
#[derive(Default, Clone)]
pub(crate) struct DeliveryDigest {
    segments: Vec<Segment>,
    /// Fingerprints kept from leaves a change removed (plans only).
    retained: Vec<u64>,
    pub(super) sensitive: bool,
    /// Staged whole, its cap still to apply (a plan step, MIK-7992).
    deferred: bool,
}

/// Each leaf as a whole segment, no seam between them.
fn whole_segments(leaves: &[&str]) -> Vec<Segment> {
    leaves
        .iter()
        .map(|leaf| Segment {
            text: (*leaf).to_owned(),
            whole: true,
            gap_before: false,
        })
        .collect()
}

/// `segments` in walk order, capped: segments from the head and from the
/// tail up to half of [`RECORD_CAP`] each, one at a boundary cut on a char
/// boundary, and the middle dropped behind a seam. A kept segment keeps its
/// own seam. Also whether anything was cut.
fn cap(segments: Vec<Segment>) -> (Vec<Segment>, bool) {
    let total = segments
        .iter()
        .map(|s| s.text.len() + 1)
        .sum::<usize>()
        .saturating_sub(1);
    if total <= RECORD_CAP {
        return (segments, false);
    }
    let half = RECORD_CAP / 2;
    let mut head = Vec::new();
    let mut room = half;
    for s in &segments {
        if room == 0 {
            break;
        }
        if s.text.len() <= room {
            head.push(s.clone());
            room -= (s.text.len() + 1).min(room);
        } else {
            let end = s.text.floor_char_boundary(room);
            if end > 0 {
                head.push(Segment {
                    text: s.text[..end].to_owned(),
                    whole: false,
                    gap_before: s.gap_before,
                });
            }
            break;
        }
    }
    let mut tail = Vec::new();
    let mut room = half;
    for s in segments.iter().rev() {
        if room == 0 {
            break;
        }
        if s.text.len() <= room {
            tail.push(s.clone());
            room -= (s.text.len() + 1).min(room);
        } else {
            let start = s.text.ceil_char_boundary(s.text.len() - room);
            if start < s.text.len() {
                tail.push(Segment {
                    text: s.text[start..].to_owned(),
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
    (head, true)
}

impl DeliveryDigest {
    /// `leaves` in walk order, capped by leaf (see [`cap`]). Also whether
    /// anything was cut.
    pub(super) fn of_leaves(leaves: &[&str], sensitive: bool) -> (Self, bool) {
        let (segments, cut) = cap(whole_segments(leaves));
        let digest = Self {
            segments,
            retained: Vec::new(),
            sensitive,
            deferred: false,
        };
        (digest, cut)
    }

    /// `leaves` of a plan step, staged whole with the cap deferred until the
    /// receipt is kept to what the plan delivers (MIK-7992): a member the
    /// plan drops must not take the budget of one it delivers. Over
    /// [`DELIVERED_SET_CAP`], capped now as [`Self::of_leaves`] does.
    pub(super) fn of_plan_step_leaves(leaves: &[&str], sensitive: bool) -> (Self, bool) {
        let total: usize = leaves.iter().map(|l| l.len()).sum();
        if total > DELIVERED_SET_CAP {
            return Self::of_leaves(leaves, sensitive);
        }
        let digest = Self {
            segments: whole_segments(leaves),
            retained: Vec::new(),
            sensitive,
            deferred: true,
        };
        (digest, false)
    }

    /// This digest with a deferred cap applied: segments capped as
    /// [`cap`] caps leaves, seams kept, and at most [`RECORD_CAP`]
    /// retained fingerprints. Also whether anything was cut. A digest
    /// capped at staging is returned as it is.
    pub(super) fn capped(mut self) -> (Self, bool) {
        if !self.deferred {
            return (self, false);
        }
        let (segments, mut cut) = cap(std::mem::take(&mut self.segments));
        cut |= self.retained.len() > RECORD_CAP;
        self.retained.truncate(RECORD_CAP);
        self.segments = segments;
        self.deferred = false;
        (self, cut)
    }

    /// Whether the cap is still to apply.
    pub(super) fn is_deferred(&self) -> bool {
        self.deferred
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
        let mut seen = HashSet::new();
        self.runs()
            .iter()
            .flat_map(|run| detector.fingerprints(&run.join("\n")))
            .chain(self.retained.iter().copied())
            .filter(|fp| seen.insert(*fp))
            .collect()
    }

    /// Kept to what `delivered` carries (a plan step's receipt against the
    /// plan's final answer): a whole leaf delivered verbatim stays in its run;
    /// any other segment leaves its run behind a seam and keeps only those of
    /// its fingerprints whose k-gram occurs in a delivered leaf. Every earlier
    /// fingerprint (the original runs' and retained ones) stays when its
    /// k-gram is in a delivered leaf or in a kept run.
    pub(super) fn retaining(self, detector: &CollusionDetector, delivered: &Delivered<'_>) -> Self {
        let verbatim = |s: &Segment| s.whole && delivered.leaves.contains(s.text.as_str());
        if self.retained.is_empty() && self.segments.iter().all(verbatim) {
            return self;
        }
        let original = self.fingerprints(detector);
        let found = delivered.kgrams(detector);
        let mut retained = Vec::new();
        let mut segments = Vec::with_capacity(self.segments.len());
        let mut gap = false;
        for segment in self.segments {
            if verbatim(&segment) {
                segments.push(Segment {
                    gap_before: gap || segment.gap_before,
                    ..segment
                });
                gap = false;
            } else {
                retained.extend(
                    detector
                        .fingerprints(&segment.text)
                        .into_iter()
                        .filter(|fp| found.contains(fp)),
                );
                gap = true;
            }
        }
        let mut kept = Self {
            segments,
            retained: Vec::new(),
            sensitive: self.sensitive,
            deferred: self.deferred,
        };
        // A removed leaf splits its run, and re-winnowing the pieces can drop
        // minima of text still delivered: the original runs' fingerprints stay
        // too, wherever their k-gram is in a delivered leaf or spans adjacent
        // kept leaves.
        let across = kept.run_kgrams(detector);
        retained.extend(
            original
                .into_iter()
                .filter(|fp| found.contains(fp) || across.contains(fp)),
        );
        kept.retained = retained;
        kept
    }

    /// Every k-gram hash of each run of this digest's segments.
    fn run_kgrams(&self, detector: &CollusionDetector) -> HashSet<u64> {
        self.runs()
            .iter()
            .flat_map(|run| detector.kgram_hashes(&run.join("\n")))
            .collect()
    }

    /// The segments' texts grouped into runs: a seam starts a new one.
    fn runs(&self) -> Vec<Vec<&str>> {
        let mut runs: Vec<Vec<&str>> = Vec::new();
        for segment in &self.segments {
            match runs.last_mut() {
                Some(run) if !segment.gap_before => run.push(&segment.text),
                _ => runs.push(vec![&segment.text]),
            }
        }
        runs
    }
}

/// The string leaves of a plan's final answer, and every k-gram hash in them,
/// taken leaf by leaf when first needed. With the kept runs' own k-grams they
/// decide which fingerprints a receipt keeps, whichever window selected them.
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
