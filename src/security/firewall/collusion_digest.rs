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
struct Segment {
    text: String,
    /// The whole leaf, not a piece the cap cut from it.
    whole: bool,
    /// A seam lies before it: never fingerprinted together with the previous one.
    gap_before: bool,
}

impl Segment {
    fn view(&self) -> View<'_> {
        View {
            text: &self.text,
            whole: self.whole,
            gap_before: self.gap_before,
        }
    }
}

/// A [`Segment`] borrowed, so capping copies only the text it keeps.
#[derive(Clone, Copy)]
struct View<'a> {
    text: &'a str,
    whole: bool,
    gap_before: bool,
}

impl View<'_> {
    fn owned(self) -> Segment {
        Segment {
            text: self.text.to_owned(),
            whole: self.whole,
            gap_before: self.gap_before,
        }
    }
}

/// A delivery reduced to what recording it needs, so a staged receipt holds
/// at most [`RECORD_CAP`] of text rather than the whole result.
#[derive(Default)]
pub(crate) struct DeliveryDigest {
    segments: Vec<Segment>,
    /// Fingerprints kept from leaves a change removed (plans only).
    retained: Vec<u64>,
    pub(super) sensitive: bool,
    /// Staged whole, its cap still to apply (a plan step, MIK-7992).
    deferred: bool,
}

/// Each leaf as a whole segment, no seam between them.
fn leaf_views<'a>(leaves: &[&'a str]) -> Vec<View<'a>> {
    leaves
        .iter()
        .map(|&leaf| View {
            text: leaf,
            whole: true,
            gap_before: false,
        })
        .collect()
}

/// `segments` in walk order, capped: segments from the head and from the
/// tail up to half of [`RECORD_CAP`] each, one at a boundary cut on a char
/// boundary, and the middle dropped behind a seam. A kept segment keeps its
/// own seam. Only kept text is copied. Also whether anything was cut.
fn cap(segments: &[View<'_>]) -> (Vec<Segment>, bool) {
    let total = segments
        .iter()
        .map(|s| s.text.len() + 1)
        .sum::<usize>()
        .saturating_sub(1);
    if total <= RECORD_CAP {
        return (segments.iter().map(|s| s.owned()).collect(), false);
    }
    let half = RECORD_CAP / 2;
    let mut head = Vec::new();
    let mut room = half;
    for s in segments {
        if room == 0 {
            break;
        }
        if s.text.len() <= room {
            head.push(s.owned());
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
            tail.push(s.owned());
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
        let (segments, cut) = cap(&leaf_views(leaves));
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
    /// [`DELIVERED_SET_CAP`] of text plus one segment per leaf (so many
    /// empty leaves cannot stage unbounded), capped now as
    /// [`Self::of_leaves`] does.
    pub(super) fn of_plan_step_leaves(leaves: &[&str], sensitive: bool) -> (Self, bool) {
        let per_leaf = std::mem::size_of::<Segment>();
        let total: usize = leaves.iter().map(|l| l.len() + per_leaf).sum();
        if total > DELIVERED_SET_CAP {
            return Self::of_leaves(leaves, sensitive);
        }
        let digest = Self {
            segments: leaf_views(leaves).into_iter().map(View::owned).collect(),
            retained: Vec::new(),
            sensitive,
            deferred: true,
        };
        (digest, false)
    }

    /// A copy of this digest with its deferred cap applied: segments capped
    /// as [`cap`] caps leaves, seams kept, and at most [`RECORD_CAP`]
    /// retained fingerprints; also whether anything was cut. `None` for a
    /// digest capped at staging. Only the kept text is copied.
    pub(super) fn capped(&self) -> Option<(Self, bool)> {
        if !self.deferred {
            return None;
        }
        let views: Vec<View<'_>> = self.segments.iter().map(Segment::view).collect();
        let (segments, cut) = cap(&views);
        let kept = self.retained.len().min(RECORD_CAP);
        let digest = Self {
            segments,
            retained: self.retained[..kept].to_vec(),
            sensitive: self.sensitive,
            deferred: false,
        };
        Some((digest, cut || kept < self.retained.len()))
    }

    /// Whether the cap is still to apply (tests only).
    #[cfg(test)]
    pub(super) fn is_deferred(&self) -> bool {
        self.deferred
    }

    /// How many fingerprints are retained (tests only).
    #[cfg(test)]
    pub(super) fn retained_len(&self) -> usize {
        self.retained.len()
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
        if self.deferred {
            return self.retaining_deferred(detector, delivered);
        }
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
        let kept = Self {
            segments,
            retained: Vec::new(),
            sensitive: self.sensitive,
            deferred: false,
        };
        kept.with_original(detector, found, original, retained, &HashSet::new())
    }

    /// [`Self::retaining`] for a digest whose cap is deferred (MIK-7992): its
    /// kept segments are the delivered leaves, in delivered order, that equal
    /// a whole leaf of the step, so every kept run is text the caller received
    /// as it stands; a delivered leaf the step did not produce whole is a seam.
    /// A step leaf delivered verbatim is covered by those; any other keeps its
    /// fingerprints whose k-gram a delivered leaf holds. Kept text is at most
    /// the delivered text, and copies the caller never got spend nothing.
    fn retaining_deferred(self, detector: &CollusionDetector, delivered: &Delivered<'_>) -> Self {
        let whole: HashSet<&str> = self
            .segments
            .iter()
            .filter(|s| s.whole)
            .map(|s| s.text.as_str())
            .collect();
        let mut segments = Vec::new();
        let mut gap = false;
        for leaf in &delivered.all {
            if whole.contains(leaf) {
                segments.push(Segment {
                    text: (*leaf).to_owned(),
                    whole: true,
                    gap_before: gap,
                });
                gap = false;
            } else {
                gap = true;
            }
        }
        let original = self.fingerprints(detector);
        let found = delivered.kgrams(detector);
        let retained = self
            .segments
            .iter()
            .filter(|s| !(s.whole && delivered.leaves.contains(s.text.as_str())))
            .flat_map(|s| detector.fingerprints(&s.text))
            .filter(|fp| found.contains(fp))
            .collect();
        let in_step = self.step_runs_kgrams(detector, delivered);
        let kept = Self {
            segments,
            retained: Vec::new(),
            sensitive: self.sensitive,
            deferred: true,
        };
        kept.with_original(detector, found, original, retained, &in_step)
    }

    /// Every k-gram hash of each step-order run of this digest's whole
    /// leaves the plan delivered verbatim; any other leaf is a seam. The
    /// step's own adjacency, as a receipt kept it before its cap was
    /// deferred, which another step's leaf between them in the answer does
    /// not undo. Only fingerprints come from it, deduplicated and capped by
    /// count, never kept text. Copies stay in it, so a span across two copies
    /// (`X\nX`) is excused: base receipted it too, and counting copies here
    /// loses a run the step delivered (step `[P, pad, P, S]`, answer
    /// `[P, Z, S]`).
    fn step_runs_kgrams(
        &self,
        detector: &CollusionDetector,
        delivered: &Delivered<'_>,
    ) -> HashSet<u64> {
        let mut runs: Vec<Vec<&str>> = Vec::new();
        let mut gap = false;
        for segment in &self.segments {
            if !(segment.whole && delivered.leaves.contains(segment.text.as_str())) {
                gap = true;
                continue;
            }
            match runs.last_mut() {
                Some(run) if !(gap || segment.gap_before) => run.push(&segment.text),
                _ => runs.push(vec![&segment.text]),
            }
            gap = false;
        }
        runs.iter()
            .flat_map(|run| detector.kgram_hashes(&run.join("\n")))
            .collect()
    }

    /// This kept digest with `retained`, then the `original` fingerprints
    /// whose k-gram is `found` in a delivered leaf, spans adjacent kept
    /// leaves, or is `in_step` (a removed leaf splits its run, and
    /// re-winnowing the pieces can drop minima of text still delivered);
    /// each fingerprint once, so a
    /// later cap on their count never drops a distinct one for a repeat.
    fn with_original(
        mut self,
        detector: &CollusionDetector,
        found: &HashSet<u64>,
        original: Vec<u64>,
        mut retained: Vec<u64>,
        in_step: &HashSet<u64>,
    ) -> Self {
        let across = self.run_kgrams(detector);
        retained.extend(
            original
                .into_iter()
                .filter(|fp| found.contains(fp) || across.contains(fp) || in_step.contains(fp)),
        );
        let mut seen = HashSet::new();
        retained.retain(|fp| seen.insert(*fp));
        self.retained = retained;
        self
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
    /// `None` over [`DELIVERED_SET_CAP`] of text plus one segment per leaf:
    /// a deferred receipt kept to it owns a segment per delivered leaf it
    /// matches, so many empty leaves must not pass as free.
    pub(super) fn of_leaves(all: Vec<&'v str>) -> Option<Self> {
        let per_leaf = std::mem::size_of::<Segment>();
        let total: usize = all.iter().map(|l| l.len() + per_leaf).sum();
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
