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

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use super::collusion::{CollusionDetector, K};
use super::collusion_gate::RECORD_CAP;

#[path = "collusion_delivered.rs"]
mod delivered;
pub(crate) use delivered::Delivered;
#[path = "collusion_key_path.rs"]
mod key_path;
pub(super) use key_path::{key_path_joins, key_path_run_indices, key_path_runs};

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
    /// From an object key, not a value: egress runs only values together.
    key: bool,
}

impl Segment {
    fn view(&self) -> View<'_> {
        View {
            text: &self.text,
            whole: self.whole,
            gap_before: self.gap_before,
            key: self.key,
        }
    }
}

/// A [`Segment`] borrowed, so capping copies only the text it keeps.
#[derive(Clone, Copy)]
struct View<'a> {
    text: &'a str,
    whole: bool,
    gap_before: bool,
    key: bool,
}

impl View<'_> {
    fn owned(self) -> Segment {
        Segment {
            text: self.text.to_owned(),
            whole: self.whole,
            gap_before: self.gap_before,
            key: self.key,
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
    /// A seam between plan steps of two or more sources (`MIK-8113`): the
    /// contributing `server:tool` sources, ascending. Its copy may leave only
    /// by a flow every one of them allows.
    pub(super) seam_sources: Option<Box<[String]>>,
    /// What the holder received when this receipt was cut: excuse only
    /// (`MIK-8066.EXCUSE.1`).
    pub(super) cut_fps: Option<std::sync::Arc<[u64]>>,
    /// The key-path joins (`MIK-8209`, design §14.1 K2).
    joins: Joins,
}

/// A delivery's key-path joins, each fingerprinted alone after the segment
/// and retained fingerprints, so the per-delivery fingerprint bound keeps
/// leaf evidence first.
#[derive(Default, Clone)]
enum Joins {
    #[default]
    None,
    /// The joins' text, kept to their own [`RECORD_CAP`] budget.
    Text(Box<[String]>),
    /// A staged plan step's runs, as segment indices: no text is copied.
    Runs(Box<[Box<[u32]>]>),
    /// What retention kept of a step's runs, as fingerprints.
    Fps(Box<[u64]>),
}

/// `joins` kept whole, in order, up to a [`RECORD_CAP`] budget of their own;
/// past the first that does not fit, every later one is left out. Also
/// whether any was.
fn budget_joins(joins: Vec<String>) -> (Box<[String]>, bool) {
    let mut room = RECORD_CAP;
    let total = joins.len();
    let kept: Box<[String]> = joins
        .into_iter()
        .take_while(|join| {
            let fits = join.len() <= room;
            room = room.saturating_sub(join.len());
            fits
        })
        .collect();
    let cut = kept.len() < total;
    (kept, cut)
}

/// Leaf `i` as a whole segment, no seam before it; the first `values` are
/// values and the rest object keys, as [`delivery_parts`] returns them.
fn part_view<'a>(leaves: &[&'a str], values: usize, i: usize) -> View<'a> {
    View {
        text: leaves[i],
        whole: true,
        gap_before: false,
        key: i >= values,
    }
}

/// The `n` segments `at` reads, in walk order, capped: segments from the head
/// and from the tail up to half of [`RECORD_CAP`] each, one at a boundary cut
/// on a char boundary, and the middle dropped behind a seam. A kept segment
/// keeps its own seam. Only kept text is copied, and no segment is held that
/// is not kept. Also whether anything was cut.
fn cap<'a>(n: usize, at: &dyn Fn(usize) -> View<'a>) -> (Vec<Segment>, bool) {
    let total = (0..n)
        .map(|i| at(i).text.len() + 1)
        .sum::<usize>()
        .saturating_sub(1);
    if total <= RECORD_CAP {
        return ((0..n).map(|i| at(i).owned()).collect(), false);
    }
    let half = RECORD_CAP / 2;
    let mut head = Vec::new();
    let mut room = half;
    for s in (0..n).map(at) {
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
                    key: s.key,
                });
            }
            break;
        }
    }
    let mut tail = Vec::new();
    let mut room = half;
    for s in (0..n).rev().map(at) {
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
                    key: s.key,
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
    /// [`Self::of_parts`] with every leaf a value (tests only).
    #[cfg(test)]
    pub(super) fn of_leaves(leaves: &[&str], sensitive: bool) -> (Self, bool) {
        Self::of_parts(leaves, leaves.len(), sensitive)
    }

    /// `leaves` in walk order, the first `values` of them values and the rest
    /// object keys, as [`delivery_parts`] returns them; capped by leaf (see
    /// [`cap`]). Also whether anything was cut.
    pub(super) fn of_parts(leaves: &[&str], values: usize, sensitive: bool) -> (Self, bool) {
        let (segments, cut) = cap(leaves.len(), &|i| part_view(leaves, values, i));
        let digest = Self {
            segments,
            retained: Vec::new(),
            sensitive,
            deferred: false,
            seam_sources: None,
            cut_fps: None,
            joins: Joins::None,
        };
        (digest, cut)
    }

    /// This digest with `joins`, its key-path joins in run order, kept whole up
    /// to a [`RECORD_CAP`] budget of their own, so they never take the leaves'
    /// room (`MIK-8209`). Also whether a join was left out: past the first that
    /// does not fit, every later one is.
    pub(super) fn with_joins(mut self, joins: Vec<String>) -> (Self, bool) {
        let (kept, cut) = budget_joins(joins);
        self.joins = Joins::Text(kept);
        (self, cut)
    }

    /// This staged digest with its key-path runs, as indices into its
    /// segments (`MIK-8209` K2a): no join text is copied while staged.
    pub(super) fn with_join_runs(mut self, runs: Vec<Box<[u32]>>) -> Self {
        if self.deferred && !runs.is_empty() {
            self.joins = Joins::Runs(runs.into());
        }
        self
    }

    /// [`Self::of_plan_step_parts`] with every leaf a value (tests only).
    #[cfg(test)]
    pub(super) fn of_plan_step_leaves(leaves: &[&str], sensitive: bool) -> (Self, bool) {
        Self::of_plan_step_parts(leaves, leaves.len(), sensitive)
    }

    /// The parts of a plan step (as [`Self::of_parts`] takes them), staged
    /// whole with the cap deferred until the receipt is kept to what the
    /// plan delivers (MIK-7992): a member the plan drops must not take the
    /// budget of one it delivers. Over [`DELIVERED_SET_CAP`] of text plus one
    /// segment per leaf (so many empty leaves cannot stage unbounded), capped
    /// now as [`Self::of_parts`] does.
    pub(super) fn of_plan_step_parts(
        leaves: &[&str],
        values: usize,
        sensitive: bool,
    ) -> (Self, bool) {
        let per_leaf = std::mem::size_of::<Segment>();
        let total: usize = leaves.iter().map(|l| l.len() + per_leaf).sum();
        if total > DELIVERED_SET_CAP {
            return Self::of_parts(leaves, values, sensitive);
        }
        let digest = Self {
            segments: (0..leaves.len())
                .map(|i| part_view(leaves, values, i).owned())
                .collect(),
            retained: Vec::new(),
            sensitive,
            deferred: true,
            seam_sources: None,
            cut_fps: None,
            joins: Joins::None,
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
        let (segments, cut) = cap(self.segments.len(), &|i| self.segments[i].view());
        let kept = self.retained.len().min(RECORD_CAP);
        // The join slot is carried over (`MIK-8209`): staged runs become their
        // text, on the joins' own budget, before the cap renumbers segments.
        let (joins, joins_cut) = match &self.joins {
            Joins::Runs(runs) => {
                let (text, cut) = budget_joins(runs.iter().map(|r| self.run_text(r)).collect());
                (Joins::Text(text), cut)
            }
            other => (other.clone(), false),
        };
        let digest = Self {
            segments,
            retained: self.retained[..kept].to_vec(),
            sensitive: self.sensitive,
            deferred: false,
            seam_sources: None,
            cut_fps: None,
            joins,
        };
        Some((digest, cut || joins_cut || kept < self.retained.len()))
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

    /// The bytes it holds, as plan-step staging counts them: the digest, its
    /// text, and one segment per leaf (MIK-7992).
    pub(crate) fn staged_len(&self) -> usize {
        let per_leaf = std::mem::size_of::<Segment>();
        let text: usize = self.segments.iter().map(|s| s.text.len() + per_leaf).sum();
        // Staged index runs are charged too (`MIK-8209` K2a).
        let runs: usize = match &self.joins {
            Joins::Runs(runs) => runs
                .iter()
                .map(|r| std::mem::size_of_val::<[u32]>(r) + std::mem::size_of::<Box<[u32]>>())
                .sum(),
            _ => 0,
        };
        std::mem::size_of::<Self>() + text + runs
    }

    /// The fingerprints of a seam between plan steps (`MIK-8113`), at most
    /// [`RECORD_CAP`] of them as any receipt's retained ones, under `sources`
    /// when two or more sources contributed (a composite), else under the one
    /// contributing source's own receipt identity.
    pub(crate) fn of_seam(
        mut fps: Vec<u64>,
        sensitive: bool,
        sources: Option<Box<[String]>>,
    ) -> Self {
        fps.sort_unstable();
        fps.dedup();
        fps.truncate(RECORD_CAP);
        Self {
            retained: fps,
            sensitive,
            seam_sources: sources,
            ..Self::default()
        }
    }

    /// The whole value leaves this digest keeps: delivered leaves a plan
    /// step produced unchanged (`MIK-8113` ownership).
    pub(crate) fn whole_values(&self) -> impl Iterator<Item = &str> {
        self.segments
            .iter()
            .filter(|s| s.whole && !s.key)
            .map(|s| s.text.as_str())
    }

    /// Whether this digest is sensitive.
    pub(crate) const fn is_sensitive(&self) -> bool {
        self.sensitive
    }

    /// This digest, as sensitive as `earlier` was: a rebuild from a redacted
    /// copy must not lose the verdict the original delivery carried.
    pub(crate) fn keeping_sensitivity_of(mut self, earlier: &Self) -> Self {
        self.sensitive |= earlier.sensitive;
        self
    }

    /// The fingerprints to record: each run's forms (see [`run_forms`]), in
    /// walk order, then the retained ones; distinct.
    pub(super) fn fingerprints(&self, detector: &CollusionDetector) -> Vec<u64> {
        let mut seen = HashSet::new();
        self.leaf_fingerprints(detector)
            .into_iter()
            .chain(self.join_fingerprints(detector))
            .filter(|fp| seen.insert(*fp))
            .collect()
    }

    /// The segment runs' forms, then the retained fingerprints; distinct.
    fn leaf_fingerprints(&self, detector: &CollusionDetector) -> Vec<u64> {
        let mut seen = HashSet::new();
        self.runs()
            .iter()
            .flat_map(|run| run_forms(run))
            .flat_map(|text| detector.fingerprints(&text))
            .chain(self.retained.iter().copied())
            .filter(|fp| seen.insert(*fp))
            .collect()
    }

    /// Each key-path join's fingerprints, the join fingerprinted alone so no
    /// form runs it into a neighbour (`MIK-8209`).
    fn join_fingerprints(&self, detector: &CollusionDetector) -> Vec<u64> {
        match &self.joins {
            Joins::None => Vec::new(),
            Joins::Text(joins) => joins
                .iter()
                .flat_map(|j| detector.fingerprints(j))
                .collect(),
            Joins::Runs(runs) => runs
                .iter()
                .flat_map(|run| detector.fingerprints(&self.run_text(run)))
                .collect(),
            Joins::Fps(fps) => fps.to_vec(),
        }
    }

    /// The text of a staged run: its segments run together.
    fn run_text(&self, run: &[u32]) -> String {
        run.iter()
            .filter_map(|&i| self.segments.get(i as usize))
            .map(|s| s.text.as_str())
            .collect()
    }

    /// Kept to what `delivered` carries (a plan step's receipt against the
    /// plan's final answer): a whole leaf delivered verbatim stays in its run;
    /// any other segment leaves its run behind a seam and keeps only those of
    /// its fingerprints whose k-gram occurs in a delivered leaf. Every earlier
    /// fingerprint (the original runs' and retained ones) stays when its
    /// k-gram is in a delivered leaf or in a kept run.
    #[cfg(test)]
    pub(super) fn retaining(self, detector: &CollusionDetector, delivered: &Delivered<'_>) -> Self {
        self.retaining_for(detector, delivered, None)
    }

    /// Kept to `delivered` as `retaining` describes, for the receipt of plan
    /// step `step`, whose own span of the answer is matched first (`MIK-8209`
    /// K7).
    pub(super) fn retaining_for(
        self,
        detector: &CollusionDetector,
        delivered: &Delivered<'_>,
        step: Option<u32>,
    ) -> Self {
        if self.deferred {
            return self.retaining_deferred(detector, delivered, step);
        }
        let verbatim = |s: &Segment| delivered.holds(s);
        // Unchanged only without joins: a join is kept only where the answer
        // still delivers it, even when every capped leaf survives (`MIK-8209`).
        if self.retained.is_empty()
            && matches!(self.joins, Joins::None)
            && self.segments.iter().all(verbatim)
        {
            return self;
        }
        let original = (
            self.leaf_fingerprints(detector),
            self.join_fingerprints(detector),
        );
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
            seam_sources: None,
            cut_fps: None,
            joins: Joins::None,
        };
        kept.with_original(detector, found, original, retained, &HashSet::new())
    }

    /// [`Self::retaining`] for a digest whose cap is deferred (MIK-7992): its
    /// kept segments are the delivered leaves, in delivered order, that equal
    /// a whole leaf of the step, so every kept run is text the caller received
    /// as it stands; a delivered leaf the step did not produce whole is a seam.
    /// A step leaf delivered verbatim is covered by those; any other keeps its
    /// fingerprints whose k-gram a delivered leaf holds. Kept text is at most
    /// the delivered text, and copies the caller never got spend nothing. It
    /// is also at most what the step staged: an answer repeating a step leaf
    /// keeps its copies only up to that, the rest behind a seam, so retention
    /// never grows a receipt past what its plan's staging bound counted.
    fn retaining_deferred(
        self,
        detector: &CollusionDetector,
        delivered: &Delivered<'_>,
        step: Option<u32>,
    ) -> Self {
        // Matched as the same kind (MIK-7773): a step value the answer
        // carries only as a key is not kept as a value. `MIK-8209` K8: each
        // whole leaf is kept at most as many times as the step staged it, so
        // copies the answer added (a late redaction marker) cannot spend the
        // room of the step's other leaves.
        let mut whole: HashMap<(&str, bool), usize> = HashMap::new();
        for s in self.segments.iter().filter(|s| s.whole) {
            *whole.entry((s.text.as_str(), s.key)).or_default() += 1;
        }
        // At most what the step staged (MIK-7992): its text, never the index
        // runs `staged_len` also charges.
        let per_leaf = std::mem::size_of::<Segment>();
        let mut room: usize = self.segments.iter().map(|s| s.text.len() + per_leaf).sum();
        // `MIK-8209` K7: room goes to the step's own span of the answer first,
        // then elsewhere, so an equal leaf another step delivered earlier
        // cannot spend it; the cap and the equality check are unchanged.
        let n = delivered.all.len();
        let own = |i: usize| step.is_some() && delivered.label(i) == step;
        let mut keep = vec![false; n];
        for i in (0..n)
            .filter(|&i| own(i))
            .chain((0..n).filter(|&i| !own(i)))
        {
            let (leaf, key) = (delivered.all[i], i >= delivered.values_len);
            let cost = leaf.len() + per_leaf;
            let Some(left) = whole.get_mut(&(leaf, key)).filter(|n| **n > 0) else {
                continue;
            };
            if cost <= room {
                room -= cost;
                *left -= 1;
                keep[i] = true;
            }
        }
        let mut segments = Vec::new();
        let mut gap = false;
        for (i, leaf) in delivered.all.iter().enumerate() {
            if keep[i] {
                segments.push(Segment {
                    text: (*leaf).to_owned(),
                    whole: true,
                    gap_before: gap,
                    key: i >= delivered.values_len,
                });
                gap = false;
            } else {
                gap = true;
            }
        }
        let original = (
            self.leaf_fingerprints(detector),
            self.join_fingerprints(detector),
        );
        let found = delivered.kgrams(detector);
        let retained = self
            .segments
            .iter()
            .filter(|s| !delivered.holds(s))
            .flat_map(|s| detector.fingerprints(&s.text))
            .filter(|fp| found.contains(fp))
            .collect();
        let mut in_step = self.step_runs_kgrams(detector, delivered);
        in_step.extend(self.step_join_kgrams(detector, delivered));
        let kept = Self {
            segments,
            retained: Vec::new(),
            sensitive: self.sensitive,
            deferred: true,
            seam_sources: None,
            cut_fps: None,
            joins: Joins::None,
        };
        kept.with_original(detector, found, original, retained, &in_step)
    }

    /// `MIK-8209` K2a: every k-gram hash of each maximal sub-run of at least
    /// two consecutive pieces of a staged key-path run that the plan delivered
    /// whole. Consecutive means next in the run, though the pieces' segment
    /// indices need not be adjacent (sibling fields sit between them). A piece
    /// the answer does not hold whole breaks the sub-run. Never filtered by
    /// what the answer's own k-grams contain: an answer interleaving the
    /// pieces still delivered each one.
    fn step_join_kgrams(
        &self,
        detector: &CollusionDetector,
        delivered: &Delivered<'_>,
    ) -> HashSet<u64> {
        let Joins::Runs(runs) = &self.joins else {
            return HashSet::new();
        };
        let mut found = HashSet::new();
        for run in runs {
            let held: Vec<Option<&str>> = run
                .iter()
                .map(|&i| {
                    self.segments
                        .get(i as usize)
                        .filter(|s| delivered.holds(s))
                        .map(|s| s.text.as_str())
                })
                .collect();
            for sub in held.split(Option::is_none) {
                if sub.len() >= 2 {
                    let text: String = sub.iter().flatten().copied().collect();
                    found.extend(detector.kgram_hashes(&text));
                }
            }
        }
        found
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
        let mut runs: Vec<Vec<&Segment>> = Vec::new();
        let mut gap = false;
        for segment in &self.segments {
            if !delivered.holds(segment) {
                gap = true;
                continue;
            }
            match runs.last_mut() {
                Some(run) if !(gap || segment.gap_before) => run.push(segment),
                _ => runs.push(vec![segment]),
            }
            gap = false;
        }
        runs.iter()
            .flat_map(|run| run_forms(run))
            .flat_map(|text| detector.kgram_hashes(&text))
            .collect()
    }

    /// This kept digest with `retained`, then the `original` fingerprints
    /// whose k-gram is `found` in a delivered leaf, spans adjacent kept
    /// leaves, or is `in_step` (a removed leaf splits its run, and the
    /// pieces' own fingerprints miss a k-gram that ran across the cut);
    /// each fingerprint once, so a
    /// later cap on their count never drops a distinct one for a repeat.
    fn with_original(
        mut self,
        detector: &CollusionDetector,
        found: &HashSet<u64>,
        (original, joins): (Vec<u64>, Vec<u64>),
        mut retained: Vec<u64>,
        in_step: &HashSet<u64>,
    ) -> Self {
        let across = self.run_kgrams(detector);
        let kept = |fp: &u64| found.contains(fp) || across.contains(fp) || in_step.contains(fp);
        retained.extend(original.into_iter().filter(kept));
        let mut seen = HashSet::new();
        retained.retain(|fp| seen.insert(*fp));
        self.retained = retained;
        // The joins keep their own slot, as fingerprints: retention never
        // copies join text or index runs (`MIK-8209` K2a).
        let joins: Box<[u64]> = joins
            .into_iter()
            .filter(|fp| kept(fp) && seen.insert(*fp))
            .collect();
        self.joins = if joins.is_empty() {
            Joins::None
        } else {
            Joins::Fps(joins)
        };
        self
    }

    /// Every k-gram hash of each run's forms (see [`run_forms`]).
    fn run_kgrams(&self, detector: &CollusionDetector) -> HashSet<u64> {
        self.runs()
            .iter()
            .flat_map(|run| run_forms(run))
            .flat_map(|text| detector.kgram_hashes(&text))
            .collect()
    }

    /// The segments grouped into runs: a seam starts a new one.
    fn runs(&self) -> Vec<Vec<&Segment>> {
        let mut runs: Vec<Vec<&Segment>> = Vec::new();
        for segment in &self.segments {
            match runs.last_mut() {
                Some(run) if !segment.gap_before => run.push(segment),
                _ => runs.push(vec![segment]),
            }
        }
        runs
    }
}

/// A run's text newline-joined, as a delivery walk joins leaves, and, for a
/// run of several value segments, those values run together too, as egress
/// reads forwarded values (keys stay out, as egress keeps them): a copy
/// delivered split mid-word over short fields then matches its holder's own
/// forwarding of the pieces (MIK-7773). A run never crosses a seam, so
/// neither form joins text across a cut.
fn run_forms(run: &[&Segment]) -> Vec<String> {
    let joined = run
        .iter()
        .map(|s| s.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let values: Vec<&str> = run
        .iter()
        .filter(|s| !s.key)
        .map(|s| s.text.as_str())
        .collect();
    let mut forms = vec![joined];
    if values.len() > 1 {
        forms.push(values.concat());
    }
    forms
}

/// The leaves of [`delivery_parts`] (tests only).
#[cfg(test)]
pub(super) fn delivery_leaves(value: &Value) -> Vec<&str> {
    delivery_parts(value).0
}

/// The string leaves of `value` a delivery walk reads, in walk order: every
/// string, leaving out a top-level `_context_integrity`, then each object key
/// of at least `K` chars; and how many of them, from the front, are values
/// (the rest are keys).
pub(super) fn delivery_parts(value: &Value) -> (Vec<&str>, usize) {
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
    let values = leaves.len();
    leaves.extend(keys.into_iter().filter(|k| k.chars().count() >= K));
    (leaves, values)
}
