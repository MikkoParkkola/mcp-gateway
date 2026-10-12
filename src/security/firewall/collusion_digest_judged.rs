// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066` 2b: a receipt's judgement by its plan's answer (D6, D9, A2)
//! and retention against an over-bound answer's view (D3, A1, A5).

use std::collections::HashSet;
use std::sync::atomic::AtomicBool;

use super::super::collusion::CollusionDetector;
use super::{Delivered, DeliveryDigest, Joins, Segment, run_forms, view};

/// A receipt's judgement by its plan's answer (`MIK-8066` D9, A2). Every
/// state is matched exhaustively, with every field bound by name.
#[derive(Default)]
#[must_use]
pub(crate) enum Judged {
    /// Not judged: an ordinary delivery, or a plan receipt not yet retained.
    /// A step still staged at record is recorded as unread (fail closed).
    #[default]
    Pending,
    /// A plan step past the plan bound, staged (`MIK-8066.BIG.3`).
    Staged(Box<super::collusion::big::BigStep>),
    /// Kept to a read answer; the step's evidence and excuse, if a step.
    Kept(Option<super::collusion::big::KeptStep>),
    /// The answer could not be read (D6): the receipt's capped evidence and
    /// the step's whole evidence, recorded under an unread holder.
    Unread {
        receipt: UnreadReceipt,
        step: Option<super::collusion::big::UnreadStep>,
    },
}

/// What an unread receipt records as evidence (D6): what `record_kept`
/// would record of the capped receipt, computed once at retention.
pub(crate) struct UnreadReceipt {
    pub(crate) fps: Vec<u64>,
    pub(crate) cut: Option<std::sync::Arc<[u64]>>,
}

impl DeliveryDigest {
    /// Kept to `delivered` as `retaining` describes, for the receipt of plan
    /// step `step`, whose own span of the answer is matched first (`MIK-8209`
    /// K7).
    pub(in super::super) fn retaining_for(
        mut self,
        detector: &CollusionDetector,
        delivered: &Delivered<'_>,
        step: Option<u32>,
    ) -> Self {
        // The judgement is moved forward by the gate (D9), never by a
        // content transform: taken out here and put back as it was.
        let judged = std::mem::take(&mut self.judged);
        // Leaf hashes stand in for whole segments only on a view (D4); the
        // leaves path keeps 2a's whole-segment ownership unchanged.
        let leaf_hashes = self
            .leaf_hashes
            .take()
            .filter(|_| delivered.view().is_some());
        let mut kept = self.retaining_content(detector, delivered, step);
        kept.judged = judged;
        kept.leaf_hashes = leaf_hashes;
        kept
    }

    fn retaining_content(
        self,
        detector: &CollusionDetector,
        delivered: &Delivered<'_>,
        step: Option<u32>,
    ) -> Self {
        // `MIK-8066` 2b D3: an over-bound answer is read through its view;
        // an unread one is judged at record (D6, D9).
        if let Some(view) = delivered.view() {
            return self.retaining_view(detector, view);
        }
        if delivered.unread() {
            return self;
        }
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
        let found = delivered.found(detector);
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
                        .filter(|&fp| found.contains(fp)),
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
            seam_excuses: None,
            joins: Joins::None,
            judged: Judged::default(),
            recorded: AtomicBool::default(),
            leaf_hashes: None,
            cut_charge: None,
            cut_lost: false,
        };
        kept.with_original(detector, found, original, retained, &HashSet::new())
    }

    /// Fingerprints an unread receipt holds until record (tests only, D6).
    #[cfg(test)]
    pub(crate) fn unread_receipt_len(&self) -> Option<usize> {
        match &self.judged {
            Judged::Unread {
                receipt: UnreadReceipt { fps, cut },
                step: _,
            } => Some(fps.len() + cut.as_deref().map_or(0, <[u64]>::len)),
            Judged::Pending | Judged::Staged(_) | Judged::Kept(_) => None,
        }
    }

    /// Whether this is a plan step past the bound, staged with attachments.
    pub(crate) fn is_staged_step(&self) -> bool {
        matches!(self.judged, Judged::Staged(_))
    }

    /// Whether this receipt produced a value leaf whose keyed hash is `hash`
    /// (D4: exact; a strict substring hashes differently).
    pub(crate) fn holds_leaf_hash(&self, hash: u64) -> bool {
        self.leaf_hashes
            .as_deref()
            .is_some_and(|hashes| hashes.binary_search(&hash).is_ok())
    }

    /// Unread (D6): the receipt's content goes; its evidence is `receipt`,
    /// a staged step's evidence its whole `step_ev`. Never deferred, so
    /// capping leaves it as it is. Only a pending or staged receipt is
    /// judged; a judged one is returned unchanged (a second retention).
    pub(in super::super) fn into_unread(
        mut self,
        receipt: impl FnOnce(&Self) -> UnreadReceipt,
    ) -> Self {
        let staged = match std::mem::take(&mut self.judged) {
            Judged::Pending => None,
            Judged::Staged(big) => Some(big),
            judged @ (Judged::Kept(_) | Judged::Unread { .. }) => {
                self.judged = judged;
                return self;
            }
        };
        let receipt = receipt(&self);
        let step = staged.map(|big| big.into_unread());
        Self {
            segments: Vec::new(),
            retained: Vec::new(),
            sensitive: self.sensitive,
            deferred: false,
            seam_sources: None,
            cut_fps: None,
            seam_excuses: None,
            joins: Joins::None,
            judged: Judged::Unread { receipt, step },
            recorded: AtomicBool::default(),
            leaf_hashes: None,
            cut_charge: None,
            cut_lost: false,
        }
    }

    /// Kept to a read answer (D9): a staged step keeps to `found`; a
    /// pending receipt is marked kept; a judged one is unchanged.
    pub(in super::super) fn judged_kept(mut self, found: view::Found<'_>) -> Self {
        self.judged = match std::mem::take(&mut self.judged) {
            Judged::Pending => Judged::Kept(None),
            Judged::Staged(big) => Judged::Kept(Some(big.keep_to(found))),
            judged @ (Judged::Kept(_) | Judged::Unread { .. }) => judged,
        };
        self
    }

    /// `MIK-8066` 2b D3 + amendment A1: kept to an over-bound answer's view.
    /// No text receipt and no joins survive (they need leaf order); what the
    /// step holds that the view holds, exactly, becomes the cut, which the
    /// record sketches as the excuse and samples as evidence. Never deferred,
    /// so capping keeps the cut as it is.
    fn retaining_view(self, detector: &CollusionDetector, view: &view::AnswerView) -> Self {
        // Every form the leaves path fingerprints (each run's leaves, joined
        // and run together), so a step of leaves shorter than a k-gram still
        // has its joined text; and a cut an earlier view retention kept (the
        // rewritten route retains twice), so a second view never erases it.
        // One run's forms at a time, hashed as they stream.
        let mut cut: Vec<u64> = Vec::new();
        for run in self.runs() {
            for form in run_forms(&run) {
                cut.extend(
                    detector
                        .sampled_kgram_stream(form.chars())
                        .filter(|&h| view.contains(h)),
                );
            }
        }
        cut.extend(
            self.join_fingerprints(detector)
                .into_iter()
                .chain(self.retained.iter().copied())
                .chain(self.cut_fps.iter().flat_map(|kept| kept.iter().copied()))
                .filter(|&h| view.contains(h)),
        );
        cut.sort_unstable();
        cut.dedup();
        // A5: the cut is charged from here to record, reserved while any
        // earlier charge is still held. Without room it is thinned to what
        // its record keeps and the excuse is marked lost (fail closed).
        let cut_charge = detector.views.budget.reserve(cut.len() * 8);
        let refused = cut_charge.is_none();
        let cut = if refused {
            detector
                .views
                .cut_refusals
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            telemetry_metrics::counter!(
                super::collusion::CAPACITY_METRIC,
                "bound" => "plan_view_cut_budget"
            )
            .increment(1);
            CollusionDetector::thinned_for_record(Vec::new(), &cut).1
        } else {
            cut
        };
        let cut_lost = self.cut_lost || refused;
        Self {
            segments: Vec::new(),
            retained: Vec::new(),
            sensitive: self.sensitive,
            deferred: false,
            seam_sources: None,
            cut_fps: (!cut.is_empty()).then(|| cut.into()),
            seam_excuses: None,
            joins: Joins::None,
            judged: Judged::default(),
            recorded: AtomicBool::default(),
            leaf_hashes: None,
            cut_charge,
            cut_lost,
        }
    }
}
