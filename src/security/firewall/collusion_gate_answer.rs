// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Reading a plan's final answer and keeping its receipts to it
//! (MIK-7887.RECEIPT.2; `MIK-8066` 2b: the view, the unread path and the
//! judgement, D6/D8/D9).

use super::{
    CAPACITY_METRIC, CollusionDetector, Delivered, DeliveryDigest, Firewall, Mode, Ordering,
    PLAN_DROP_METRIC, PlanStaging, UnreadReceipt, Value, delivery_parts, view,
};

impl Firewall {
    /// The leaves of a plan's final answer that its step receipts are kept
    /// against (MIK-7887.RECEIPT.2). `None` with relay detection off, or over
    /// the bound, where the plan's receipts are dropped and counted.
    pub(crate) fn delivered_for_plan<'v>(
        &self,
        answer: &'v Value,
        staged: Option<&PlanStaging>,
    ) -> Option<Delivered<'v>> {
        let _ = staged;
        let delivered = self.read_answer(answer)?;
        if let Some(why) = delivered.unread_reason() {
            self.count_unread(why);
        }
        Some(delivered)
    }

    /// `answer` read leaf by leaf under the 1 MiB bound, else as a bounded
    /// view (`MIK-8066` 2b D1), else unread (D6). The allocation-free
    /// preflight runs first, so no walk ever runs past its caps. Uncounted.
    pub(super) fn read_answer<'v>(&self, answer: &'v Value) -> Option<Delivered<'v>> {
        let detector = self.relay_detector()?;
        // The walks' charge is reserved before the first walk allocates (D8).
        let walk = match view::reserve_walk(detector, answer) {
            Ok(walk) => walk,
            Err(why) => return Some(Delivered::of_mode(Mode::Unread(why))),
        };
        let (leaves, values) = delivery_parts(answer);
        if let Some(delivered) = Delivered::of_parts(leaves, values) {
            // D8: retention reads even a leaf reading through its sampled,
            // charged view; no room means unread.
            return Some(match view::build_with(detector, answer, walk, None) {
                Ok(view) => delivered.with_answer(answer).with_found_view(view),
                Err(why) => Delivered::of_mode(Mode::Unread(why)),
            });
        }
        Some(match view::build_with(detector, answer, walk, None) {
            Ok(view) => Delivered::of_mode(Mode::View(view)).with_answer(answer),
            Err(why) => Delivered::of_mode(Mode::Unread(why)),
        })
    }

    /// Count a plan whose answer could not be read (D6): for want of
    /// `VIEW_BYTES` room, or past a cap.
    pub(super) fn count_unread(&self, why: view::Unreadable) {
        let Some(detector) = self.relay_detector() else {
            return;
        };
        let (counter, bound) = match why {
            view::Unreadable::NoRoom => (&detector.views.budget_refusals, "plan_view_budget"),
            view::Unreadable::Shape | view::Unreadable::EntryCap => {
                (&detector.views.unread_plans, "plan_answer_unread")
            }
        };
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        telemetry_metrics::counter!(CAPACITY_METRIC, "bound" => bound).increment(1);
    }

    /// What `answer` delivers, read as `delivered_for_plan` reads it; when it is
    /// over the bound, what `fallback` (the same text read as one leaf)
    /// delivers instead, so a fuller reading never loses a receipt the plainer
    /// one keeps (`MIK-8043.JOIN.4`). A drop is counted only when both fail.
    pub(crate) fn delivered_preferring<'v>(
        &self,
        answer: &'v Value,
        fallback: &'v Value,
        staged: Option<&PlanStaging>,
    ) -> Option<Delivered<'v>> {
        let _ = staged;
        let full = self.read_answer(answer)?;
        let Some(why) = full.unread_reason() else {
            return Some(full);
        };
        // `MIK-8066` 2b D7: the flat fallback only while the fuller reading
        // cannot be read; counted only when neither can.
        let flat = self.read_answer(fallback)?;
        if flat.unread_reason().is_none() {
            return Some(flat);
        }
        self.count_unread(why);
        Some(full)
    }

    /// [`Self::count_plan_drop`] unless this delivery already counted one:
    /// `staged` then holds `usize::MAX`, past every bound (`MIK-8094`).
    pub(super) fn count_plan_drop_once(&self, staged: &PlanStaging) {
        if staged.mark_dropped() {
            self.count_plan_drop();
        }
    }

    pub(super) fn count_plan_drop(&self) {
        self.relay.plan_drop.fetch_add(1, Ordering::Relaxed);
        telemetry_metrics::counter!(PLAN_DROP_METRIC).increment(1);
    }

    /// `digest` kept to what `delivered` carries, its deferred cap still to
    /// apply: the seam pass reads which leaves it keeps whole before
    /// [`Self::cap_kept`] cuts any (`MIK-8113`); unchanged with relay
    /// detection off.
    /// `step`, the receipt's plan step, has its own span of the answer
    /// matched first (`MIK-8209` K7).
    pub(crate) fn retain_delivered(
        &self,
        digest: DeliveryDigest,
        delivered: &Delivered<'_>,
        step: Option<u32>,
    ) -> DeliveryDigest {
        let Some(detector) = self.relay_detector() else {
            return digest;
        };
        let digest = digest.retaining_for(detector, delivered, step);
        // `MIK-8066` D6/D9: the judgement moves forward once; a second
        // retention (the rewritten route) leaves a judged receipt unchanged.
        if delivered.unread() {
            // What `record_kept` would record of the capped receipt.
            return digest.into_unread(|d| {
                let capped = self.capped(d);
                let receipt = capped.as_ref().unwrap_or(d);
                let (fps, middle) = CollusionDetector::thinned_for_record(
                    receipt.fingerprints(detector),
                    receipt.cut_fps.as_deref().unwrap_or_default(),
                );
                UnreadReceipt {
                    fps,
                    cut: (!middle.is_empty()).then(|| middle.into()),
                }
            });
        }
        // `MIK-8066.BIG.3`: a step past the plan bound keeps its evidence and
        // excuse to what the answer delivered.
        digest.judged_kept(delivered.found(detector))
    }

    /// `digest` with its deferred cap applied, a cut counted.
    pub(crate) fn cap_kept(&self, digest: DeliveryDigest) -> DeliveryDigest {
        self.capped(&digest).unwrap_or(digest)
    }
}
