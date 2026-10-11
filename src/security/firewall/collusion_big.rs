// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066.BIG.3`: bounded fingerprint state for plan steps past the 1 MiB
//! plan bound (design r5.1). Such a step is capped at staging, so its text
//! is gone by the time the plan's answer is known. In its place it keeps:
//! - `step_ev`, its sampled fingerprints thinned to a budget (exact): the
//!   evidence candidates, kept only where the answer delivered them;
//! - `step_all`, a Bloom filter over all its sampled fingerprints: the
//!   answer's fingerprints it holds become the caller's excuse sketch;
//! - a sketch position reserved at staging (F1), sized with headroom for the
//!   filter's false positives, so a step delivered whole never overflows.
//!
//! A Bloom hit is never evidence: only `step_ev`'s exact entries are.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::CollusionDetector;
use super::sketch::{P0, Reservation, Shape, Sketch, shape};
use super::thin::thinned_middle;

/// The most sampled fingerprints one retention can select from: 4 × 1 MiB
/// of text, one k-gram in four. In 2a an answer is at most 1 MiB of text
/// (`DELIVERED_SET_CAP`), well under it; P3's bounded view (PR 2b) will
/// drop an answer past it whole. The headroom is sized for it.
pub(super) const PLAN_ANSWER_FPS: usize = 1 << 20;

/// Fingerprints kept per over-bound step at staging (`step_ev`), before
/// the per-delivery bound thins them again at record time.
pub(super) const STEP_EV_BUDGET: usize = 32_768;

/// The extra sketch room a step reserves at logical position `position`
/// for false positives its Bloom filter selects from the answer view.
/// Bernstein's bound at a 1e-12 tail, for `PLAN_ANSWER_FPS` candidates each a
/// false positive with probability at most 2 · (P0/2) · 2^-position
/// (twice the sizing target): at least 19, 4,130 at position 0.
pub(super) fn headroom(position: usize) -> usize {
    let halvings = i32::try_from(position.min(1_000)).unwrap_or(1_000);
    let rate_bound = P0 * 2f64.powi(-halvings);
    #[expect(clippy::cast_precision_loss, reason = "a constant far below 2^52")]
    let mean = PLAN_ANSWER_FPS as f64 * rate_bound;
    let ln_tail = 1e12f64.ln();
    let spread = ln_tail / 3.0 + ((ln_tail / 3.0).powi(2) + 2.0 * mean * ln_tail).sqrt();
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a positive count far below usize::MAX"
    )]
    let room = (mean + spread).ceil() as usize;
    room
}

/// `fps` thinned to at most `budget` with CAP.2's selector: the rate `m`
/// and the survivors. A step's staged evidence candidates.
pub(super) fn stage_thinned(fps: &[u64], budget: usize) -> (u64, Vec<u64>) {
    thinned_middle(fps, &[], budget)
}

/// The sketch shape a step reserves for `n` fingerprints at logical
/// position `position`: room for its own fingerprints plus the headroom,
/// at the target (P0/2)·2^-position (`shape`'s position + 1).
pub(super) fn reservation_shape(n: usize, position: usize) -> Shape {
    shape(n + headroom(position), position + 1)
}

/// A step's pending sketch position. Dropped unpublished (the step was
/// omitted, its plan dropped, or its sketch overflowed), it is abandoned,
/// so a pending reservation never outlives its plan.
pub(crate) struct StepReservation {
    detector: Arc<CollusionDetector>,
    reservation: Mutex<Option<Reservation>>,
    /// The step's own sampled fingerprint count.
    n: usize,
    /// The room reserved beyond `n`.
    headroom: usize,
}

impl StepReservation {
    fn shape(&self) -> Option<Shape> {
        self.reservation.lock().ok()?.as_ref().map(|r| r.shape)
    }

    fn take(&self) -> Option<Reservation> {
        self.reservation.lock().ok()?.take()
    }
}

impl Drop for StepReservation {
    fn drop(&mut self) {
        if let Some(reservation) = self.take() {
            self.detector.state.lock().sketches.abandon(&reservation);
        }
    }
}

/// A plan step past the plan bound: its attachments, then, once kept to the
/// answer, the fingerprints the answer delivered from it.
pub(crate) struct BigStep {
    reservation: StepReservation,
    /// Exact-size, so the bytes charged are the bytes held (a thinned
    /// `Vec` keeps its pre-thinning capacity).
    step_ev: Box<[u64]>,
    /// Dropped at retention, before the final sketch is built: between
    /// staging and record only the reserved bytes are held. Retention itself
    /// briefly holds one step's selection while it builds the sketch: 8 bytes
    /// per selected fingerprint, up to about twice that as the `Vec` grows
    /// (sizing it exactly would need a second probe pass over the answer).
    /// Uncharged, and freed before retention returns.
    step_all: Option<Sketch>,
    /// Exact evidence candidates: `step_ev` entries the answer delivered.
    evidence: Option<Arc<[u64]>>,
    /// The excuse sketch, built at retention in the reserved shape from the
    /// answer fingerprints `step_all` holds; published at record.
    excuse: Option<Arc<Sketch>>,
}

impl BigStep {
    /// The attachments of a step whose sampled fingerprints are `fps`, for
    /// `caller` from `source`, within `room` bytes of the plan; `None` when
    /// the sketch store or the plan has no room, and the pair's excuse is
    /// then marked lost. The fit is checked before the filter is built, so a
    /// skipped step never pays for one (F5).
    pub(crate) fn new(
        detector: &Arc<CollusionDetector>,
        (source, caller): (&str, &str),
        fps: &[u64],
        room: usize,
    ) -> Option<Self> {
        let mut fps = fps.to_vec();
        fps.sort_unstable();
        fps.dedup();
        let (_, step_ev) = stage_thinned(&fps, STEP_EV_BUDGET);
        // The evidence attachment is charged to the reservation, so every
        // attachment byte is inside the sketch store's global budget.
        let reservation = detector.reserve_step(source, caller, fps.len(), step_ev.len() * 8)?;
        let shape = reservation.shape()?;
        if shape.bytes() + step_ev.len() * 8 > room {
            drop(reservation);
            detector.mark_step_lost(source, caller);
            telemetry_metrics::counter!(super::CAPACITY_METRIC, "bound" => "plan_step_fps_skipped")
                .increment(1);
            return None;
        }
        Some(Self {
            step_all: Some(Sketch::build(&fps, shape)),
            step_ev: step_ev.into_boxed_slice(),
            evidence: None,
            excuse: None,
            reservation,
        })
    }

    /// Bytes the attachments hold, charged to the plan's total.
    pub(crate) fn bytes(&self) -> usize {
        self.step_ev.len() * 8 + self.step_all.as_ref().map_or(0, Sketch::bytes)
    }
}

impl BigStep {
    /// Keep the step to what the answer delivered: `found` is every k-gram
    /// hash of the answer. Its evidence is the exact `step_ev` entries found;
    /// its excuse is the sampled answer hashes `step_all` holds. A selection
    /// past the reserved room (n + headroom) abandons the sketch, counted
    /// and marked: never overfilled. An empty one leaves nothing to publish.
    /// The selection itself is transient: what stays until record is the
    /// sketch, whose bytes the reservation charged.
    pub(crate) fn keep_to(&mut self, found: &HashSet<u64>) {
        // Retention runs once: a second call finds no filter and keeps the
        // first call's evidence and excuse.
        let Some(step_all) = self.step_all.take() else {
            return;
        };
        let detector = Arc::clone(&self.reservation.detector);
        let evidence: Vec<u64> = self
            .step_ev
            .iter()
            .copied()
            .filter(|fp| found.contains(fp))
            .collect();
        self.evidence = (!evidence.is_empty()).then(|| evidence.into());
        let selection: Vec<u64> = found
            .iter()
            .copied()
            .filter(|&h| detector.keeps(h) && step_all.holds(h))
            .collect();
        drop(step_all);
        self.step_ev = Box::default();
        let room = self.reservation.n + self.reservation.headroom;
        let mut state = detector.state.lock();
        if let Some(reservation) = self
            .reservation
            .reservation
            .lock()
            .ok()
            .and_then(|r| r.as_ref().map(Reservation::pair))
        {
            #[cfg(test)]
            {
                state.sketches.last_selection =
                    Some((reservation, selection.len(), self.reservation.n));
            }
            if selection.len() > room {
                state.sketches.overfull += 1;
                telemetry_metrics::counter!(super::CAPACITY_METRIC, "bound" => "sketch_overfull")
                    .increment(1);
                state.sketches.mark_lost(reservation);
                if let Some(held) = self.reservation.take() {
                    state.sketches.abandon(&held);
                }
                let until = Instant::now() + detector.params.window;
                for lost in state.sketches.take_lost() {
                    state.markers.mark(lost, until);
                }
                return;
            }
        }
        drop(state);
        if selection.is_empty() {
            return;
        }
        if let Some(shape) = self.reservation.shape() {
            self.excuse = Some(Arc::new(Sketch::build(&selection, shape)));
        }
    }

    /// The exact evidence candidates kept by [`Self::keep_to`].
    pub(crate) fn evidence(&self) -> Option<Arc<[u64]>> {
        self.evidence.clone()
    }

    /// Publish the excuse sketch into the reserved position (at record).
    /// Without one the reservation is dropped, which abandons it.
    pub(crate) fn publish(&self, now: Instant) {
        let Some(sketch) = &self.excuse else {
            return;
        };
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        let sketch = Arc::clone(sketch);
        let detector = &self.reservation.detector;
        let mut state = detector.state.lock();
        state.sketches.publish(&reservation, sketch, now);
        let until = now + detector.params.window;
        for lost in state.sketches.take_lost() {
            state.markers.mark(lost, until);
        }
    }
}

impl CollusionDetector {
    /// [`Self::record_cut_fingerprints_at`] with exact evidence candidates
    /// (`sample`) sampled into the record but never sketched.
    pub(crate) fn record_sampled_at(
        &self,
        (source, principal): (&str, &str),
        (sensitive, flows): (bool, u64),
        (fps, cut, sample): super::Recorded,
        now: Instant,
    ) {
        self.record_held_at(
            source,
            principal,
            (sensitive, super::Flows::Any(flows)),
            (fps, cut, sample),
            now,
        );
    }
}

impl CollusionDetector {
    /// Whether `hash` is a sampled fingerprint (one k-gram in `SAMPLE`).
    pub(super) fn keeps(&self, hash: u64) -> bool {
        hash.is_multiple_of(self.sample)
    }

    /// Reserve `caller`'s next sketch position from `source` for a step of
    /// `n` sampled fingerprints, sized with its headroom (F1, H rule).
    fn reserve_step(
        self: &Arc<Self>,
        source: &str,
        caller: &str,
        n: usize,
        extra: usize,
    ) -> Option<StepReservation> {
        let pair = (self.digest(source), self.digest(caller));
        let now = Instant::now();
        let window = self.params.window;
        let mut state = self.state.lock();
        state.sweep(now, window);
        #[cfg(test)]
        let zero = state.sketches.zero_headroom;
        #[cfg(not(test))]
        let zero = false;
        let room = |position: usize| if zero { 0 } else { headroom(position) };
        let reservation = state.sketches.reserve_sized(
            pair,
            |position| {
                if zero {
                    shape(n, position + 1)
                } else {
                    reservation_shape(n, position)
                }
            },
            extra,
            false,
        );
        for lost in state.sketches.take_lost() {
            state.markers.mark(lost, now + window);
        }
        let reservation = reservation?;
        let headroom = room(reservation.position());
        Some(StepReservation {
            detector: Arc::clone(self),
            reservation: Mutex::new(Some(reservation)),
            n,
            headroom,
        })
    }

    /// Mark `caller`'s excuse from `source` lost for room: a step whose
    /// attachments did not fit the plan (F5).
    fn mark_step_lost(&self, source: &str, caller: &str) {
        let pair = (self.digest(source), self.digest(caller));
        let until = Instant::now() + self.params.window;
        let mut state = self.state.lock();
        state.sketches.mark_lost(pair);
        for lost in state.sketches.take_lost() {
            state.markers.mark(lost, until);
        }
    }
}

#[cfg(test)]
impl CollusionDetector {
    /// The live and pending sketch positions of `principal` from `source`.
    pub(crate) fn sketch_positions(&self, source: &str, principal: &str) -> Vec<usize> {
        let pair = (self.digest(source), self.digest(principal));
        self.state.lock().sketches.positions_with_pending(pair)
    }

    /// Whether a live sketch of `principal`'s from `source` holds `fp`.
    pub(crate) fn sketch_holds(&self, source: &str, principal: &str, fp: u64) -> bool {
        let pair = (self.digest(source), self.digest(principal));
        let window = self.params.window;
        self.state
            .lock()
            .sketches
            .holds(pair, fp, Instant::now(), window)
    }

    /// One k-gram in `sample_rate()` is a sampled fingerprint.
    pub(crate) fn sample_rate(&self) -> u64 {
        self.sample
    }

    /// The live (published) sketch positions of `principal` from `source`.
    pub(crate) fn live_sketch_positions(&self, source: &str, principal: &str) -> Vec<usize> {
        let pair = (self.digest(source), self.digest(principal));
        self.state.lock().sketches.positions_of(pair)
    }

    /// Whether any exact record holds `fp`.
    pub(crate) fn tracks(&self, fp: u64) -> bool {
        self.is_tracked(fp)
    }

    /// Bytes of every live and pending sketch.
    pub(crate) fn sketch_bytes_held(&self) -> usize {
        self.state.lock().sketches.bytes_held()
    }

    /// Whether `principal`'s excuse from `source` is marked lost for room.
    pub(crate) fn excuse_lost(&self, source: &str, principal: &str) -> bool {
        let pair = (self.digest(source), self.digest(principal));
        self.state.lock().markers.holds(pair, Instant::now())
    }

    /// Sketches abandoned because their selection passed n + H.
    pub(crate) fn overfull_sketches(&self) -> u64 {
        self.state.lock().sketches.overfull
    }

    /// The last retention's (distinct selected, own count) for a pair.
    pub(crate) fn last_selection(&self, source: &str, principal: &str) -> Option<(usize, usize)> {
        let pair = (self.digest(source), self.digest(principal));
        match self.state.lock().sketches.last_selection {
            Some((p, selected, own)) if p == pair => Some((selected, own)),
            _ => None,
        }
    }

    /// STUB (`MIK-8066` 2b red): the answer text cap P3 reads under. A no-op
    /// until the view lands, so a row using it fails at its own assertion.
    pub(crate) fn set_answer_text_cap(&self, bytes: usize) {
        let _ = (self, bytes);
    }

    /// STUB (2b red): the view's entry cap A.
    pub(crate) fn set_view_entry_cap(&self, entries: usize) {
        let _ = (self, entries);
    }

    /// STUB (2b red): `VIEW_BYTES` held by live views.
    pub(crate) fn view_bytes(&self) -> usize {
        let _ = self;
        0
    }

    /// STUB (2b red): plans whose answer took the unread path (D6).
    pub(crate) fn unread_plans(&self) -> u64 {
        let _ = self;
        0
    }

    /// STUB (2b red): the `VIEW_BYTES` charge `answer`'s view would take,
    /// computed from the view's length, not from the budget counter.
    pub(crate) fn view_charge_of(&self, answer: &serde_json::Value) -> usize {
        let _ = (self, answer);
        0
    }

    /// STUB (2b red): `VIEW_BYTES` lowered for this detector.
    pub(crate) fn set_view_budget(&self, bytes: usize) {
        let _ = (self, bytes);
    }

    /// STUB (2b red): views refused for lack of `VIEW_BYTES` (D6).
    pub(crate) fn view_budget_refusals(&self) -> u64 {
        let _ = self;
        0
    }

    /// Reserve no headroom on this detector (the abandon path, made
    /// reachable).
    pub(crate) fn zero_headroom(&self) {
        self.state.lock().sketches.zero_headroom = true;
    }
}

#[cfg(test)]
#[path = "collusion_big_tests.rs"]
mod tests;
