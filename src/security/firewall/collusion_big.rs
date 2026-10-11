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

use std::sync::atomic::Ordering;
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

/// `MIK-8066` D8: the transient budget every answer view (P3 and <= 1 MiB)
/// reserves from while its answer is judged; separate from the sketch
/// store's `SKETCH_BYTES`, so window-long sketches never decide whether a
/// millisecond judgement runs. Combined worst case 64 MiB. A constant.
pub(crate) const VIEW_BYTES: usize = 32 * 1024 * 1024;

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

/// A plan step past the plan bound, staged: its attachments, until the
/// plan's answer judges it. Its only exits consume it (D9):
/// [`BigStep::keep_to`] and [`BigStep::into_unread`]. Dropped un-judged (its
/// plan dropped before any answer), its reservation is abandoned and
/// nothing is recorded: nothing was delivered.
pub(crate) struct BigStep {
    reservation: StepReservation,
    /// Exact-size, so the bytes charged are the bytes held (a thinned
    /// `Vec` keeps its pre-thinning capacity).
    step_ev: Box<[u64]>,
    /// Dropped at retention, before the final sketch is built: between
    /// staging and record only the reserved bytes are held.
    step_all: Sketch,
}

/// Bytes of step evidence split off a sketch reservation (D9): charged to
/// the sketch store's total while it lives, released when it drops.
pub(crate) struct EvidenceCharge {
    detector: Arc<CollusionDetector>,
    bytes: usize,
}

impl Drop for EvidenceCharge {
    fn drop(&mut self) {
        self.detector
            .state
            .lock()
            .sketches
            .release_extra(self.bytes);
        self.detector
            .views
            .evidence_bytes
            .fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

/// A judged step's exact evidence candidates, with their charge (D9).
#[must_use]
pub(crate) struct StepEvidence {
    fps: Arc<[u64]>,
    /// Held for its `Drop`: evidence never outlives its charge.
    _charge: EvidenceCharge,
}

impl StepEvidence {
    /// The candidates, offered to the record's sample.
    pub(crate) fn fps(&self) -> Arc<[u64]> {
        Arc::clone(&self.fps)
    }
}

/// A built excuse sketch in its reserved position, published at record.
pub(crate) struct Excuse {
    sketch: Arc<Sketch>,
    reservation: StepReservation,
}

/// A step kept to what its answer delivered (D9): the exact `step_ev`
/// entries the view holds, and the excuse sketch (`None` when abandoned,
/// overfull, empty or refused for selection room, already marked).
#[must_use]
pub(crate) struct KeptStep {
    pub(crate) evidence: Option<StepEvidence>,
    pub(crate) excuse: Option<Excuse>,
}

/// A step whose answer could not be read (D6/D9): all of `step_ev` is
/// evidence; its sketch was abandoned, so it can never publish.
#[must_use]
pub(crate) struct UnreadStep {
    pub(crate) evidence: StepEvidence,
}

impl StepReservation {
    /// Move the evidence bytes off the reservation into their own charge.
    fn split_evidence(&self) -> EvidenceCharge {
        let detector = Arc::clone(&self.detector);
        let bytes = self.reservation.lock().ok().map_or(0, |mut held| {
            held.as_mut()
                .map_or(0, |r| detector.state.lock().sketches.split_extra(r))
        });
        detector
            .views
            .evidence_bytes
            .fetch_add(bytes, Ordering::Relaxed);
        EvidenceCharge { detector, bytes }
    }

    /// Abandon the sketch position, mark the pair's excuse lost.
    fn abandon_marked(&self) {
        let detector = &self.detector;
        let mut state = detector.state.lock();
        if let Some(held) = self.take() {
            state.sketches.mark_lost(held.pair());
            state.sketches.abandon(&held);
        }
        let until = Instant::now() + detector.params.window;
        for lost in state.sketches.take_lost() {
            state.markers.mark(lost, until);
        }
    }
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
            step_all: Sketch::build(&fps, shape),
            step_ev: step_ev.into_boxed_slice(),
            reservation,
        })
    }

    /// A copy of the staged evidence candidates, for the one record arm
    /// that meets a step never judged (D9: recorded as unread, fail closed).
    pub(crate) fn staged_evidence(&self) -> Arc<[u64]> {
        Arc::from(&*self.step_ev)
    }

    /// Bytes the attachments hold, charged to the plan's total.
    pub(crate) fn bytes(&self) -> usize {
        self.step_ev.len() * 8 + self.step_all.bytes()
    }
}

impl BigStep {
    /// Keep the step to what the answer delivered (D3, D9). Its evidence is
    /// the exact `step_ev` entries `found` holds; its excuse is the answer's
    /// sampled hashes `step_all` holds. The selection is reserved from
    /// `VIEW_BYTES` first (n + headroom + 1 entries: one past the room proves
    /// overflow); without room the sketch is abandoned, counted and marked,
    /// and the evidence kept. A selection past the room abandons the sketch,
    /// counted and marked: never overfilled.
    pub(crate) fn keep_to(
        self,
        found: super::super::collusion_digest::view::Found<'_>,
    ) -> KeptStep {
        let Self {
            reservation,
            step_ev,
            step_all,
        } = self;
        let detector = Arc::clone(&reservation.detector);
        let charge = reservation.split_evidence();
        let kept: Vec<u64> = step_ev
            .iter()
            .copied()
            .filter(|&fp| found.contains(fp))
            .collect();
        drop(step_ev);
        let evidence = (!kept.is_empty()).then(|| StepEvidence {
            fps: kept.into(),
            _charge: charge,
        });
        let room = reservation.n + reservation.headroom;
        let Some(selection_charge) = detector.views.budget.reserve((room + 1) * 8) else {
            detector
                .views
                .selection_refusals
                .fetch_add(1, Ordering::Relaxed);
            telemetry_metrics::counter!(super::CAPACITY_METRIC, "bound" => "plan_selection_budget")
                .increment(1);
            reservation.abandon_marked();
            return KeptStep {
                evidence,
                excuse: None,
            };
        };
        // A view's entries are already sampled: no `keeps` recheck (D8).
        let presampled = found.presampled();
        let mut selection: Vec<u64> = Vec::with_capacity(room + 1);
        found.for_each(|h| {
            if selection.len() <= room && (presampled || detector.keeps(h)) && step_all.holds(h) {
                selection.push(h);
            }
        });
        drop(step_all);
        #[cfg(test)]
        if let Some(pair) = reservation
            .reservation
            .lock()
            .ok()
            .and_then(|r| r.as_ref().map(Reservation::pair))
        {
            detector.state.lock().sketches.last_selection =
                Some((pair, selection.len(), reservation.n));
        }
        if selection.len() > room {
            detector.state.lock().sketches.overfull += 1;
            telemetry_metrics::counter!(super::CAPACITY_METRIC, "bound" => "sketch_overfull")
                .increment(1);
            reservation.abandon_marked();
            return KeptStep {
                evidence,
                excuse: None,
            };
        }
        let excuse = match reservation.shape() {
            Some(shape) if !selection.is_empty() => Some(Excuse {
                sketch: Arc::new(Sketch::build(&selection, shape)),
                reservation,
            }),
            // Nothing selected: dropping the reservation abandons it.
            _ => None,
        };
        drop(selection);
        drop(selection_charge);
        KeptStep { evidence, excuse }
    }

    /// The step's answer could not be read (D6): all of `step_ev` is
    /// evidence, keeping its charge; the sketch reservation is abandoned
    /// (dropped), so an unread step never publishes.
    pub(crate) fn into_unread(self) -> UnreadStep {
        let Self {
            reservation,
            step_ev,
            step_all,
        } = self;
        drop(step_all);
        let charge = reservation.split_evidence();
        drop(reservation);
        UnreadStep {
            evidence: StepEvidence {
                fps: step_ev.into(),
                _charge: charge,
            },
        }
    }
}

impl Excuse {
    /// Publish the sketch into its reserved position (at record). A second
    /// call finds the reservation taken and does nothing.
    pub(crate) fn publish(&self, now: Instant) {
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        let detector = &self.reservation.detector;
        let mut state = detector.state.lock();
        state
            .sketches
            .publish(&reservation, Arc::clone(&self.sketch), now);
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
    pub(crate) fn mark_step_lost(&self, source: &str, caller: &str) {
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

    /// The answer text cap P3 reads under (`PLAN_ANSWER_TEXT`; tests lower it).
    pub(crate) fn set_answer_text_cap(&self, bytes: usize) {
        self.views
            .answer_text_cap
            .store(bytes, std::sync::atomic::Ordering::Relaxed);
    }

    /// The view's entry cap A.
    pub(crate) fn set_view_entry_cap(&self, entries: usize) {
        self.views
            .entry_cap
            .store(entries, std::sync::atomic::Ordering::Relaxed);
    }

    /// `VIEW_BYTES` held by live views.
    pub(crate) fn view_bytes(&self) -> usize {
        self.views.budget.used()
    }

    /// Second records of one digest, each a no-op (A2).
    pub(crate) fn double_records(&self) -> u64 {
        self.views.double_records.load(Ordering::Relaxed)
    }

    /// Plans whose answer took the unread path (D6).
    pub(crate) fn unread_plans(&self) -> u64 {
        self.views
            .unread_plans
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The `VIEW_BYTES` charge `answer`'s view would take,
    /// computed from the view's length, not from the budget counter.
    pub(crate) fn view_charge_of(&self, answer: &serde_json::Value) -> usize {
        super::super::collusion_digest::view::build(self, answer, None)
            .map_or(0, |v| v.charge_bytes())
    }

    /// The streaming sampled k-gram hashes of `text` (D2), collected.
    pub(crate) fn sampled_kgrams(&self, text: &str) -> Vec<u64> {
        self.sampled_kgram_stream(text.chars()).collect()
    }

    /// The sorted sampled view of `answer`, built without the
    /// over-bound gate (unit rows only).
    pub(crate) fn view_of(&self, answer: &serde_json::Value) -> Option<Vec<u64>> {
        super::super::collusion_digest::view::build(self, answer, None)
            .ok()
            .map(|v| v.entries().to_vec())
    }

    /// The view's entry cap A (`PLAN_ANSWER_FPS`), for rows outside this
    /// module.
    pub(crate) fn view_entry_cap(&self) -> usize {
        self.views
            .entry_cap
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether a view of `distinct` sampled hashes is admitted
    /// under the entry cap A.
    pub(crate) fn view_admits(&self, distinct: usize) -> bool {
        distinct
            <= self
                .views
                .entry_cap
                .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The most `VIEW_BYTES` a build of `answer` reserves at once.
    pub(crate) fn view_build_peak(&self, answer: &serde_json::Value) -> usize {
        self.view_build_probe(answer)
            .iter()
            .map(|&(reserved, _)| reserved)
            .max()
            .unwrap_or(0)
    }

    /// (reserved bytes, live buffer bytes) at the first reservation, every
    /// growth and compaction while `answer`'s view is built.
    pub(crate) fn view_build_probe(&self, answer: &serde_json::Value) -> Vec<(usize, usize)> {
        let mut probe = Vec::new();
        let _ = super::super::collusion_digest::view::build(self, answer, Some(&mut probe));
        probe
    }

    /// Bytes charged for step evidence awaiting record (D9).
    pub(crate) fn evidence_charge_bytes(&self) -> usize {
        self.views.evidence_bytes.load(Ordering::Relaxed)
    }

    /// Selections refused for lack of `VIEW_BYTES`.
    pub(crate) fn selection_budget_refusals(&self) -> u64 {
        self.views.selection_refusals.load(Ordering::Relaxed)
    }

    /// STUB (2b red): reference lists the answer walks built.
    pub(crate) fn walk_refs_built(&self) -> u64 {
        let _ = self;
        0
    }

    /// `VIEW_BYTES` lowered for this detector.
    pub(crate) fn set_view_budget(&self, bytes: usize) {
        self.views.set_budget_cap(bytes);
    }

    /// Views refused for lack of `VIEW_BYTES` (D6).
    pub(crate) fn view_budget_refusals(&self) -> u64 {
        self.views
            .budget_refusals
            .load(std::sync::atomic::Ordering::Relaxed)
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
