// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Recording a delivery under a holder: a presented caller, or the one shared
//! unread holder (`MIK-8066` D6, A4), with evidence thinned to what a record
//! keeps.

use super::*;

impl CollusionDetector {
    /// The one holder every unread plan records its evidence under (D6, A4):
    /// shared by every caller, so unread evidence adds at most one holder per
    /// fingerprint whatever the caller count. Each caller is marked lost on
    /// its own; the holder is another principal to every caller.
    pub(super) fn unread_holder() -> HolderId {
        HolderId {
            key: unread_key().hash_one(""),
            unread: true,
        }
    }

    /// Evidence as its record will keep it, computed once at retention so
    /// nothing larger is held until record: `fps` to the per-delivery bound,
    /// and `cut` thinned into the room left. For an unread receipt (D6),
    /// whose holder keeps no sketch, and for a view cut refused its charge
    /// (A5), whose excuse is lost.
    pub(crate) fn thinned_for_record(mut fps: Vec<u64>, cut: &[u64]) -> (Vec<u64>, Vec<u64>) {
        fps.truncate(MAX_SOURCE_FINGERPRINTS);
        let room = MAX_SOURCE_FINGERPRINTS.saturating_sub(fps.len());
        let (_, middle) = thin::thinned_middle(cut, &fps, room);
        (fps, middle)
    }

    /// Record an unread plan receipt's evidence (D6) under the shared unread
    /// holder (A4): its fingerprints, its cut's middle and a step's candidates
    /// sampled as evidence, nothing sketched, so nothing excuses anyone.
    pub(crate) fn record_unread_at(
        &self,
        source: &str,
        (sensitive, flows): (bool, u64),
        recorded: Recorded<'_>,
        now: Instant,
    ) {
        self.record_holder_at(
            source,
            Self::unread_holder(),
            (sensitive, Flows::Any(flows)),
            recorded,
            now,
        );
    }

    pub(super) fn record_holder_at(
        &self,
        source: &str,
        id: HolderId,
        (sensitive, flows): (bool, Flows),
        (mut fps, cut, sample): Recorded<'_>,
        now: Instant,
    ) {
        if self.params.action == RelayAction::Off {
            return;
        }
        // `MIK-8066.EXCUSE.1`: what a cut or truncation drops is still the
        // caller's own copy, so it is sketched, one sketch per delivery.
        let mut sketched: Vec<u64> = cut.as_deref().map(<[u64]>::to_vec).unwrap_or_default();
        if fps.len() > MAX_SOURCE_FINGERPRINTS {
            let cut_off = count(fps.len() - MAX_SOURCE_FINGERPRINTS);
            self.source_truncated.fetch_add(cut_off, Ordering::Relaxed);
            telemetry_metrics::counter!(CAPACITY_METRIC, "bound" => "receipt_truncated")
                .increment(cut_off);
            sketched.extend_from_slice(&fps);
            fps.truncate(MAX_SOURCE_FINGERPRINTS);
        }
        // `MIK-8066.CAP.2`: a thinned sample of the cut middle is evidence,
        // under the caller's own records (so it excuses the caller's copy
        // too), in the room the receipt left under the per-delivery bound.
        // `MIK-8066.BIG.3`: a plan step's exact evidence candidates, sampled
        // the same way; never sketched, so a Bloom hit never becomes one.
        for candidates in [cut.as_deref(), sample].into_iter().flatten() {
            let room = MAX_SOURCE_FINGERPRINTS.saturating_sub(fps.len());
            let (_, middle) = thin::thinned_middle(candidates, &fps, room);
            fps.extend(middle);
        }
        // An unread holder is never excused: it keeps no sketch (D6).
        if id.unread {
            sketched.clear();
        }
        sketched.sort_unstable();
        sketched.dedup();
        let pair = (self.digest(source), id.key);
        let window = self.params.window;
        // `MIK-8200`: the position is reserved under the lock, the sketch
        // built outside it, then published with the receipt in one step.
        let mut pending = Pending {
            state: &self.state,
            reservation: None,
        };
        if !sketched.is_empty() {
            let mut state = self.state.lock();
            state.sweep(now, window);
            pending.reservation = state.sketches.reserve(pair, sketched.len());
            // A loss is marked under the lock that caused it, so no egress
            // checked during the build sees it unmarked (`MIK-8201`).
            for lost in state.sketches.take_lost() {
                state.markers.mark(lost, now + window);
            }
        }
        let built = pending
            .reservation
            .as_ref()
            .map(|r| std::sync::Arc::new(sketch::Sketch::build(&sketched, r.shape)));
        let holder = |at| Holder {
            source: self.digest(source),
            principal: id.key,
            copies: Copies::one(at),
            sensitive: sensitive.then(|| Copies::one(at)),
            flows: flows.clone(),
            unread: id.unread,
        };
        let mut state = self.state.lock();
        state.sweep(now, window);
        if let (Some(reservation), Some(sketch)) = (pending.reservation.take(), built) {
            state.sketches.publish(&reservation, sketch, now);
        }
        let until = now + window;
        for lost in state.sketches.take_lost() {
            state.markers.mark(lost, until);
        }
        let me = id.key;
        for fp in fps {
            // Calls can reach the lock out of time order; an entry's age only
            // ever moves forward.
            let mut touched = now;
            let holders = if let Some(entry) = state.remove(fp) {
                state.order.remove(&entry.order);
                touched = touched.max(entry.order.0);
                entry.holders
            } else {
                if state.entries.len() >= self.params.max_fingerprints
                    && let Some((_, oldest)) = state.order.pop_first()
                {
                    state.remove(oldest);
                    self.evicted.fetch_add(1, Ordering::Relaxed);
                    telemetry_metrics::counter!(CAPACITY_METRIC, "bound" => "fingerprint_evicted")
                        .increment(1);
                }
                Holders::Tracked(holders::Tracked::default())
            };
            let room = self.pool_capacity.saturating_sub(state.pool);
            let (holders, lost) = self.add(holders, holder(now), now, room);
            if let Some(source) = lost {
                state.markers.mark((source, me), until);
            }
            let order = state.stamp(touched, fp);
            state.insert(fp, Entry { holders, order });
        }
    }
}
