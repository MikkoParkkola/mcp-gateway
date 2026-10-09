// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Verbatim cross-principal relay detection (OWASP ASI10, partial).
//!
//! Content delivered to principal A that principal B then sends out through a
//! backend call, when B never received it from that source itself. Each side
//! looks ordinary to a per-principal control; only the pair is suspicious.
//!
//! This is the pure core: sampled fingerprints, bounded in-process state and
//! the relay predicate. Wiring into the request and response paths, the
//! config surface and metrics come in later increments.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::BuildHasher;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use icu_normalizer::ComposingNormalizerBorrowed;
use parking_lot::Mutex;

/// What the detector does. Mirrors the operator-facing `collusion.action`;
/// the detector keeps the same state under both on-states, and the firewall
/// decides whether a finding refuses the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayAction {
    /// No state is kept.
    Off,
    /// Findings are reported, calls proceed.
    Observe,
    /// Findings are reported and the call is refused.
    Block,
}

/// Detector tuning. Defaults are the design's documented values.
#[derive(Debug, Clone)]
pub(crate) struct RelayParams {
    pub(crate) action: RelayAction,
    pub(crate) window: Duration,
    pub(crate) min_matches: usize,
    pub(crate) common_principals: usize,
    pub(crate) max_fingerprints: usize,
}

impl Default for RelayParams {
    fn default() -> Self {
        Self {
            action: RelayAction::Off,
            window: Duration::from_secs(600),
            min_matches: 2,
            common_principals: 5,
            max_fingerprints: 250_000,
        }
    }
}

/// A relay: content principal `receiver` got from `source` left via `sender`.
///
/// Carries digests and a count, never content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayFinding {
    pub(crate) source: u64,
    pub(crate) receiver: u64,
    pub(crate) sender: u64,
    pub(crate) tool: u64,
    pub(crate) matches: usize,
    pub(crate) reason: RelayReason,
}

/// Characters per k-gram. Nothing shorter than this can ever match.
pub(super) const K: usize = 48;
/// One k-gram in `SAMPLE` is kept, by its own hash: whether a k-gram is kept
/// never depends on the text around it, so two texts sharing a k-gram keep it
/// in both or in neither, and the same-source excuse is exact (MIK-8083).
const SAMPLE: u64 = 4;
/// The source a finding names when its witness is a caller's overflow: no
/// source survives for a record past the cap (`MIK-8123`).
const OVERFLOW_SOURCE: u64 = 0;

/// The largest `common_principals` a configuration may set: the boilerplate
/// guard stays meaningful only for text a handful of callers share.
pub(super) const MAX_COMMON_PRINCIPALS: usize = 9;
/// Fingerprints kept per delivered result; the rest are counted, not stored.
/// Twice one form's share: a split delivery records its newline-joined and
/// its run-together forms, which share almost no k-grams, and both are
/// expected to fit for a copy up to the record cap (sampling keeps about 1
/// in [`SAMPLE`] positions; crafted text can exceed it, costing only an
/// excuse).
const MAX_SOURCE_FINGERPRINTS: usize = 4 * 1_024;

/// One (source, principal) pair that received a fingerprint.
struct Holder {
    source: u64,
    principal: u64,
    /// Every delivery of this pair: what the same-source excuse reads.
    copies: Copies,
    /// The *sensitive* deliveries: what a relay witness reads. Kept apart so
    /// a plain re-delivery cannot extend sensitive evidence.
    sensitive: Option<Copies>,
    /// The `allowed_flows` entries this copy may leave through without being
    /// a relay.
    flows: Flows,
}

/// Which `allowed_flows` entries (one bit per entry) let a held copy leave
/// through an egress without being a relay.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Flows {
    /// An ordinary source: the entries whose source glob matched it; an
    /// egress matching any of them is allowed.
    Any(u64),
    /// A seam between plan steps (`MIK-8113`): one mask per contributing
    /// source; an egress is allowed only when it matches an entry of every
    /// one, so the joined text never leaves by a flow some contributor's text
    /// may not take. Never empty.
    Each(std::sync::Arc<[u64]>),
}

impl Flows {
    /// Whether an egress matching the entries in `egress` may carry this copy.
    fn allows(&self, egress: u64) -> bool {
        match self {
            Self::Any(mask) => mask & egress != 0,
            Self::Each(masks) => !masks.is_empty() && masks.iter().all(|m| m & egress != 0),
        }
    }

    /// A repeat delivery of the same pair: an ordinary source's entries
    /// accumulate; a seam's identity fixes its contributors, so its masks
    /// are the same and kept.
    fn merge(&mut self, more: Self) {
        if let (Self::Any(held), Self::Any(more)) = (&mut *self, more) {
            *held |= more;
        }
    }
}

enum Holders {
    /// Still judged (`MIK-8123`: never switched off by fan-out).
    Tracked(holders::Tracked),
    /// Held by `common_principals` distinct principals: boilerplate.
    Common,
}

impl Entry {
    fn pool_records(&self) -> usize {
        match &self.holders {
            Holders::Tracked(t) => t.pool_records(),
            Holders::Common => 0,
        }
    }
}

struct Entry {
    holders: Holders,
    /// Position in `State::order`: last touch, then insertion sequence.
    order: (Instant, u64),
}

#[derive(Default)]
struct State {
    entries: HashMap<u64, Entry>,
    /// Oldest-first index of `entries`, for expiry and the cap.
    order: BTreeMap<(Instant, u64), u64>,
    next_seq: u64,
    /// Pool records held across every entry (`MIK-8123`).
    pool: usize,
    /// What cut deliveries carried, by (source, caller): excuse only
    /// (`MIK-8066.EXCUSE.1`).
    sketches: sketch::SketchStore,
    /// "Excuse lost" markers, apart from the sketches (`MIK-8201`).
    markers: sketch::Markers,
}

impl State {
    fn sweep(&mut self, now: Instant, window: Duration) {
        while let Some((&(seen, seq), &fp)) = self.order.first_key_value() {
            if now.saturating_duration_since(seen) <= window {
                break;
            }
            self.order.remove(&(seen, seq));
            self.remove(fp);
        }
        self.sketches.sweep(now, window);
        self.markers.sweep(now);
    }

    /// Remove `fp`'s entry, releasing its pool records: every removal goes
    /// through here, so the pool count never leaks.
    fn remove(&mut self, fp: u64) -> Option<Entry> {
        let entry = self.entries.remove(&fp)?;
        self.pool -= entry.pool_records();
        Some(entry)
    }

    /// Insert `entry` for `fp`, taking its pool records.
    fn insert(&mut self, fp: u64, entry: Entry) {
        self.pool += entry.pool_records();
        self.entries.insert(fp, entry);
    }

    fn stamp(&mut self, now: Instant, fp: u64) -> (Instant, u64) {
        let key = (now, self.next_seq);
        self.next_seq += 1;
        self.order.insert(key, fp);
        key
    }
}

/// The hashes kept as fingerprints: those 0 mod `every` ([`SAMPLE`]),
/// distinct, in position order.
fn sample(hashes: &[u64], every: u64) -> Vec<u64> {
    let mut seen = HashSet::new();
    hashes
        .iter()
        .copied()
        .filter(|h| h % every == 0 && seen.insert(*h))
        .collect()
}

/// Relay detector state for one gateway process.
pub(crate) struct CollusionDetector {
    params: RelayParams,
    /// One k-gram in this many is kept: [`SAMPLE`], or 1 in a test that
    /// must not depend on the hash key.
    sample: u64,
    state: Mutex<State>,
    evicted: AtomicU64,
    /// Records that did not fit a caller's cap or the pool: plain ones
    /// dropped, sensitive ones kept as overflow (`MIK-8123`).
    capped: AtomicU64,
    source_truncated: AtomicU64,
    /// Pool records allowed across every fingerprint.
    pool_capacity: usize,
}

/// A sketch position held while its sketch is built outside the lock; if
/// the build never publishes it, dropping this releases the position and its
/// bytes (`MIK-8200`: a pending position is never evicted, so only its owner
/// may free it).
struct Pending<'a> {
    state: &'a Mutex<State>,
    reservation: Option<sketch::Reservation>,
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if let Some(reservation) = self.reservation.take() {
            self.state.lock().sketches.abandon(&reservation);
        }
    }
}

/// `SipHash` with a per-process random key: fingerprints and id digests are
/// not comparable across processes, and not precomputable by a caller.
fn key() -> &'static RandomState {
    static KEY: OnceLock<RandomState> = OnceLock::new();
    KEY.get_or_init(RandomState::new)
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

impl CollusionDetector {
    pub(crate) fn new(params: RelayParams) -> Self {
        Self {
            params,
            sample: SAMPLE,
            state: Mutex::new(State::default()),
            evicted: AtomicU64::new(0),
            capped: AtomicU64::new(0),
            source_truncated: AtomicU64::new(0),
            pool_capacity: holders::EXTRA_RECORD_POOL,
        }
    }

    /// Keyed 64-bit digest of an id (source, principal), as findings carry it.
    #[expect(
        clippy::unused_self,
        reason = "the key is per process; a method keeps callers from hashing with any other"
    )]
    pub(crate) fn digest(&self, id: &str) -> u64 {
        key().hash_one(id)
    }

    /// Sampled fingerprints of `text`, distinct, in position order.
    ///
    /// Characters input sanitization strips are dropped first, so text
    /// interleaved with them matches what a backend receives; then
    /// NFC-normalized and whitespace-collapsed; then every `K`-char
    /// k-gram is hashed and those [`sample`] keeps are kept. Context-free: a
    /// k-gram is kept wherever it occurs, whatever surrounds it.
    ///
    /// Scratch memory is linear in `text`; callers bound it with the request
    /// and response size limits, not this function.
    pub(crate) fn fingerprints(&self, text: &str) -> Vec<u64> {
        sample(&self.kgram_hashes(text), self.sample)
    }

    /// Keep every k-gram, so whether a text has fingerprints no longer
    /// depends on the per-process hash key (tests only).
    #[cfg(test)]
    pub(crate) fn keep_every_kgram(&mut self) {
        self.sample = 1;
    }

    /// Allow `n` pool records in all (tests only).
    #[cfg(test)]
    fn set_pool_capacity(&mut self, n: usize) {
        self.pool_capacity = n;
    }

    /// Pool records held now (tests only).
    #[cfg(test)]
    fn pool_in_use(&self) -> usize {
        self.state.lock().pool
    }

    /// Every `K`-char k-gram hash of `text`, normalised as
    /// [`Self::fingerprints`] reads it, before sampling: a fingerprint is
    /// one of these.
    pub(crate) fn kgram_hashes(&self, text: &str) -> Vec<u64> {
        let norm = self.normalized(text);
        let bounds: Vec<usize> = norm
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(norm.len()))
            .collect();
        let chars = bounds.len() - 1;
        if chars < K {
            return Vec::new();
        }
        (0..=chars - K)
            .map(|i| key().hash_one(&norm[bounds[i]..bounds[i + K]]))
            .collect()
    }

    /// `text` as every k-gram reads it: unsafe controls dropped, NFC,
    /// whitespace collapsed.
    #[expect(
        clippy::unused_self,
        reason = "one normalization for every reader, the seam pass included"
    )]
    fn normalized(&self, text: &str) -> String {
        let visible: String = text
            .chars()
            .filter(|&c| !crate::security::sanitize::is_unsafe_control(c))
            .collect();
        let nfc = ComposingNormalizerBorrowed::new_nfc().normalize(&visible);
        nfc.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Records a result delivered to `principal` from `source`.
    ///
    /// Every delivered result is recorded, sensitive or not, so B's own copy
    /// excuses B whichever side arrived first.
    pub(crate) fn record_delivery_at(
        &self,
        source: &str,
        principal: &str,
        sensitive: bool,
        text: &str,
        now: Instant,
    ) {
        self.record_delivery_flows_at(source, principal, (sensitive, 0), text, now);
    }

    /// [`Self::record_delivery_at`] for a source that matched the
    /// `allowed_flows` entries in `flows` (bit per entry), given with the
    /// delivery's sensitivity.
    pub(crate) fn record_delivery_flows_at(
        &self,
        source: &str,
        principal: &str,
        (sensitive, flows): (bool, u64),
        text: &str,
        now: Instant,
    ) {
        if self.params.action == RelayAction::Off {
            return;
        }
        self.record_fingerprints_at(
            source,
            principal,
            (sensitive, flows),
            self.fingerprints(text),
            now,
        );
    }

    /// [`Self::record_delivery_flows_at`] for fingerprints already taken, in
    /// the order they are kept when over [`MAX_SOURCE_FINGERPRINTS`].
    pub(crate) fn record_fingerprints_at(
        &self,
        source: &str,
        principal: &str,
        (sensitive, flows): (bool, u64),
        fps: Vec<u64>,
        now: Instant,
    ) {
        self.record_held_at(
            source,
            principal,
            (sensitive, Flows::Any(flows)),
            (fps, None),
            now,
        );
    }

    /// [`Self::record_fingerprints_at`] for a delivery whose receipt was cut:
    /// `cut` is every fingerprint the caller received, sketched as excuse
    /// only (`MIK-8066.EXCUSE.1`) and live in the same step as the receipt
    /// (`MIK-8200`).
    pub(crate) fn record_cut_fingerprints_at(
        &self,
        source: &str,
        principal: &str,
        (sensitive, flows): (bool, u64),
        (fps, cut): (Vec<u64>, Option<std::sync::Arc<[u64]>>),
        now: Instant,
    ) {
        self.record_held_at(
            source,
            principal,
            (sensitive, Flows::Any(flows)),
            (fps, cut),
            now,
        );
    }

    /// [`Self::record_fingerprints_at`] for a seam between plan steps under
    /// its composite `source` (`MIK-8113`): `masks` holds one `allowed_flows`
    /// mask per contributing source, and an egress must match every one.
    pub(crate) fn record_seam_at(
        &self,
        source: &str,
        principal: &str,
        (sensitive, mut masks): (bool, Vec<u64>),
        fps: Vec<u64>,
        now: Instant,
    ) {
        // Distinct masks, shared by every fingerprint's holder: as allowing
        // as the full list, and never one copy per fingerprint.
        masks.sort_unstable();
        masks.dedup();
        let flows = Flows::Each(masks.into());
        self.record_held_at(source, principal, (sensitive, flows), (fps, None), now);
    }

    fn record_held_at(
        &self,
        source: &str,
        principal: &str,
        (sensitive, flows): (bool, Flows),
        (mut fps, cut): (Vec<u64>, Option<std::sync::Arc<[u64]>>),
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
        sketched.sort_unstable();
        sketched.dedup();
        let pair = (self.digest(source), self.digest(principal));
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
        }
        let built = pending
            .reservation
            .as_ref()
            .map(|r| std::sync::Arc::new(sketch::Sketch::build(&sketched, r.shape)));
        let holder = |at| Holder {
            source: self.digest(source),
            principal: self.digest(principal),
            copies: Copies::one(at),
            sensitive: sensitive.then(|| Copies::one(at)),
            flows: flows.clone(),
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
        let me = self.digest(principal);
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

    /// `new` added to `holders`; `room` is how many pool records this
    /// fingerprint may hold in all (`MIK-8123`).
    /// Also the source whose excuse of the caller was dropped for room, if
    /// any (`MIK-8201`); an overflowed copy is read per fingerprint instead.
    fn add(
        &self,
        holders: Holders,
        new: Holder,
        now: Instant,
        room: usize,
    ) -> (Holders, Option<u64>) {
        let Holders::Tracked(mut tracked) = holders else {
            return (holders, None);
        };
        let window = self.params.window;
        tracked.expire(now, window);
        let new_source = new.source;
        let (bound, lost) = match tracked.add(new, now, window, room) {
            holders::Added::Kept => (None, None),
            holders::Added::PlainDropped => (Some("record_dropped"), Some(new_source)),
            holders::Added::PlainReplaced { source } => (Some("record_replaced"), Some(source)),
            holders::Added::Overflowed => (Some("record_overflow"), None),
        };
        if let Some(bound) = bound {
            self.capped.fetch_add(1, Ordering::Relaxed);
            telemetry_metrics::counter!(CAPACITY_METRIC, "bound" => bound).increment(1);
        }
        let holders = if tracked.callers() >= self.params.common_principals {
            Holders::Common
        } else {
            Holders::Tracked(tracked)
        };
        (holders, lost)
    }

    /// The relay predicate for `principal` sending `args` through `tool`.
    ///
    /// A fingerprint counts when, inside the window, some other principal got
    /// it as sensitive from a source T that `principal` never got it from,
    /// and it is not `Common`; or some other caller's sensitive record past
    /// its cap is held (`MIK-8123`).
    pub(crate) fn check_egress_at(
        &self,
        principal: &str,
        tool: &str,
        args: &str,
        now: Instant,
    ) -> Option<RelayFinding> {
        self.check_egress_flows_at(principal, (tool, 0), args, now)
    }

    /// [`Self::check_egress_at`] for an egress that matched the
    /// `allowed_flows` entries in `flows` (bit per entry): a copy whose source
    /// matched the same entry is an allowed flow, not a relay.
    pub(crate) fn check_egress_flows_at(
        &self,
        principal: &str,
        (tool, egress_flows): (&str, u64),
        args: &str,
        now: Instant,
    ) -> Option<RelayFinding> {
        if self.params.action == RelayAction::Off {
            return None;
        }
        let sender = self.digest(principal);
        let fps = self.fingerprints(args);
        let window = self.params.window;
        // Held at `now`: some copy delivered by then, inside the window.
        let live = |t: &&Holder| t.copies.held(now, window);
        let mut state = self.state.lock();
        state.sweep(now, window);
        let mut matches = 0;
        let (mut plain, mut overflow, mut lost, mut elsewhere) = (None, None, None, None);
        for fp in fps {
            let Some(Entry {
                holders: Holders::Tracked(tracked),
                ..
            }) = state.entries.get(&fp)
            else {
                continue;
            };
            let tuples = &tracked.records;
            // The sender's own copy from that source: a held tuple, or a
            // cut delivery's sketch (`MIK-8066.EXCUSE.1`).
            let excused = |source| {
                tuples
                    .iter()
                    .filter(live)
                    .any(|t| t.source == source && t.principal == sender)
                    || state.sketches.holds((source, sender), fp, now, window)
            };
            let sensitive =
                |t: &&Holder| t.sensitive.is_some_and(|copies| copies.held(now, window));
            if let Some(t) = tuples.iter().filter(sensitive).find(|t| {
                t.principal != sender && !excused(t.source) && !t.flows.allows(egress_flows)
            }) {
                matches += 1;
                // `MIK-8201`: which reason this match supports. Capacity
                // first, then another source; labels only, never excuses.
                let witness = (t.source, t.principal);
                if tracked.overflowed(sender, now, window)
                    || state.markers.holds((t.source, sender), now)
                {
                    lost.get_or_insert(witness);
                } else if tuples
                    .iter()
                    .filter(live)
                    .any(|h| h.principal == sender && h.source != t.source)
                    || state
                        .sketches
                        .held_from_elsewhere((t.source, sender), fp, now, window)
                {
                    elsewhere.get_or_insert(witness);
                } else {
                    plain.get_or_insert(witness);
                }
            } else if let Some(receiver) = tracked.overflow_witness(sender, now, window) {
                // `MIK-8123`: a sensitive record past the cap has no source
                // left to excuse it or flow to allow it.
                matches += 1;
                overflow.get_or_insert((OVERFLOW_SOURCE, receiver));
            }
        }
        // Plain detection wins; a stated bound is named only without one.
        let (reason, (source, receiver)) = [
            (RelayReason::Relay, plain),
            (RelayReason::OverflowWitness, overflow),
            (RelayReason::ExcuseLost, lost),
            (RelayReason::OtherSource, elsewhere),
        ]
        .into_iter()
        .find_map(|(reason, witness)| witness.map(|w| (reason, w)))?;
        (matches >= self.params.min_matches).then(|| RelayFinding {
            source,
            receiver,
            sender,
            tool: self.digest(tool),
            matches,
            reason,
        })
    }

    #[cfg(test)]
    fn is_tracked(&self, fp: u64) -> bool {
        self.state.lock().entries.contains_key(&fp)
    }

    pub(crate) fn tracked_fingerprints(&self) -> usize {
        self.state.lock().entries.len()
    }

    pub(crate) fn evicted(&self) -> u64 {
        self.evicted.load(Ordering::Relaxed)
    }

    pub(crate) fn capped(&self) -> u64 {
        self.capped.load(Ordering::Relaxed)
    }

    pub(crate) fn source_truncated(&self) -> u64 {
        self.source_truncated.load(Ordering::Relaxed)
    }
}

#[path = "collusion_copies.rs"]
mod copies;
use copies::Copies;
#[path = "collusion_holders.rs"]
mod holders;
#[path = "collusion_reason.rs"]
mod reason;
#[cfg(test)]
#[path = "collusion_reason_tests.rs"]
mod reason_tests;
use reason::CAPACITY_METRIC;
pub(crate) use reason::RelayReason;
#[path = "collusion_seam.rs"]
mod seam;
#[cfg(test)]
#[path = "collusion_seam_tests.rs"]
mod seam_tests;
#[path = "collusion_sketch.rs"]
pub(super) mod sketch;
pub(crate) use seam::SeamFingerprint;

#[cfg(test)]
#[path = "collusion_holders_tests.rs"]
mod holders_tests;
#[cfg(test)]
#[path = "collusion_tests.rs"]
mod tests;
