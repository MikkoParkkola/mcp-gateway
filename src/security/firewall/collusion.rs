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
}

/// Characters per k-gram. Nothing shorter than this can ever match.
pub(super) const K: usize = 48;
/// One k-gram in `SAMPLE` is kept, by its own hash: whether a k-gram is kept
/// never depends on the text around it, so two texts sharing a k-gram keep it
/// in both or in neither, and the same-source excuse is exact (MIK-8083).
const SAMPLE: u64 = 4;
/// Tuples one fingerprint may hold before it is `Saturated`.
const MAX_TUPLES: usize = 8;
/// The most distinct principals one tracked fingerprint can reach: a 9th
/// tuple saturates it, so a larger `common_principals` is never met.
pub(super) const MAX_COMMON_PRINCIPALS: usize = MAX_TUPLES + 1;
/// Fingerprints kept per delivered result; the rest are counted, not stored.
/// Twice one form's share: a split delivery records its newline-joined and
/// its run-together forms, which share almost no k-grams, and both are
/// expected to fit for a copy up to the record cap (sampling keeps about 1
/// in [`SAMPLE`] positions; crafted text can exceed it, costing only an
/// excuse).
const MAX_SOURCE_FINGERPRINTS: usize = 4 * 1_024;

/// Delivery instants kept per pair; see [`Copies`].
const MAX_COPIES: usize = 3;

/// When one pair received a fingerprint: up to [`MAX_COPIES`] delivery
/// instants, ascending. Calls reach the lock out of time order, so a copy
/// stamped after an egress can already be here when that egress is checked,
/// and the earliest and latest alone cannot say whether a copy was held in
/// the window at that instant (MIK-7881).
///
/// A copy whose neighbours are at most a window apart is dropped: a window
/// that contains it contains one of them, so no answer changes. Past the cap
/// the oldest is dropped; an egress checked more than about a window before
/// the pair's latest copy can then miss an older one, which turns an excuse
/// into a finding and can drop a witness.
#[derive(Clone, Copy)]
struct Copies {
    at: [Instant; MAX_COPIES],
    len: usize,
}

impl Copies {
    fn one(at: Instant) -> Self {
        Self {
            at: [at; MAX_COPIES],
            len: 1,
        }
    }

    fn all(&self) -> &[Instant] {
        &self.at[..self.len]
    }

    fn latest(&self) -> Instant {
        self.at[self.len - 1]
    }

    fn add(&mut self, other: &Self, window: Duration) {
        for &at in other.all() {
            let mut all = [at; MAX_COPIES + 1];
            all[..self.len].copy_from_slice(self.all());
            let mut n = self.len + 1;
            all[..n].sort_unstable();
            let mut i = 1;
            while i + 1 < n {
                if all[i + 1].saturating_duration_since(all[i - 1]) <= window {
                    all.copy_within(i + 1..n, i);
                    n -= 1;
                    i = (i - 1).max(1);
                } else {
                    i += 1;
                }
            }
            let oldest = n.saturating_sub(MAX_COPIES);
            self.len = n - oldest;
            self.at[..self.len].copy_from_slice(&all[oldest..n]);
        }
    }

    /// A copy delivered by `now` and within `window` of it.
    fn held(&self, now: Instant, window: Duration) -> bool {
        self.all()
            .iter()
            .any(|&at| at <= now && now.saturating_duration_since(at) <= window)
    }
}

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
    Tracked(Vec<Holder>),
    /// A 9th holder arrived. Evicting one could erase a same-source excuse
    /// and turn an excused copy into a finding, so none is evicted and the
    /// fingerprint never counts toward a finding again.
    Saturated,
    /// Held by `common_principals` distinct principals: boilerplate.
    Common,
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
}

impl State {
    fn sweep(&mut self, now: Instant, window: Duration) {
        while let Some((&(seen, seq), &fp)) = self.order.first_key_value() {
            if now.saturating_duration_since(seen) <= window {
                break;
            }
            self.order.remove(&(seen, seq));
            self.entries.remove(&fp);
        }
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
    saturated: AtomicU64,
    source_truncated: AtomicU64,
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
            saturated: AtomicU64::new(0),
            source_truncated: AtomicU64::new(0),
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
        self.record_held_at(source, principal, (sensitive, Flows::Any(flows)), fps, now);
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
        self.record_held_at(source, principal, (sensitive, flows), fps, now);
    }

    fn record_held_at(
        &self,
        source: &str,
        principal: &str,
        (sensitive, flows): (bool, Flows),
        mut fps: Vec<u64>,
        now: Instant,
    ) {
        if self.params.action == RelayAction::Off {
            return;
        }
        if fps.len() > MAX_SOURCE_FINGERPRINTS {
            self.source_truncated.fetch_add(
                count(fps.len() - MAX_SOURCE_FINGERPRINTS),
                Ordering::Relaxed,
            );
            fps.truncate(MAX_SOURCE_FINGERPRINTS);
        }
        let holder = |at| Holder {
            source: self.digest(source),
            principal: self.digest(principal),
            copies: Copies::one(at),
            sensitive: sensitive.then(|| Copies::one(at)),
            flows: flows.clone(),
        };
        let window = self.params.window;
        let mut state = self.state.lock();
        state.sweep(now, window);
        for fp in fps {
            // Calls can reach the lock out of time order; an entry's age only
            // ever moves forward.
            let mut touched = now;
            let holders = if let Some(entry) = state.entries.remove(&fp) {
                state.order.remove(&entry.order);
                touched = touched.max(entry.order.0);
                self.add(entry.holders, holder(now), now)
            } else {
                if state.entries.len() >= self.params.max_fingerprints
                    && let Some((_, oldest)) = state.order.pop_first()
                {
                    state.entries.remove(&oldest);
                    self.evicted.fetch_add(1, Ordering::Relaxed);
                }
                self.add(Holders::Tracked(Vec::new()), holder(now), now)
            };
            let order = state.stamp(touched, fp);
            state.entries.insert(fp, Entry { holders, order });
        }
    }

    fn add(&self, holders: Holders, new: Holder, now: Instant) -> Holders {
        let Holders::Tracked(mut tuples) = holders else {
            return holders;
        };
        let window = self.params.window;
        tuples.retain(|t| now.saturating_duration_since(t.copies.latest()) <= window);
        match tuples
            .iter_mut()
            .find(|t| t.source == new.source && t.principal == new.principal)
        {
            Some(t) => {
                // Kept by their own times, whatever order calls arrive in.
                t.copies.add(&new.copies, window);
                match (&mut t.sensitive, new.sensitive) {
                    (Some(held), Some(more)) => held.add(&more, window),
                    (held, more) => *held = held.or(more),
                }
                t.flows.merge(new.flows);
            }
            None => tuples.push(new),
        }
        let principals: HashSet<u64> = tuples.iter().map(|t| t.principal).collect();
        if principals.len() >= self.params.common_principals {
            Holders::Common
        } else if tuples.len() > MAX_TUPLES {
            self.saturated.fetch_add(1, Ordering::Relaxed);
            Holders::Saturated
        } else {
            Holders::Tracked(tuples)
        }
    }

    /// The relay predicate for `principal` sending `args` through `tool`.
    ///
    /// A fingerprint counts when, inside the window, some other principal got
    /// it as sensitive from a source T that `principal` never got it from,
    /// and it is neither `Common` nor `Saturated`.
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
        let mut first = None;
        for fp in fps {
            let Some(Entry {
                holders: Holders::Tracked(tuples),
                ..
            }) = state.entries.get(&fp)
            else {
                continue;
            };
            let excused = |source| {
                tuples
                    .iter()
                    .filter(live)
                    .any(|t| t.source == source && t.principal == sender)
            };
            let sensitive =
                |t: &&Holder| t.sensitive.is_some_and(|copies| copies.held(now, window));
            if let Some(t) = tuples.iter().filter(sensitive).find(|t| {
                t.principal != sender && !excused(t.source) && !t.flows.allows(egress_flows)
            }) {
                matches += 1;
                first.get_or_insert((t.source, t.principal));
            }
        }
        let (source, receiver) = first?;
        (matches >= self.params.min_matches).then(|| RelayFinding {
            source,
            receiver,
            sender,
            tool: self.digest(tool),
            matches,
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

    pub(crate) fn saturated(&self) -> u64 {
        self.saturated.load(Ordering::Relaxed)
    }

    pub(crate) fn source_truncated(&self) -> u64 {
        self.source_truncated.load(Ordering::Relaxed)
    }
}

#[path = "collusion_seam.rs"]
mod seam;
#[cfg(test)]
#[path = "collusion_seam_tests.rs"]
mod seam_tests;
pub(crate) use seam::SeamFingerprint;

#[cfg(test)]
#[path = "collusion_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "collusion_holders_tests.rs"]
mod holders_tests;
