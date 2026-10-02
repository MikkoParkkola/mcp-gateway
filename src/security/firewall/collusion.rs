// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Verbatim cross-principal relay detection (OWASP ASI10, partial).
//!
//! Content delivered to principal A that principal B then sends out through a
//! backend call, when B never received it from that source itself. Each side
//! looks ordinary to a per-principal control; only the pair is suspicious.
//!
//! This is the pure core: winnowed fingerprints, bounded in-process state and
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
/// Hashes per winnowing window: a shared run of `K + W - 1` chars yields at
/// least one common fingerprint.
const W: usize = 16;
/// Tuples one fingerprint may hold before it is `Saturated`.
const MAX_TUPLES: usize = 8;
/// The most distinct principals one tracked fingerprint can reach: a 9th
/// tuple saturates it, so a larger `common_principals` is never met.
pub(super) const MAX_COMMON_PRINCIPALS: usize = MAX_TUPLES + 1;
/// Fingerprints kept per delivered result; the rest are counted, not stored.
const MAX_SOURCE_FINGERPRINTS: usize = 1_024;

/// One (source, principal) pair that received a fingerprint.
struct Holder {
    source: u64,
    principal: u64,
    /// Any delivery of this pair: what the same-source excuse ages on.
    last_seen: Instant,
    /// The earliest delivery. Calls reach the lock out of time order, so a
    /// copy stamped after an egress can already be here when that egress is
    /// checked; only a pair held by the egress instant may excuse it.
    first_seen: Instant,
    /// The latest *sensitive* delivery: what a relay witness ages on. Kept
    /// apart so a plain re-delivery cannot extend sensitive evidence.
    sensitive_at: Option<Instant>,
    /// The earliest sensitive delivery: a witness must predate the egress.
    sensitive_first: Option<Instant>,
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

/// Winnowing: the rightmost minimum of every `W`-hash window, distinct, in
/// position order. Fewer than `W` hashes form one short window.
fn winnow(hashes: &[u64]) -> Vec<u64> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut last = None;
    for start in 0..=hashes.len().saturating_sub(W) {
        let end = (start + W).min(hashes.len());
        // Rightmost minimum: `min_by_key` keeps the first of equals, so scan
        // the window backwards.
        let pos = (start..end)
            .rev()
            .min_by_key(|&i| hashes[i])
            .unwrap_or(start);
        if end > start && last != Some(pos) {
            last = Some(pos);
            if seen.insert(hashes[pos]) {
                out.push(hashes[pos]);
            }
        }
    }
    out
}

/// Relay detector state for one gateway process.
pub(crate) struct CollusionDetector {
    params: RelayParams,
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

    /// Winnowed fingerprints of `text`, distinct, in position order.
    ///
    /// Characters input sanitization strips are dropped first, so text
    /// interleaved with them matches what a backend receives; then
    /// NFC-normalized and whitespace-collapsed; then every `K`-char
    /// k-gram is hashed and the rightmost minimum of each `W`-hash window is
    /// kept. Offset-independent: a shifted copy selects the same minima.
    ///
    /// Scratch memory is linear in `text`; callers bound it with the request
    /// and response size limits, not this function.
    #[expect(
        clippy::unused_self,
        reason = "the key is per process; a method keeps callers from hashing with any other"
    )]
    pub(crate) fn fingerprints(&self, text: &str) -> Vec<u64> {
        let visible: String = text
            .chars()
            .filter(|&c| !crate::security::sanitize::is_unsafe_control(c))
            .collect();
        let nfc = ComposingNormalizerBorrowed::new_nfc().normalize(&visible);
        let norm = nfc.split_whitespace().collect::<Vec<_>>().join(" ");
        let bounds: Vec<usize> = norm
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(norm.len()))
            .collect();
        let chars = bounds.len() - 1;
        if chars < K {
            return Vec::new();
        }
        let hashes: Vec<u64> = (0..=chars - K)
            .map(|i| key().hash_one(&norm[bounds[i]..bounds[i + K]]))
            .collect();
        winnow(&hashes)
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
        if self.params.action == RelayAction::Off {
            return;
        }
        let mut fps = self.fingerprints(text);
        if fps.len() > MAX_SOURCE_FINGERPRINTS {
            self.source_truncated.fetch_add(
                count(fps.len() - MAX_SOURCE_FINGERPRINTS),
                Ordering::Relaxed,
            );
            fps.truncate(MAX_SOURCE_FINGERPRINTS);
        }
        let holder = |last_seen| Holder {
            source: self.digest(source),
            principal: self.digest(principal),
            last_seen,
            first_seen: last_seen,
            sensitive_at: sensitive.then_some(last_seen),
            sensitive_first: sensitive.then_some(last_seen),
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
        tuples.retain(|t| now.saturating_duration_since(t.last_seen) <= self.params.window);
        match tuples
            .iter_mut()
            .find(|t| t.source == new.source && t.principal == new.principal)
        {
            Some(t) => {
                // Keep the earliest and latest of each time, whatever order calls arrive in.
                t.last_seen = t.last_seen.max(new.last_seen);
                t.first_seen = t.first_seen.min(new.first_seen);
                t.sensitive_at = t.sensitive_at.max(new.sensitive_at);
                t.sensitive_first = t
                    .sensitive_first
                    .into_iter()
                    .chain(new.sensitive_first)
                    .min();
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
        if self.params.action == RelayAction::Off {
            return None;
        }
        let sender = self.digest(principal);
        let fps = self.fingerprints(args);
        let window = self.params.window;
        // Held at `now`: first delivered by then, last delivered in the window.
        // Known limit: a pair with one copy before the window and one after
        // `now` still counts; exact per-copy times would need a list per pair.
        let live = |t: &&Holder| {
            t.first_seen <= now && now.saturating_duration_since(t.last_seen) <= window
        };
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
            let sensitive = |t: &&Holder| {
                t.sensitive_first.is_some_and(|first| first <= now)
                    && t.sensitive_at
                        .is_some_and(|at| now.saturating_duration_since(at) <= window)
            };
            if let Some(t) = tuples
                .iter()
                .filter(sensitive)
                .find(|t| t.principal != sender && !excused(t.source))
            {
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

#[cfg(test)]
#[path = "collusion_tests.rs"]
mod tests;
