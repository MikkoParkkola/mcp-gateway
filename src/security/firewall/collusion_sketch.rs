// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066.EXCUSE.1`, `MIK-8200`: sketches of what cut deliveries carried.
//!
//! A receipt keeps only the head and tail of a long delivery (and at most
//! a fixed number of fingerprints), so its holder's own copy of the cut
//! text is unrecorded, and relaying it would be refused as if it were
//! someone else's. A sketch is a Bloom filter over every fingerprint of the
//! text the caller received from that source; it only ever excuses that
//! caller, never counts as evidence. It indexes only keyed fingerprints
//! (`SipHash` under the per-process key), so a sender cannot choose text
//! whose bits collide.
//!
//! A pair keeps a sketch for as long as its delivery is in the window, with
//! no count cap (`MIK-8200`). The pair's i-th live sketch is sized for
//! `P0 · 2^-i`, so however many live at once, a stray fingerprint is
//! excused at most `2 · P0` of the time (design §14.3 B3; measured bound
//! 0.8%). Memory is bounded by bytes, globally and per pair.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The first sketch's sizing target (0.35%): a target, not a guarantee;
/// the guarantee is the measured aggregate (design §14.3).
const P0: f64 = 0.0035;
/// The smallest filter, in 64-bit words: a few fingerprints in a tiny table
/// would collide far above the target.
const MIN_WORDS: usize = 16;
/// Most probes one filter uses.
const MAX_PROBES: u32 = 63;
/// Spreads the probe index across the fingerprint (splitmix64's gamma).
const PROBE_STEP: u64 = 0xD1B5_4A32_D192_ED03;

/// Bytes of sketches across every pair, live and being built; past it the
/// oldest live sketch goes.
pub(super) const SKETCH_BYTES: usize = 32 * 1024 * 1024;
/// The largest filter [`shape`] ever gives, in words: the global byte cap.
/// A shape this large never fits a pair's backstop, so it is refused, not
/// built; the bound also stops the sizing loop whatever its float
/// comparison says (a NaN rate never meets a target).
const MAX_WORDS: usize = SKETCH_BYTES / 8;

/// A filter's size: 64-bit words and probes per fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Shape {
    pub(super) words: usize,
    pub(super) probes: u32,
}

impl Shape {
    pub(super) fn bytes(self) -> usize {
        self.words * 8
    }
}

/// `ln` of the classic ideal-hash false-positive rate of `probes` probes
/// over `n` fingerprints in `bits` bits, computed in log space.
fn ln_rate(n: usize, bits: usize, probes: u32) -> f64 {
    #[expect(clippy::cast_precision_loss, reason = "sizes stay far below 2^52")]
    let (n, bits) = (n as f64, bits as f64);
    let k = f64::from(probes);
    k * (-(k * n * (-1.0 / bits).ln_1p()).exp()).ln_1p()
}

/// The shape of the sketch at `position` holding `n` fingerprints: the
/// smallest whose rate is at most `P0 · 2^-position`.
pub(super) fn shape(n: usize, position: usize) -> Shape {
    sized(n, position).0
}

/// [`shape`] with the number of growth steps it took: a few hundred at
/// most, since it runs under the detector lock.
fn sized(n: usize, position: usize) -> (Shape, usize) {
    #[expect(clippy::cast_precision_loss, reason = "positions are small")]
    let ln_target = P0.ln() - position as f64 * std::f64::consts::LN_2;
    let per_fp = -ln_target / (std::f64::consts::LN_2 * std::f64::consts::LN_2);
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "a positive, bounded word count"
    )]
    let mut words = ((n.max(1) as f64 * per_fp / 64.0).ceil() as usize).clamp(MIN_WORDS, MAX_WORDS);
    // Grows by about 1/64 per step, so at most a few hundred steps up to the
    // cap: this runs under the detector lock (`reserve`).
    for steps in 0.. {
        let bits = words * 64;
        let probes = best_probes(n, bits);
        if n == 0 || words >= MAX_WORDS || ln_rate(n, bits, probes) <= ln_target {
            return (Shape { words, probes }, steps);
        }
        words = (words + words.div_ceil(64)).min(MAX_WORDS);
    }
    unreachable!("the word count reaches MAX_WORDS")
}

/// The probe count with the lowest rate for `n` fingerprints in `bits`
/// bits. The rate is unimodal in the probe count, with its minimum within one
/// of `bits / n · ln 2`, so only that neighbourhood is searched.
fn best_probes(n: usize, bits: usize) -> u32 {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "a small positive probe count"
    )]
    let k0 = ((bits as f64 / n.max(1) as f64) * std::f64::consts::LN_2)
        .round()
        .clamp(1.0, f64::from(MAX_PROBES)) as u32;
    (k0.saturating_sub(2).max(1)..=(k0 + 2).min(MAX_PROBES))
        .min_by(|a, b| ln_rate(n, bits, *a).total_cmp(&ln_rate(n, bits, *b)))
        .unwrap_or(k0)
}

/// splitmix64's finalizer.
fn splitmix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The probe positions of `fp` in `bits` bits, each from its own mix: on
/// small tables double hashing correlates probes and breaks the rate.
fn positions(fp: u64, bits: usize, probes: u32) -> impl Iterator<Item = usize> {
    let len = u64::try_from(bits).unwrap_or(u64::MAX);
    (1..=u64::from(probes)).map(move |j| {
        let at = splitmix(fp ^ j.wrapping_mul(PROBE_STEP)) % len;
        usize::try_from(at).unwrap_or(0)
    })
}

/// An immutable Bloom filter over one delivery's fingerprints.
pub(crate) struct Sketch {
    bits: Box<[u64]>,
    probes: u32,
}

impl Sketch {
    /// The sketch of `fps` in `shape`.
    pub(super) fn build(fps: &[u64], shape: Shape) -> Self {
        let mut bits = vec![0_u64; shape.words].into_boxed_slice();
        let len = bits.len() * 64;
        for &fp in fps {
            for bit in positions(fp, len, shape.probes) {
                bits[bit / 64] |= 1 << (bit % 64);
            }
        }
        Self {
            bits,
            probes: shape.probes,
        }
    }

    /// The sketch of `fps` at position 0 (tests).
    #[cfg(test)]
    pub(super) fn of(fps: &[u64]) -> Self {
        Self::build(fps, shape(fps.len(), 0))
    }

    /// Whether `fp` may be one of the sketched fingerprints: never false
    /// for one that is.
    pub(super) fn holds(&self, fp: u64) -> bool {
        let len = self.bits.len() * 64;
        positions(fp, len, self.probes).all(|bit| self.bits[bit / 64] & (1 << (bit % 64)) != 0)
    }

    /// Bytes it holds.
    pub(super) fn bytes(&self) -> usize {
        self.bits.len() * 8
    }
}

/// (source, caller) digests.
type Pair = (u64, u64);

/// A live sketch.
struct Live {
    seq: u64,
    at: Instant,
    position: usize,
    sketch: Arc<Sketch>,
}

/// One pair's live sketches and pending positions.
#[derive(Default)]
struct PairState {
    live: Vec<Live>,
    pending: Vec<usize>,
    bytes: usize,
}

impl PairState {
    /// The lowest position no live or pending sketch holds: one at most
    /// their count always is.
    fn lowest_free(&self) -> usize {
        let held = self.live.len() + self.pending.len();
        (0..=held)
            .find(|p| !self.pending.contains(p) && !self.live.iter().any(|l| l.position == *p))
            .unwrap_or(held)
    }
}

/// A position held for a sketch being built, with its shape and bytes.
/// Pending positions are never evicted (design T4).
#[derive(Debug)]
pub(super) struct Reservation {
    pair: Pair,
    position: usize,
    pub(super) shape: Shape,
}

/// The live sketches by pair, with an oldest-first index for expiry and the
/// byte caps.
pub(super) struct SketchStore {
    by_pair: HashMap<Pair, PairState>,
    /// The sources each caller holds a pair with: what `held_from_elsewhere`
    /// reads, so a label never scans every pair (`MIK-8206`).
    by_caller: HashMap<u64, HashSet<u64>>,
    order: BTreeMap<(Instant, u64), Pair>,
    next: u64,
    /// Live and pending bytes across every pair.
    bytes: usize,
    /// [`SKETCH_BYTES`]; smaller only in tests.
    cap: usize,
    /// One pair's byte backstop: a quarter of [`SKETCH_BYTES`], so one busy
    /// pair cannot spend the whole cap; other values only in tests.
    pair_cap: usize,
    /// Deliveries whose sketch did not fit and were recorded without one.
    pub(super) refused: u64,
    /// Pairs whose sketch a cap refused or evicted since the last
    /// [`Self::take_lost`]: their excuse was dropped for room (`MIK-8201`).
    lost: Vec<Pair>,
}

impl Default for SketchStore {
    fn default() -> Self {
        Self {
            by_pair: HashMap::new(),
            by_caller: HashMap::new(),
            order: BTreeMap::new(),
            next: 0,
            bytes: 0,
            cap: SKETCH_BYTES,
            pair_cap: SKETCH_BYTES / 4,
            refused: 0,
            lost: Vec::new(),
        }
    }
}

impl SketchStore {
    /// A store whose global and per-pair byte caps are `cap` and
    /// `pair_cap`, so a row can cross either cheaply.
    #[cfg(test)]
    pub(super) fn with_caps(cap: usize, pair_cap: usize) -> Self {
        Self {
            cap,
            pair_cap,
            ..Self::default()
        }
    }

    /// Hold the lowest free position of `pair` for a sketch of `n`
    /// fingerprints, evicting live sketches (the pair's own for its
    /// backstop, any pair's for the global cap, oldest first) until it
    /// fits. `None`, counted, when it cannot fit even then: the delivery is
    /// recorded without a sketch.
    pub(super) fn reserve(&mut self, pair: Pair, n: usize) -> Option<Reservation> {
        let pair_cap = self.pair_cap;
        loop {
            let state = self.pair_state(pair);
            let position = state.lowest_free();
            let shape = shape(n, position);
            let bytes = shape.bytes();
            if state.bytes + bytes > pair_cap {
                if self.pop_oldest_of(pair).is_none() {
                    break;
                }
                self.evicted_for_room(pair);
                continue;
            }
            if self.bytes + bytes > self.cap {
                let Some(gone) = self.pop_oldest() else {
                    break;
                };
                self.evicted_for_room(gone);
                continue;
            }
            self.bytes += bytes;
            let state = self.pair_state(pair);
            state.pending.push(position);
            state.bytes += bytes;
            return Some(Reservation {
                pair,
                position,
                shape,
            });
        }
        self.refused += 1;
        telemetry_metrics::counter!(super::CAPACITY_METRIC, "bound" => "sketch_refused")
            .increment(1);
        self.lost.push(pair);
        self.drop_if_empty(pair);
        None
    }

    /// A live sketch of `pair` evicted by a byte cap (never by expiry).
    fn evicted_for_room(&mut self, pair: Pair) {
        telemetry_metrics::counter!(super::CAPACITY_METRIC, "bound" => "sketch_evicted")
            .increment(1);
        self.lost.push(pair);
    }

    /// The pairs that lost a sketch to a cap since the last call.
    pub(super) fn take_lost(&mut self) -> Vec<Pair> {
        std::mem::take(&mut self.lost)
    }

    /// Make `sketch`, built in `reservation`'s shape, live at `at`.
    pub(super) fn publish(&mut self, reservation: &Reservation, sketch: Arc<Sketch>, at: Instant) {
        let seq = self.next;
        self.next += 1;
        let state = self.pair_state(reservation.pair);
        state.pending.retain(|p| *p != reservation.position);
        state.live.push(Live {
            seq,
            at,
            position: reservation.position,
            sketch,
        });
        self.order.insert((at, seq), reservation.pair);
    }

    /// Release a reservation whose sketch will never be built.
    pub(super) fn abandon(&mut self, reservation: &Reservation) {
        let bytes = reservation.shape.bytes();
        if let Some(state) = self.by_pair.get_mut(&reservation.pair) {
            state.pending.retain(|p| *p != reservation.position);
            state.bytes -= bytes;
        }
        self.bytes -= bytes;
        self.drop_if_empty(reservation.pair);
    }

    /// Reserve, build and publish in one step (tests).
    #[cfg(test)]
    pub(super) fn insert(&mut self, pair: Pair, fps: &[u64], at: Instant) -> bool {
        let Some(reservation) = self.reserve(pair, fps.len()) else {
            return false;
        };
        let sketch = Arc::new(Sketch::build(fps, reservation.shape));
        self.publish(&reservation, sketch, at);
        true
    }

    /// The positions a pair's live sketches sit at (tests).
    #[cfg(test)]
    pub(super) fn positions_of(&self, pair: Pair) -> Vec<usize> {
        self.by_pair
            .get(&pair)
            .map(|s| s.live.iter().map(|l| l.position).collect())
            .unwrap_or_default()
    }

    /// Drop sketches older than `window` at `now`.
    pub(super) fn sweep(&mut self, now: Instant, window: Duration) {
        while let Some((&(at, _), _)) = self.order.first_key_value() {
            if now.saturating_duration_since(at) <= window {
                break;
            }
            self.pop_oldest();
        }
    }

    fn pop_oldest(&mut self) -> Option<Pair> {
        let ((_, seq), pair) = self.order.pop_first()?;
        self.remove_live(pair, seq);
        Some(pair)
    }

    fn pop_oldest_of(&mut self, pair: Pair) -> Option<()> {
        let state = self.by_pair.get(&pair)?;
        let oldest = state.live.iter().min_by_key(|l| (l.at, l.seq))?;
        let key = (oldest.at, oldest.seq);
        self.order.remove(&key);
        self.remove_live(pair, key.1);
        Some(())
    }

    fn remove_live(&mut self, pair: Pair, seq: u64) {
        if let Some(state) = self.by_pair.get_mut(&pair)
            && let Some(i) = state.live.iter().position(|l| l.seq == seq)
        {
            let gone = state.live.swap_remove(i);
            state.bytes -= gone.sketch.bytes();
            self.bytes -= gone.sketch.bytes();
        }
        self.drop_if_empty(pair);
    }

    /// `pair`'s state, created and indexed by caller on first use.
    fn pair_state(&mut self, pair: Pair) -> &mut PairState {
        self.by_caller.entry(pair.1).or_default().insert(pair.0);
        self.by_pair.entry(pair).or_default()
    }

    fn drop_if_empty(&mut self, pair: Pair) {
        if self
            .by_pair
            .get(&pair)
            .is_some_and(|s| s.live.is_empty() && s.pending.is_empty())
        {
            self.by_pair.remove(&pair);
            if let Some(sources) = self.by_caller.get_mut(&pair.1) {
                sources.remove(&pair.0);
                if sources.is_empty() {
                    self.by_caller.remove(&pair.1);
                }
            }
        }
    }

    /// Whether a live sketch `caller` holds from a source other than
    /// `source` may hold `fp`: a label only (`MIK-8206`), never an excuse.
    pub(super) fn held_from_elsewhere(
        &self,
        (source, caller): Pair,
        fp: u64,
        now: Instant,
        window: Duration,
    ) -> bool {
        self.by_caller.get(&caller).is_some_and(|sources| {
            sources
                .iter()
                .filter(|s| **s != source)
                .any(|s| self.holds((*s, caller), fp, now, window))
        })
    }

    /// Whether a live sketch of `pair` at `now` holds `fp`.
    pub(super) fn holds(&self, pair: Pair, fp: u64, now: Instant, window: Duration) -> bool {
        self.by_pair.get(&pair).is_some_and(|state| {
            state.live.iter().any(|l| {
                l.at <= now && now.saturating_duration_since(l.at) <= window && l.sketch.holds(fp)
            })
        })
    }
}

/// Most "excuse lost" markers kept (`MIK-8201`).
const MAX_MARKERS: usize = 65_536;

/// "Excuse lost" markers: (source, caller) pairs some excuse of which
/// capacity dropped, until when. Kept apart from the sketches: never charged
/// to their budget, never evicting one; losing a marker only loses a label.
#[derive(Default)]
pub(super) struct Markers {
    until: HashMap<Pair, (Instant, u64)>,
    order: BTreeMap<(Instant, u64), Pair>,
    next: u64,
}

impl Markers {
    /// Mark `pair` until `until`, keeping the later time.
    pub(super) fn mark(&mut self, pair: Pair, until: Instant) {
        if let Some(&(held, seq)) = self.until.get(&pair) {
            if held >= until {
                return;
            }
            self.order.remove(&(held, seq));
        }
        let seq = self.next;
        self.next += 1;
        self.until.insert(pair, (until, seq));
        self.order.insert((until, seq), pair);
        while self.until.len() > MAX_MARKERS {
            let Some((_, gone)) = self.order.pop_first() else {
                break;
            };
            self.until.remove(&gone);
            telemetry_metrics::counter!(super::CAPACITY_METRIC, "bound" => "marker_evicted")
                .increment(1);
        }
    }

    /// Drop markers that ended before `now`.
    pub(super) fn sweep(&mut self, now: Instant) {
        while let Some((&(until, _), _)) = self.order.first_key_value() {
            if until >= now {
                break;
            }
            if let Some((_, gone)) = self.order.pop_first() {
                self.until.remove(&gone);
            }
        }
    }

    /// Whether `pair` holds a marker at `now`.
    pub(super) fn holds(&self, pair: Pair, now: Instant) -> bool {
        self.until
            .get(&pair)
            .is_some_and(|(until, _)| *until >= now)
    }
}

#[cfg(test)]
#[path = "collusion_sketch_tests.rs"]
mod tests;
