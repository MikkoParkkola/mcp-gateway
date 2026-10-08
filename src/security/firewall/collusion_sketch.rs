// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066.EXCUSE.1`: a sketch of the fingerprints one cut delivery
//! carried.
//!
//! A receipt keeps only the head and tail of a long delivery (and at most
//! a fixed number of fingerprints), so its holder's own copy of the cut
//! text is unrecorded, and relaying it would be refused as if it were
//! someone else's. The sketch is a Bloom filter over every fingerprint of
//! the text the caller actually received from that source; it is used only
//! to excuse that caller, never as evidence. It indexes only keyed
//! fingerprints (`SipHash` under the per-process key), so a sender cannot
//! choose text whose bits collide.

use std::sync::Arc;
use std::time::{Duration, Instant};

/// Bits per fingerprint: about a 0.25% false-positive rate with
/// [`PROBES`] probes, so a caller's at most [`MAX_SKETCHES`] live
/// sketches for one source excuse a stray fingerprint under 1% of the time.
const BITS_PER_FINGERPRINT: usize = 15;
/// Bit positions probed per fingerprint.
const PROBES: u32 = 10;

/// An immutable Bloom filter over one delivery's fingerprints.
pub(crate) struct Sketch {
    bits: Box<[u64]>,
}

impl Sketch {
    /// The sketch of `fps`.
    pub(crate) fn of(fps: &[u64]) -> Self {
        let words = (fps.len() * BITS_PER_FINGERPRINT).div_ceil(64).max(1);
        let mut bits = vec![0_u64; words].into_boxed_slice();
        let len = bits.len() * 64;
        for &fp in fps {
            for bit in positions(fp, len) {
                bits[bit / 64] |= 1 << (bit % 64);
            }
        }
        Self { bits }
    }

    /// Whether `fp` may be one of the sketched fingerprints: never false
    /// for one that is.
    pub(super) fn holds(&self, fp: u64) -> bool {
        let len = self.bits.len() * 64;
        positions(fp, len).all(|bit| self.bits[bit / 64] & (1 << (bit % 64)) != 0)
    }

    /// Bytes it holds.
    pub(super) fn bytes(&self) -> usize {
        self.bits.len() * 8
    }
}

/// The probe positions of `fp` in `len` bits: double hashing of the keyed
/// 64-bit fingerprint (the second hash odd, so the probes cycle the table).
fn positions(fp: u64, len: usize) -> impl Iterator<Item = usize> {
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    let step = fp.rotate_left(32) | 1;
    (0..u64::from(PROBES)).map(move |i| {
        let at = fp.wrapping_add(i.wrapping_mul(step)) % len;
        usize::try_from(at).unwrap_or(0)
    })
}

/// Live sketches kept per (source, caller): a caller's next cut delivery
/// from that source evicts its oldest, which then refuses as before the
/// sketch existed, never excuses anything new.
pub(super) const MAX_SKETCHES: usize = 4;
/// Bytes of sketches kept across every pair; past it the oldest goes.
pub(super) const SKETCH_BYTES: usize = 32 * 1024 * 1024;

/// (source, caller) digests.
type Pair = (u64, u64);

/// The live sketches, by pair, with an oldest-first index for expiry and
/// the byte cap.
#[derive(Default)]
pub(super) struct SketchStore {
    by_pair: std::collections::HashMap<Pair, Vec<(u64, Instant, Arc<Sketch>)>>,
    order: std::collections::BTreeMap<(Instant, u64), Pair>,
    next: u64,
    bytes: usize,
    /// Sketches dropped by the per-pair or byte cap (not by expiry).
    pub(super) evicted: u64,
}

impl SketchStore {
    /// Keep `sketch` for `pair`, delivered at `at`.
    pub(super) fn insert(&mut self, pair: Pair, sketch: Arc<Sketch>, at: Instant) {
        let seq = self.next;
        self.next += 1;
        self.bytes += sketch.bytes();
        self.order.insert((at, seq), pair);
        let list = self.by_pair.entry(pair).or_default();
        list.push((seq, at, sketch));
        if list.len() > MAX_SKETCHES {
            let (old, old_at, gone) = list.remove(0);
            self.order.remove(&(old_at, old));
            self.bytes -= gone.bytes();
            self.evicted += 1;
        }
        while self.bytes > SKETCH_BYTES {
            if self.pop_oldest().is_none() {
                break;
            }
            self.evicted += 1;
        }
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

    fn pop_oldest(&mut self) -> Option<()> {
        let ((_, seq), pair) = self.order.pop_first()?;
        if let Some(list) = self.by_pair.get_mut(&pair) {
            if let Some(i) = list.iter().position(|(s, _, _)| *s == seq) {
                let (_, _, gone) = list.remove(i);
                self.bytes -= gone.bytes();
            }
            if list.is_empty() {
                self.by_pair.remove(&pair);
            }
        }
        Some(())
    }

    /// Whether a live sketch of `pair` at `now` holds `fp`.
    pub(super) fn holds(&self, pair: Pair, fp: u64, now: Instant, window: Duration) -> bool {
        self.by_pair.get(&pair).is_some_and(|list| {
            list.iter().any(|(_, at, sketch)| {
                *at <= now && now.saturating_duration_since(*at) <= window && sketch.holds(fp)
            })
        })
    }
}

#[cfg(test)]
#[path = "collusion_sketch_tests.rs"]
mod tests;
