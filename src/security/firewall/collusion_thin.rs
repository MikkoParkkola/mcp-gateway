// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066.CAP.2`: a thinned sample of a cut delivery's middle, recorded
//! as evidence. A receipt keeps only the head and tail of a long delivery;
//! the rest of what the caller received (`cut`) is sketched as excuse only.
//! Without evidence from the middle, a relay of it is never caught. The
//! sample is recorded under the caller's own records, so it also excuses
//! the caller's own copy, with or without a sketch.
//!
//! Which fingerprints survive depends only on the fingerprint (a keyed
//! hash) and the rate, never on where the text sat, so two deliveries of
//! the same text at the same rate keep the same sample.

use std::collections::HashSet;

use super::CollusionDetector;

/// The splitmix64 finalizer: spreads a fingerprint's bits so the thinning
/// is independent of the `SAMPLE` test on its low bits. A bijection, so only
/// 0 maps to 0.
pub(super) fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Whether `fp` survives thinning at one in `m` (a power of two).
pub(super) fn keep_thinned(fp: u64, m: u64) -> bool {
    mix(fp) % m == 0
}

/// The middle of a cut delivery thinned to fit `room`: `cut` minus `kept`,
/// at the smallest power-of-two rate `m` whose survivors fit. Returns `m`
/// and the survivors, sorted. Empty when `room` is 0.
///
/// One pass: `keep_thinned(fp, 2^k)` holds exactly when `mix(fp)` has at
/// least k trailing zeros, so a histogram of trailing zeros gives every
/// rate's survivor count at once. Only 0 has 64 (mix is a bijection), so
/// for `room >= 1` the search ends by k = 64; `m` saturates at 2^63 there.
pub(super) fn thinned_middle(cut: &[u64], kept: &[u64], room: usize) -> (u64, Vec<u64>) {
    if room == 0 {
        return (1, Vec::new());
    }
    let kept: HashSet<u64> = kept.iter().copied().collect();
    let mut middle: Vec<u64> = cut
        .iter()
        .copied()
        .filter(|fp| !kept.contains(fp))
        .collect();
    middle.sort_unstable();
    middle.dedup();
    let mut at_least = [0usize; 66];
    for fp in &middle {
        at_least[mix(*fp).trailing_zeros() as usize] += 1;
    }
    // Suffix sums: at_least[k] = survivors at rate 2^k.
    for k in (0..65).rev() {
        at_least[k] += at_least[k + 1];
    }
    let k = (0..=64).find(|&k| at_least[k] <= room).unwrap_or(64);
    let sample = middle
        .into_iter()
        .filter(|fp| mix(*fp).trailing_zeros() as usize >= k)
        .collect();
    (1u64 << k.min(63), sample)
}

#[cfg(test)]
impl CollusionDetector {
    /// Replace the sketch store with one whose byte caps are `cap` and
    /// `pair_cap` (tests only).
    pub(crate) fn install_sketch_caps(&self, cap: usize, pair_cap: usize) {
        self.state.lock().sketches = super::sketch::SketchStore::with_caps(cap, pair_cap);
    }

    /// Set the global sketch cap to the bytes live now, so the next sketch
    /// evicts the oldest (tests only).
    pub(crate) fn cap_sketches_at_live_bytes(&self) {
        self.state.lock().sketches.cap_at_live();
    }

    /// Live sketches of `principal` from `source` (tests only).
    pub(crate) fn live_sketches(&self, source: &str, principal: &str) -> usize {
        let pair = (self.digest(source), self.digest(principal));
        self.state.lock().sketches.positions_of(pair).len()
    }

    /// Deliveries recorded without a sketch for lack of room (tests only).
    pub(crate) fn sketches_refused(&self) -> u64 {
        self.state.lock().sketches.refused
    }
}

#[cfg(test)]
#[path = "collusion_thin_tests.rs"]
mod tests;
