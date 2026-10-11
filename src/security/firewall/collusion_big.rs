// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066.BIG.3`: bounded fingerprint state for plan steps and answers
//! past the 1 MiB plan bound (design r5.1). This file holds the pure parts:
//! the reservation headroom and the staging-time thinning.

/// The most sampled fingerprints a plan answer's bounded view stores
/// (4 × 1 MiB of text, one k-gram in four): an answer past it is dropped
/// whole, never partly kept, so it caps what one retention can select.
pub(super) const PLAN_ANSWER_FPS: usize = 1 << 20;

/// Fingerprints kept per over-bound step at staging (`step_ev`), before
/// the per-delivery bound thins them again at record time.
pub(super) const STEP_EV_BUDGET: usize = 32_768;

/// The extra sketch room a step reserves at logical position `position`
/// for false positives its Bloom filter selects from the answer view, so a
/// step delivered whole beside foreign text never overflows its sketch.
pub(super) fn headroom(_position: usize) -> usize {
    0
}

/// `fps` thinned to at most `budget` with CAP.2's selector: the rate `m`
/// and the survivors. A step's staged evidence candidates.
pub(super) fn stage_thinned(fps: &[u64], _budget: usize) -> (u64, Vec<u64>) {
    let mut kept = fps.to_vec();
    kept.sort_unstable();
    kept.dedup();
    (1, kept)
}

/// The sketch shape a step reserves for `n` fingerprints at logical
/// position `position`: room for its own fingerprints plus the headroom,
/// at the target (P0/2)·2^-position (`shape`'s position + 1).
pub(super) fn reservation_shape(n: usize, position: usize) -> super::sketch::Shape {
    super::sketch::shape(n + headroom(position), position + 1)
}

#[cfg(test)]
impl super::CollusionDetector {
    /// The live and pending sketch positions of `principal` from `source`.
    pub(crate) fn sketch_positions(&self, source: &str, principal: &str) -> Vec<usize> {
        let pair = (self.digest(source), self.digest(principal));
        self.state.lock().sketches.positions_of(pair)
    }

    /// Bytes of every live and pending sketch.
    pub(crate) fn sketch_bytes_held(&self) -> usize {
        self.state.lock().sketches.bytes_held()
    }

    /// Whether `principal`'s excuse from `source` is marked lost for room.
    pub(crate) fn excuse_lost(&self, source: &str, principal: &str) -> bool {
        let pair = (self.digest(source), self.digest(principal));
        self.state
            .lock()
            .markers
            .holds(pair, std::time::Instant::now())
    }

    /// Sketches abandoned because their selection passed n + H.
    pub(crate) fn overfull_sketches(&self) -> u64 {
        0
    }

    /// The last retention's (distinct selected, reserved n) for a pair.
    pub(crate) fn last_selection(&self, _source: &str, _principal: &str) -> Option<(usize, usize)> {
        None
    }

    /// Reserve no headroom on this detector (the abandon path, made
    /// reachable).
    pub(crate) fn zero_headroom(&self) {}
}

#[cfg(test)]
#[path = "collusion_big_tests.rs"]
mod tests;
