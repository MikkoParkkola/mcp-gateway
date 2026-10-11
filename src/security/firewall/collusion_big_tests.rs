// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066.BIG.3` unit rows: the reservation headroom, the reserved
//! shape, and the staging-time thinning. Deterministic: closed-form sums or
//! seeded draws, never the detector's per-process key.

use super::super::sketch::shape;
use super::super::thin::{keep_thinned, mix};
use super::{PLAN_ANSWER_FPS, STEP_EV_BUDGET, headroom, reservation_shape, stage_thinned};

/// The sizing target of the first sketch (`collusion_sketch.rs` `P0`).
const P0: f64 = 0.0035;

/// The bound on a reserved filter's per-candidate false-positive rate at
/// logical position `i`: twice its sizing target (P0/2)·2^-i.
fn p_bound(i: usize) -> f64 {
    let i = i32::try_from(i).expect("small position");
    2.0 * (P0 / 2.0) * 2f64.powi(-i)
}

/// P(X > h) for X ~ Binomial(n, p), summed exactly in log space: the
/// first term from ln C(n, h + 1), then the ratio of successive terms.
fn binomial_tail_above(n: usize, p: f64, h: usize) -> f64 {
    let k0 = h + 1;
    let mut ln_c = 0.0;
    for j in 0..k0 {
        #[expect(clippy::cast_precision_loss, reason = "counts far below 2^52")]
        let (a, b) = ((n - j) as f64, (j + 1) as f64);
        ln_c += a.ln() - b.ln();
    }
    #[expect(clippy::cast_precision_loss, reason = "counts far below 2^52")]
    let mut ln_term = ln_c + k0 as f64 * p.ln() + (n - k0) as f64 * (-p).ln_1p();
    let mut total = 0.0;
    for k in k0..n {
        let term = ln_term.exp();
        total += term;
        if term < total * 1e-18 && k > k0 + 64 {
            break;
        }
        #[expect(clippy::cast_precision_loss, reason = "counts far below 2^52")]
        let ratio = ((n - k) as f64 / (k + 1) as f64) * (p / (1.0 - p));
        ln_term += ratio.ln();
    }
    total
}

/// `MIK-8066` (r5.1, H rule v4): at every logical position the headroom
/// keeps the chance that false positives from the largest admitted answer
/// view overflow the reservation at or under 1e-12, at the conservative
/// rate bound. The closed form is a Bernstein bound; this checks it against
/// the exact binomial tail. H_0 = 4,130 (design handoff, checked twice).
#[test]
fn headroom_keeps_the_abandon_tail_below_budget() {
    assert_eq!(headroom(0), 4_130, "the headroom at position 0");
    for i in 0..=64 {
        let tail = binomial_tail_above(PLAN_ANSWER_FPS, p_bound(i), headroom(i));
        assert!(tail <= 1e-12, "position {i}: overflow tail {tail:e}");
    }
}

/// `MIK-8066` (r5.1 H rule v4): a step reserves room for its own
/// fingerprints plus the headroom, at the target (P0/2)·2^-i.
#[test]
fn reserved_shape_includes_the_headroom() {
    for n in [1, 64, 4_096, 16_384, 262_144] {
        for i in 0..=7 {
            assert_eq!(
                reservation_shape(n, i),
                shape(n + headroom(i), i + 1),
                "n = {n}, position {i}"
            );
        }
    }
}

/// `MIK-8066` (r5.1 H rule v4, premise (a)): every admitted reserved shape
/// meets its sizing target at full load (the ideal-hash rate). Shapes past
/// the 8 MiB per-pair cap are never admitted, so they are skipped.
#[test]
fn every_admitted_shape_meets_its_target_rate() {
    const PAIR_CAP: usize = 8 * 1024 * 1024;
    let mut checked = 0;
    for n in (0..=20).map(|e| 1usize << e) {
        for i in 0..=64 {
            let s = reservation_shape(n, i);
            if s.bytes() > PAIR_CAP {
                continue;
            }
            #[expect(clippy::cast_precision_loss, reason = "sizes far below 2^52")]
            let (load, bits) = ((n + headroom(i)) as f64, (s.words * 64) as f64);
            let k = f64::from(s.probes);
            let rate = (1.0 - (-k * load / bits).exp()).powf(k);
            let target = p_bound(i) / 2.0;
            assert!(
                rate <= target * (1.0 + 1e-9),
                "n = {n}, position {i}: {rate:e} > {target:e}"
            );
            checked += 1;
        }
    }
    assert!(
        checked > 1_000,
        "premise: the grid covers the admitted shapes ({checked})"
    );
}

/// `MIK-8066` T17 (F4): a big step's evidence is thinned at staging and
/// again at record time with the same predicate, so its miss rate follows
/// the larger rate. A step with about 15 × `STEP_EV_BUDGET` candidates stages
/// at m = 16 (about 30,720 survive against the 32,768 budget; m = 8 would keep
/// twice that); the record-time selector then keeps every staged candidate the
/// answer holds (m = 1). Over N = 20,000 seeded 200-char relays (n = 153),
/// the miss count is inside the exact binomial band for q = 1/(4·16):
/// P = 0.308093, 5,853..=6,474 (each tail ≤ 1e-6). At q = 1/4 it would be
/// about 920.
#[test]
fn a_big_steps_miss_rate_uses_the_larger_thinning() {
    let mut s = 0x8066_B163_0000_0001u64;
    let mut next = || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        mix(s.wrapping_add(0x9E37_79B9_7F4A_7C15))
    };
    let step: Vec<u64> = (0..15 * STEP_EV_BUDGET * 4)
        .map(|_| next())
        .filter(|h| h.is_multiple_of(4))
        .collect();
    let (m_stage, _) = stage_thinned(&step, STEP_EV_BUDGET);
    assert_eq!(m_stage, 16, "the staging rate for 15 × the budget");
    let mut missed = 0usize;
    for _ in 0..20_000 {
        let kept = (0..153)
            .map(|_| next())
            .filter(|h| h.is_multiple_of(4) && keep_thinned(*h, m_stage))
            .count();
        missed += usize::from(kept < 2);
    }
    assert!(
        (5_853..=6_474).contains(&missed),
        "{missed} of 20,000 missed, outside q = 1/64"
    );
}
