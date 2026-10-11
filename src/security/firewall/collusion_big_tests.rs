// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066.BIG.3` unit rows: the reservation headroom, the reserved
//! shape, the staging-time thinning, and the evidence split. Deterministic:
//! closed-form sums or seeded draws; the one row that needs filter hits
//! (T8) picks them under the run's own filter and asserts they exist.

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

/// P(X > `cap`) for X ~ Binomial(`trials`, `prob`), summed exactly in log
/// space: the first term from ln C(trials, cap + 1), then the ratio of
/// successive terms.
fn binomial_tail_above(trials: usize, prob: f64, cap: usize) -> f64 {
    let first = cap + 1;
    let mut ln_choose = 0.0;
    for step in 0..first {
        #[expect(clippy::cast_precision_loss, reason = "counts far below 2^52")]
        let (top, bottom) = ((trials - step) as f64, (step + 1) as f64);
        ln_choose += top.ln() - bottom.ln();
    }
    #[expect(clippy::cast_precision_loss, reason = "counts far below 2^52")]
    let mut ln_term =
        ln_choose + first as f64 * prob.ln() + (trials - first) as f64 * (-prob).ln_1p();
    let mut total = 0.0;
    for count in first..trials {
        let term = ln_term.exp();
        total += term;
        if term < total * 1e-18 && count > first + 64 {
            break;
        }
        #[expect(clippy::cast_precision_loss, reason = "counts far below 2^52")]
        let ratio = ((trials - count) as f64 / (count + 1) as f64) * (prob / (1.0 - prob));
        ln_term += ratio.ln();
    }
    total
}

/// `MIK-8066` (r5.1, H rule v4): at every logical position the headroom
/// keeps the chance that false positives from the largest admitted answer
/// view overflow the reservation at or under 1e-12, at the conservative
/// rate bound. The closed form is a Bernstein bound; this checks it against
/// the exact binomial tail. `H_0` = 4,130 (design handoff, checked twice).
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
/// the larger rate. A step of 3.06M k-grams (about 765k sampled) stages,
/// through production's `stage_thinned`, at m = 16 against twice
/// `STEP_EV_BUDGET` (m = 8 would keep about 95k). A delivery whose staged
/// evidence fits the record's room keeps it all (m = 1). Over 20,000
/// disjoint 153-k-gram windows of the step itself, a window is missed when
/// fewer than 2 of its k-grams are in the staged set: inside the exact
/// binomial band for q = 1/(4·16): P = 0.308093, 5,853..=6,474 (each tail
/// ≤ 1e-6). At m = 8 (q = 1/32) it would be about 920.
#[test]
fn a_big_steps_miss_rate_uses_the_larger_thinning() {
    use std::collections::HashSet;

    use super::super::thin::thinned_middle;

    const WINDOWS: usize = 20_000;
    const WINDOW: usize = 153;
    let budget = 2 * STEP_EV_BUDGET;
    let mut s = 0x8066_B163_0000_0001u64;
    let raw: Vec<u64> = (0..WINDOWS * WINDOW)
        .map(|_| {
            s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            mix(s.wrapping_add(0x9E37_79B9_7F4A_7C15))
        })
        .collect();
    let step: Vec<u64> = raw
        .iter()
        .copied()
        .filter(|h| h.is_multiple_of(4))
        .collect();
    let (m_stage, staged) = stage_thinned(&step, budget);
    assert_eq!(m_stage, 16, "the staging rate for the step");
    assert!(
        staged.len() <= budget && staged.iter().all(|&h| keep_thinned(h, m_stage)),
        "the staged candidates are not thinned at the stated rate ({})",
        staged.len()
    );
    let (m_record, recorded) = thinned_middle(&staged[..4_000], &[], 4_096);
    assert_eq!(
        (m_record, recorded.len()),
        (1, 4_000),
        "a delivery whose staged evidence fits the room keeps it all"
    );
    let staged: HashSet<u64> = staged.into_iter().collect();
    let missed = raw
        .as_chunks::<WINDOW>()
        .0
        .iter()
        .filter(|window| window.iter().filter(|h| staged.contains(h)).count() < 2)
        .count();
    assert!(
        (5_853..=6_474).contains(&missed),
        "{missed} of 20,000 missed, outside q = 1/64"
    );
}

/// `MIK-8066` T8 (guard): a foreign fingerprint the step's Bloom filter holds
/// by chance enters the excuse selection but is never evidence; evidence is
/// only `step_ev`'s exact entries the answer delivered. Mutant "Bloom hit
/// recorded as evidence" makes the foreign hits evidence.
#[test]
fn a_bloom_hit_on_foreign_text_is_never_evidence() {
    use std::collections::HashSet;
    use std::sync::Arc;

    use super::super::{CollusionDetector, RelayParams};
    use super::BigStep;

    let detector = Arc::new(CollusionDetector::new(RelayParams::default()));
    let mut s = 0x8066_B163_0000_0008u64;
    let mut sampled = || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let h = mix(s);
        h - h % detector.sample
    };
    // Large enough that its own entries, not the headroom, fill the filter,
    // so chance hits occur at about the sizing target.
    let step: Vec<u64> = (0..100_000).map(|_| sampled()).collect();
    let mut big = BigStep::new(&detector, ("alpha:read", "alice"), &step, usize::MAX)
        .expect("premise: the store has room");
    let own: HashSet<u64> = step.iter().copied().collect();
    let filter = big.step_all.as_ref().expect("premise: the filter is built");
    let foreign: HashSet<u64> = (0..200_000)
        .map(|_| sampled())
        .filter(|h| !own.contains(h) && filter.holds(*h))
        .collect();
    assert!(!foreign.is_empty(), "premise: the filter has chance hits");
    let delivered: HashSet<u64> = big.step_ev[..10].iter().copied().collect();
    big.keep_to(&delivered.union(&foreign).copied().collect());
    assert!(
        big.excuse
            .as_ref()
            .is_some_and(|sketch| foreign.iter().any(|&h| sketch.holds(h))),
        "premise: the chance hits reached the excuse sketch"
    );
    let evidence: HashSet<u64> = big
        .evidence()
        .expect("own text delivered")
        .iter()
        .copied()
        .collect();
    assert_eq!(evidence, delivered, "a Bloom hit became evidence");
}
