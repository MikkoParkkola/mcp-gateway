// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066.EXCUSE.1`, `MIK-8200`: the sketch's rates and the store's
//! bounds.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{Shape, Sketch, SketchStore, shape};

/// Spread-out 64-bit values, as keyed fingerprints are.
fn values(seed: u64, n: usize) -> Vec<u64> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            x ^ (x >> 29)
        })
        .collect()
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// Every sketched fingerprint is held; a stranger is held at about the
/// first position's 0.35% target, under 0.5%.
#[test]
fn a_sketch_holds_its_own_and_rarely_a_stranger() {
    let mine = values(1, 10_000);
    let sketch = Sketch::of(&mine);
    assert!(mine.iter().all(|fp| sketch.holds(*fp)), "a false negative");
    let strangers = values(2, 100_000);
    let held = strangers.iter().filter(|fp| sketch.holds(**fp)).count();
    assert!(held * 200 < strangers.len(), "{held} strangers held");
}

/// `MIK-8200.EVICT.3`: a holder keeps every sketch whose delivery is in the
/// window. A fifth keeps the first (it used to evict it), and no other
/// holder is excused by any of them.
#[test]
fn a_fifth_sketch_keeps_the_first() {
    let mut store = SketchStore::default();
    let now = Instant::now();
    let window = secs(600);
    let first = values(10, 100);
    assert!(store.insert((1, 2), &first, now));
    for i in 0..4 {
        assert!(store.insert((1, 2), &values(20 + i, 100), now));
    }
    assert!(
        store.holds((1, 2), first[0], now, window),
        "the first was evicted"
    );
    assert!(
        !store.holds((1, 3), values(20, 1)[0], now, window),
        "another holder excused"
    );
}

/// A sketch expires with the window like any copy.
#[test]
fn a_sketch_expires_with_the_window() {
    let mut store = SketchStore::default();
    let now = Instant::now();
    let window = secs(600);
    let fps = values(30, 100);
    assert!(store.insert((1, 2), &fps, now));
    assert!(store.holds((1, 2), fps[0], now, window));
    let later = now + secs(700);
    store.sweep(later, window);
    assert!(
        !store.holds((1, 2), fps[0], later, window),
        "an expired sketch excused"
    );
}

/// A sketch of a handful of fingerprints keeps the rate: tiny tables
/// would collide far above it.
#[test]
fn a_small_sketch_keeps_the_rate() {
    let mut checks = 0_usize;
    let mut held = 0_usize;
    for seed in 0..200 {
        let sketch = Sketch::of(&values(1_000 + seed, 4));
        for stranger in values(5_000 + seed, 500) {
            checks += 1;
            held += usize::from(sketch.holds(stranger));
        }
    }
    assert!(held * 400 < checks, "{held} of {checks} strangers held");
}

/// Kept fingerprints are 0 mod 4 (sampling); the rate holds for them too.
#[test]
fn sampled_fingerprints_keep_the_rate() {
    let quarter = |v: Vec<u64>| v.into_iter().map(|x| x << 2).collect::<Vec<_>>();
    let mine = quarter(values(40, 10_000));
    let sketch = Sketch::of(&mine);
    assert!(mine.iter().all(|fp| sketch.holds(*fp)), "a false negative");
    let strangers = quarter(values(41, 100_000));
    let held = strangers.iter().filter(|fp| sketch.holds(**fp)).count();
    assert!(held * 200 < strangers.len(), "{held} strangers held");
}

/// Past the per-pair backstop the earliest delivered sketch goes, whatever
/// order the calls arrived in: the backstop fits two, a third arrives.
#[test]
fn the_earliest_delivered_sketch_is_evicted() {
    let pair_cap = shape(100, 0).bytes() + shape(100, 1).bytes();
    let mut store = SketchStore::with_caps(usize::MAX, pair_cap);
    let now = Instant::now();
    let window = secs(600);
    let (late, early, third) = (values(50, 100), values(51, 100), values(52, 100));
    assert!(store.insert((1, 2), &late, now + secs(9)));
    assert!(store.insert((1, 2), &early, now));
    assert!(store.insert((1, 2), &third, now + secs(5)));
    let at = now + secs(10);
    assert!(
        !store.holds((1, 2), early[0], at, window),
        "the earliest was kept"
    );
    assert!(
        store.holds((1, 2), late[0], at, window),
        "a later one was evicted"
    );
    assert!(
        store.holds((1, 2), third[0], at, window),
        "the new one was evicted"
    );
}

/// Past the byte cap the oldest sketch goes, whichever pair holds it, and
/// stops excusing; the rest stay. Four sketches of four pairs (so the
/// per-pair backstop never acts) in a store that fits three.
#[test]
fn past_the_byte_cap_the_oldest_sketch_goes() {
    let now = Instant::now();
    let window = secs(600);
    let fps: Vec<Vec<u64>> = (0..4).map(|i| values(70 + i, 10)).collect();
    let one = shape(10, 0).bytes();
    let mut store = SketchStore::with_caps(3 * one, usize::MAX);
    for (i, f) in fps.iter().enumerate() {
        let n = u64::try_from(i).unwrap_or(0);
        assert!(store.insert((n, 9), f, now + secs(n)));
    }
    let at = now + secs(5);
    assert!(
        !store.holds((0, 9), fps[0][0], at, window),
        "the oldest outlived the byte cap"
    );
    for (i, f) in fps.iter().enumerate().skip(1) {
        let pair = (u64::try_from(i).unwrap_or(0), 9);
        assert!(
            store.holds(pair, f[0], at, window),
            "sketch {i} was evicted"
        );
    }
}

/// One delivery bigger than the slack the cap leaves evicts as many of the
/// oldest as it takes, not just one: two small sketches fill the cap, a
/// larger third pushes both out.
#[test]
fn a_large_sketch_evicts_until_the_store_fits() {
    let now = Instant::now();
    let window = secs(600);
    let (a, b, big) = (values(80, 10), values(81, 10), values(82, 150));
    let (one, large) = (shape(10, 0).bytes(), shape(150, 0).bytes());
    assert!(one < large && large <= 2 * one, "sizes {one} {large}");
    let mut store = SketchStore::with_caps(2 * one, usize::MAX);
    assert!(store.insert((1, 9), &a, now));
    assert!(store.insert((2, 9), &b, now + secs(1)));
    assert!(store.insert((3, 9), &big, now + secs(2)));
    let at = now + secs(5);
    assert!(
        !store.holds((1, 9), a[0], at, window),
        "the oldest was kept"
    );
    assert!(
        !store.holds((2, 9), b[0], at, window),
        "one pop left the store over its cap"
    );
    assert!(
        store.holds((3, 9), big[0], at, window),
        "the new sketch was evicted"
    );
}

/// Pooled aggregate false-excuse rate of one pair holding sketches of
/// `sizes` (built at production positions, or in `fixed` shapes), over
/// `builds` independent builds of `strangers` each.
fn aggregate(sizes: &[usize], fixed: Option<&[Shape]>, builds: u64, strangers: usize) -> f64 {
    let mut held = 0_usize;
    for build in 0..builds {
        let sketches: Vec<Sketch> = sizes
            .iter()
            .enumerate()
            .map(|(i, &n)| {
                let fps = values(1_000 * build + 7 * u64::try_from(i).unwrap_or(0) + 1, n);
                let shape = fixed.map_or_else(|| shape(n, i), |s| s[i]);
                Sketch::build(&fps, shape)
            })
            .collect();
        held += values(900_000 + build, strangers)
            .iter()
            .filter(|fp| sketches.iter().any(|s| s.holds(**fp)))
            .count();
    }
    #[expect(clippy::cast_precision_loss, reason = "counts far below 2^52")]
    let rate = held as f64 / (builds as f64 * strangers as f64);
    rate
}

/// `MIK-8200.EVICT.5`: sixteen live sketches of one pair keep the B3
/// budget: under 1% (stated bound 0.8%, measured 0.69% on the mixed input).
#[test]
fn sixteen_live_sketches_keep_the_budget() {
    let rate = aggregate(&[10_000; 16], None, 2, 50_000);
    assert!(rate < 0.01, "aggregate {rate}");
}

/// `MIK-8200.EVICT.5`: gpt r3's mixed input (8 × 10,000 then 40 × 16
/// fingerprints) at production sizes stays under 1%.
#[test]
fn a_mixed_pair_keeps_the_budget() {
    let mut sizes = vec![10_000; 8];
    sizes.extend([16; 40]);
    let rate = aggregate(&sizes, None, 4, 50_000);
    assert!(rate < 0.01, "aggregate {rate}");
}

/// `MIK-8200` mixer discriminator (not a bound check): gpt r3's exact
/// 1,024-bit filters with 8/9/10/11 probes. Independent probes measure about
/// 0.81%; a fold-and-multiply mixer about 1.33%, which this row refuses.
#[test]
fn independent_probes_keep_small_filters_under_the_budget() {
    let shapes = [8, 9, 10, 11].map(|probes| Shape { words: 16, probes });
    let rate = aggregate(&[89, 79, 71, 64], Some(&shapes), 8, 50_000);
    assert!(rate < 0.01, "aggregate {rate}");
}

/// `MIK-8200` sizing row (carries the bound): every shape the rule gives
/// has a classic rate at most its position's target, named cell
/// (n = 212, position 0) included.
#[test]
fn every_shape_meets_its_target() {
    let named = shape(212, 0);
    assert!(super::ln_rate(212, named.words * 64, named.probes) <= 0.0035_f64.ln());
    for position in (0..=32).step_by(4) {
        #[expect(clippy::cast_precision_loss, reason = "small positions")]
        let target = 0.0035_f64.ln() - position as f64 * std::f64::consts::LN_2;
        for n in (1..=20_000).step_by(7) {
            let s = shape(n, position);
            assert!(
                super::ln_rate(n, s.words * 64, s.probes) <= target,
                "n = {n}, position {position}: {s:?}"
            );
        }
    }
}

/// `MIK-8200`: a new sketch takes the lowest free position, not one still
/// held: positions 0-3 live, the one at 0 expires, the next takes 0.
#[test]
fn a_freed_position_is_reused_first() {
    let mut store = SketchStore::default();
    let now = Instant::now();
    let window = secs(600);
    assert!(store.insert((1, 2), &values(1, 50), now));
    for i in 0..3 {
        assert!(store.insert((1, 2), &values(2 + i, 50), now + secs(100)));
    }
    store.sweep(now + secs(650), window);
    assert!(store.insert((1, 2), &values(9, 50), now + secs(650)));
    let mut positions = store.positions_of((1, 2));
    positions.sort_unstable();
    assert_eq!(positions, vec![0, 1, 2, 3], "a held position was reused");
}

/// `MIK-8200`: two reservations for one pair, both pending, hold distinct
/// positions, even where the second crosses the pair's backstop.
#[test]
fn concurrent_reservations_hold_distinct_positions() {
    let mut store = SketchStore::default();
    let a = store.reserve((1, 2), 100).expect("fits");
    let b = store.reserve((1, 2), 100).expect("fits");
    assert_ne!(a.position, b.position, "one position held twice");
    let cap = shape(100, 0).bytes() + shape(100, 1).bytes();
    let mut tight = SketchStore::with_caps(usize::MAX, cap);
    let a = tight.reserve((1, 2), 100).expect("fits");
    let b = tight.reserve((1, 2), 100).expect("fits");
    assert_ne!(a.position, b.position, "one position held twice");
    assert!(
        tight.reserve((1, 2), 100).is_none(),
        "a pending reservation was evicted to make room"
    );
    assert_eq!(tight.refused, 1, "the refusal was not counted");
}

/// `MIK-8200`: an abandoned build releases its position and bytes.
#[test]
fn an_abandoned_build_releases_its_position() {
    let cap = shape(100, 0).bytes();
    let mut store = SketchStore::with_caps(usize::MAX, cap);
    let held = store.reserve((1, 2), 100).expect("fits");
    assert!(store.reserve((1, 2), 100).is_none(), "the cap is full");
    store.abandon(&held);
    let again = store.reserve((1, 2), 100).expect("released");
    assert_eq!(again.position, 0, "the position was not freed");
}

/// `MIK-8200`: a sketch still being built excuses nothing yet.
#[test]
fn a_pending_sketch_excuses_nothing() {
    let mut store = SketchStore::default();
    let now = Instant::now();
    let fps = values(60, 50);
    let reservation = store.reserve((1, 2), fps.len()).expect("fits");
    assert!(!store.holds((1, 2), fps[0], now, secs(600)));
    let sketch = Arc::new(Sketch::build(&fps, reservation.shape));
    store.publish(&reservation, sketch, now);
    assert!(store.holds((1, 2), fps[0], now, secs(600)));
}

/// `MIK-8200`: the sizing loop is bounded by the byte cap, whatever its
/// float comparison says: a count no delivery can reach still returns at
/// most `MAX_WORDS`, and that shape is refused, counted, never built.
#[test]
fn an_impossible_count_is_bounded_and_refused() {
    let huge = shape(usize::MAX, 0);
    assert!(huge.words <= super::MAX_WORDS, "{huge:?}");
    let mut store = SketchStore::default();
    assert!(store.reserve((1, 2), usize::MAX).is_none(), "built");
    assert_eq!(store.refused, 1, "the refusal was not counted");
}
