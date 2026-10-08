// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066.EXCUSE.1`: the sketch's rates and the store's bounds.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{MAX_SKETCHES, Sketch, SketchStore};

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

/// Every sketched fingerprint is held; a stranger is held under 0.25% of
/// the time, so four live sketches excuse a stray one under 1%.
#[test]
fn a_sketch_holds_its_own_and_rarely_a_stranger() {
    let mine = values(1, 10_000);
    let sketch = Sketch::of(&mine);
    assert!(mine.iter().all(|fp| sketch.holds(*fp)), "a false negative");
    let strangers = values(2, 100_000);
    let held = strangers.iter().filter(|fp| sketch.holds(**fp)).count();
    assert!(held * 400 < strangers.len(), "{held} strangers held");
}

/// A holder keeps at most four sketches per source: a fifth evicts the
/// oldest, counted, and the oldest no longer excuses.
#[test]
fn a_fifth_sketch_evicts_the_oldest() {
    let mut store = SketchStore::default();
    let now = Instant::now();
    let window = Duration::from_secs(600);
    let first = values(10, 100);
    store.insert((1, 2), Arc::new(Sketch::of(&first)), now);
    for i in 0..MAX_SKETCHES {
        let more = values(20 + u64::try_from(i).unwrap_or(0), 100);
        store.insert((1, 2), Arc::new(Sketch::of(&more)), now);
    }
    assert!(
        !store.holds((1, 2), first[0], now, window),
        "the oldest still excused"
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
    let window = Duration::from_secs(600);
    let fps = values(30, 100);
    store.insert((1, 2), Arc::new(Sketch::of(&fps)), now);
    assert!(store.holds((1, 2), fps[0], now, window));
    let later = now + Duration::from_secs(700);
    store.sweep(later, window);
    assert!(
        !store.holds((1, 2), fps[0], later, window),
        "an expired sketch excused"
    );
}

/// A sketch of a handful of fingerprints keeps the same bound: tiny tables
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
    assert!(held * 400 < strangers.len(), "{held} strangers held");
}

/// Past the per-holder cap the earliest delivered sketch goes, whatever
/// order the calls arrived in.
#[test]
fn the_earliest_delivered_sketch_is_evicted() {
    let mut store = SketchStore::default();
    let now = Instant::now();
    let window = Duration::from_secs(600);
    let late = values(50, 100);
    store.insert(
        (1, 2),
        Arc::new(Sketch::of(&late)),
        now + Duration::from_secs(9),
    );
    let early = values(51, 100);
    store.insert((1, 2), Arc::new(Sketch::of(&early)), now);
    for i in 0..MAX_SKETCHES - 1 {
        let more = values(60 + u64::try_from(i).unwrap_or(0), 100);
        store.insert(
            (1, 2),
            Arc::new(Sketch::of(&more)),
            now + Duration::from_secs(5),
        );
    }
    let at = now + Duration::from_secs(10);
    assert!(
        !store.holds((1, 2), early[0], at, window),
        "the earliest was kept"
    );
    assert!(
        store.holds((1, 2), late[0], at, window),
        "a later one was evicted"
    );
}
