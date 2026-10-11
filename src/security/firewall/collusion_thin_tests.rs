// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066.CAP.2` unit rows: the thinned middle sample. Every row here is
//! deterministic: fingerprints are drawn from a fixed-seed generator, never
//! from the detector's per-process hash key.

use super::super::{SAMPLE, sample};
use super::{keep_thinned, mix, thinned_middle};

/// The seeded generator the rows draw raw k-gram hashes from: a 64-bit LCG
/// whose state is passed through `mix` (offset by the splitmix gamma, so the
/// draw and the thinning never apply `mix` to the same value).
struct Draws(u64);

impl Draws {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        mix(self.0.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }

    /// `count` distinct hashes that pass the `SAMPLE` test: a cut middle's
    /// candidates, as the record path sees them.
    fn sampled(&mut self, count: usize) -> Vec<u64> {
        let mut out = std::collections::BTreeSet::new();
        while out.len() < count {
            let h = self.next();
            if h % SAMPLE == 0 {
                out.insert(h);
            }
        }
        out.into_iter().collect()
    }
}

/// B1′ (design §14.3): a run of `n` distinct k-grams is missed when fewer
/// than 2 survive, each surviving with q = 1/(4m). The §14.3 table cites it.
fn b1_prime_miss(n: u32, m: u32) -> f64 {
    let q = 1.0 / (4.0 * f64::from(m));
    (1.0 - q).powf(f64::from(n)) + f64::from(n) * q * (1.0 - q).powf(f64::from(n - 1))
}

/// The selector as the design states it, by brute force: double m and
/// recount until the survivors fit. The oracle for the one-pass selector.
fn brute_select(middle: &[u64], room: usize) -> (u64, usize) {
    let mut m = 1u64;
    loop {
        let k = middle.iter().filter(|&&h| keep_thinned(h, m)).count();
        if k <= room {
            return (m, k);
        }
        m *= 2;
    }
}

/// `MIK-8066.CAP.2` M6b: the rate comes from the survivors themselves, not
/// their expected count. [8, 24] keeps both at m = 2 (the expected-count
/// rule's pick, over a room of 1); the first fitting rate is m = 16, with
/// none left. 0 maps to 0 and survives every rate, so [0, 304] climbs to
/// m = 256.
#[test]
fn a_middle_sample_never_exceeds_its_room() {
    assert_eq!(thinned_middle(&[8, 24], &[], 1), (16, vec![]));
    assert_eq!(thinned_middle(&[0, 304], &[], 1), (256, vec![0]));
    // mix(0xCE25_6BA9_4D67_D15A) = 2^63: only 0 survives past it, so the
    // search ends at k = 64 and the reported rate saturates at 2^63.
    assert_eq!(mix(0xCE25_6BA9_4D67_D15A), 1 << 63, "premise");
    assert_eq!(
        thinned_middle(&[0, 0xCE25_6BA9_4D67_D15A], &[], 1),
        (1 << 63, vec![0])
    );
    assert!(
        keep_thinned(8, 2) && keep_thinned(24, 2),
        "premise: m = 2 keeps both"
    );
    assert_eq!(
        thinned_middle(&[8, 24], &[], 0),
        (1, vec![]),
        "no room, no sample"
    );
}

/// `MIK-8066.CAP.2` M5b: the sample is drawn from the cut minus what the
/// receipt kept, so the kept head and tail never spend the middle's room.
#[test]
fn the_middle_is_exactly_cut_minus_kept() {
    let cut: Vec<u64> = (0..4_096).map(|i| 4 * i).collect();
    let (kept, middle) = cut.split_at(1_512);
    let (m, sample) = thinned_middle(&cut, kept, 2_584);
    assert_eq!(m, 1, "the whole middle fits its room");
    assert_eq!(sample, middle, "the sample is exactly cut minus kept");
    // Duplicates and order in `cut` do not matter.
    let mut shuffled: Vec<u64> = cut.iter().rev().copied().collect();
    shuffled.extend_from_slice(middle);
    assert_eq!(thinned_middle(&shuffled, kept, 2_584).1, middle);
}

/// `MIK-8066.CAP.2` M8: the sample misses a 200-char relay (n = 153 k-grams)
/// at m = 8 within B1′. Fixed seed and trial count: one outcome on every
/// run. The band is the exact binomial(N, P) interval with each tail at most
/// 1e-6 (785..=1067, about 4.9 sigma), two-sided so over-keeping fails too;
/// it shows the fixed outcome conforms to the formula, not run-to-run noise.
/// Reference outcome (design handoff m8.py, same algorithm): 920.
#[test]
fn the_middle_sample_misses_within_its_budget() {
    const N: usize = 20_000;
    const RUN: usize = 153;
    let p = b1_prime_miss(153, 8);
    assert!((p - 0.046_116).abs() < 1e-6, "premise: P = {p}");
    let mut draws = Draws(0x8066_CA92_0000_0001);
    let mut missed = 0;
    for _ in 0..N {
        let hashes: Vec<u64> = (0..RUN).map(|_| draws.next()).collect();
        let kept = sample(&hashes, SAMPLE)
            .into_iter()
            .filter(|&h| keep_thinned(h, 8))
            .count();
        missed += usize::from(kept < 2);
    }
    assert!(
        (785..=1_067).contains(&missed),
        "{missed} of {N} missed, outside B1' at m = 8"
    );
}

/// `MIK-8066.CAP.2` M8b: the one-pass selector agrees with the brute-force
/// one on seeded middles the size of a 12 KiB, 64 KiB and 1 MiB cut, and
/// picks the rates the §14.3 table publishes. Room: 4,096 less the 1,512
/// head and tail fingerprints. Python cross-check (m8.py), not asserted:
/// survivors 1,524 / 1,834 / 1,978.
#[test]
fn the_selector_matches_the_published_rows() {
    const ROOM: usize = 4_096 - 1_512;
    for (candidates, published) in [(1_524, 1), (14_836, 8), (260_600, 128)] {
        let middle = Draws(0x8066_0B00_0000_0002).sampled(candidates);
        let (m, sample) = thinned_middle(&middle, &[], ROOM);
        let (brute_m, brute_k) = brute_select(&middle, ROOM);
        assert_eq!(
            (m, sample.len()),
            (brute_m, brute_k),
            "{candidates} candidates"
        );
        assert_eq!(m, published, "{candidates} candidates: the published rate");
        assert!(sample.len() <= ROOM);
        assert!(sample.iter().all(|&h| keep_thinned(h, m)));
    }
}
