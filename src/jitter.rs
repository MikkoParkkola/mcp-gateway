// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one retry jitter: a delay spread uniformly over `[0, bound]`.

use std::time::Duration;

/// Spread a delay uniformly over `[0, bound]` ("full jitter").
///
/// Callers that back off from the same failure, or warm-start tasks spawned in
/// the same instant, would otherwise wake together and hit a recovering or
/// still-booting service as one burst; exponential growth alone does not
/// prevent that herd.
///
/// NANOSECONDS, not milliseconds. Rounding to whole milliseconds collapses any
/// sub-millisecond bound to zero, so a 100 µs backoff would retry with no wait
/// at all (warm-start's own copy did exactly that until MIK-8665).
pub(crate) fn full_jitter(bound: Duration) -> Duration {
    if bound.is_zero() {
        return bound;
    }
    let nanos = u64::try_from(bound.as_nanos()).unwrap_or(u64::MAX);
    Duration::from_nanos(rand::random_range(0..=nanos))
}

#[cfg(test)]
mod tests {
    use super::full_jitter;
    use std::collections::HashSet;
    use std::time::Duration;

    #[test]
    fn a_zero_bound_gives_zero() {
        assert_eq!(full_jitter(Duration::ZERO), Duration::ZERO);
    }

    /// Bounded AND spread: a constant delay, zero or the bound itself, fails the
    /// distinct-value check, so this cannot pass on a jitter that does nothing.
    #[test]
    fn draws_stay_within_the_bound_and_spread_over_it() {
        let bound = Duration::from_secs(1);
        let draws: Vec<Duration> = (0..256).map(|_| full_jitter(bound)).collect();
        assert!(
            draws.iter().all(|d| *d <= bound),
            "a draw exceeded {bound:?}"
        );
        let distinct: HashSet<Duration> = draws.into_iter().collect();
        assert!(
            distinct.len() >= 2,
            "256 draws over {bound:?} were all equal"
        );
    }

    #[test]
    fn the_largest_bound_does_not_panic() {
        // `as_nanos` exceeds u64 here; the saturating conversion must not panic.
        let _ = full_jitter(Duration::MAX);
    }
}
