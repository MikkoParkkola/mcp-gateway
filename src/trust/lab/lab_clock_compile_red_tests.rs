// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4a compile-red row R10: written against
//! `CatalogTrustLab::evaluate_card -> crate::Result<TrustLabEvaluation>`, so
//! it does not build on the code before that change. Kept apart so it can be
//! held back on its own.

use chrono::TimeZone;

use super::tests::clean_card;
use super::*;

/// MIK-8202.AC.16 (R10, mutant M10): `evaluate_card` reads the clock through
/// `crate::clock`; on a clock that reads before 1970 it returns
/// `crate::Error::Internal` naming the clock, never an evaluation dated 1969 or
/// the epoch. Under a readable clock it equals the explicit-time evaluation at
/// that reading. Mutant M10: on the clock error, evaluate at the epoch.
#[test]
fn evaluate_card_on_a_clock_before_1970_is_an_error() {
    const T: i64 = 1_782_648_000;
    let lab = CatalogTrustLab::default();
    let dark = crate::clock::test_clock::before_epoch();
    match lab.evaluate_card(&clean_card()) {
        Err(crate::Error::Internal(message)) => assert!(message.contains("1970"), "{message}"),
        other => panic!("a dark clock must not evaluate: {other:?}"),
    }
    drop(dark);

    let readable = crate::clock::test_clock::at_secs(u64::try_from(T).unwrap());
    let evaluation = lab
        .evaluate_card(&clean_card())
        .expect("a readable clock evaluates");
    drop(readable);
    let at = Utc.timestamp_opt(T, 0).unwrap();
    assert_eq!(
        evaluation,
        lab.evaluate_card_with_baseline_at(&clean_card(), None, at)
    );
}
