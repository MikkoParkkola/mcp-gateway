// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How each store refusal maps to an input outcome (moved out of
//! `input_round.rs` to keep it under its size ceiling).

use super::{InputOutcome, StoreError, input_outcome_of};

/// Each store refusal means one thing to the caller of `provide_input`,
/// whether the read or the write raised it.
#[test]
fn a_store_refusal_maps_to_one_input_outcome() {
    assert!(matches!(
        input_outcome_of(StoreError::InvalidTransition),
        InputOutcome::NotOutstanding
    ));
    assert!(matches!(
        input_outcome_of(StoreError::Capacity),
        InputOutcome::TooLarge
    ));
    assert!(matches!(
        input_outcome_of(StoreError::NotFound),
        InputOutcome::NotFound
    ));
    assert!(matches!(
        input_outcome_of(StoreError::Unavailable),
        InputOutcome::Unavailable
    ));
}
