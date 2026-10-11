// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 slice 3a unit rows (design M1): each decision a may-effect step
//! reports, and the one function that drops the witness on an effect.

use super::*;

#[test]
fn an_effect_drops_the_witness() {
    assert!(RefundWitness::carry(Some(RefundWitness::at_capture()), Effect::Took).is_none());
}

#[test]
fn no_effect_keeps_the_witness() {
    let kept = RefundWitness::carry(Some(RefundWitness::at_capture()), Effect::None);
    assert!(kept.is_some());
    if let Some(kept) = kept {
        kept.spend();
    }
    assert!(
        RefundWitness::carry(None, Effect::None).is_none(),
        "nothing to keep"
    );
}

#[test]
fn a_mint_or_an_account_credential_is_an_effect() {
    assert_eq!(
        dispatch_effect(true, false),
        Effect::Took,
        "a propagation mint"
    );
    assert_eq!(
        dispatch_effect(false, true),
        Effect::Took,
        "an account credential"
    );
    assert_eq!(
        dispatch_effect(false, false),
        Effect::None,
        "a static credential"
    );
}

#[test]
fn a_cold_schema_check_is_an_effect() {
    assert_eq!(
        schema_effect(false),
        Effect::Took,
        "a fetch or a wait on one"
    );
    assert_eq!(schema_effect(true), Effect::None, "held metadata");
}

#[test]
fn a_consumed_continuation_is_an_effect() {
    assert_eq!(retry_effect(true), Effect::Took);
    assert_eq!(retry_effect(false), Effect::None);
}
