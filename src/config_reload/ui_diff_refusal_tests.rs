// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Independent mapping oracles: neither debug output nor input text is public.

use super::{RefusalClass, ReplaceError, UiRefused, validate_refusal};

const CANARY: &str = "validation-detail-canary";

fn no_input_text(refusal: &UiRefused) {
    assert!(!format!("{refusal:?}").contains(CANARY), "{refusal:?}");
}

/// K6: red oracle is the typed posture refusal without its input reason.
#[test]
fn k6_posture_is_typed() {
    let got = validate_refusal(&ReplaceError::ReloadRefused {
        class: RefusalClass::Posture,
        reason: CANARY.to_owned(),
    });
    assert_eq!(
        got,
        UiRefused::ReloadRefused {
            class: RefusalClass::Posture
        }
    );
    no_input_text(&got);
}

/// K6: red oracle is Unsupported with a fixed reason, not debug input text.
#[test]
fn k6_unsupported_is_fixed() {
    let got = validate_refusal(&ReplaceError::Unsupported(CANARY.to_owned()));
    assert!(matches!(got, UiRefused::Unsupported(_)), "{got:?}");
    no_input_text(&got);
}

/// K6: red oracle is Failed with a fixed reason, rather than Unsupported.
#[test]
fn k6_failed_is_fixed() {
    let got = validate_refusal(&ReplaceError::Failed(CANARY.to_owned()));
    assert!(matches!(got, UiRefused::Failed(_)), "{got:?}");
    no_input_text(&got);
}

/// K6: red oracle is Failed for Busy, which has no input string to echo.
#[test]
fn k6_busy_is_failed() {
    let got = validate_refusal(&ReplaceError::Busy);
    assert!(matches!(got, UiRefused::Failed(_)), "{got:?}");
    no_input_text(&got);
}

/// K6: red oracle is Invalid with a fixed reason for a compute refusal.
#[test]
fn k6_refused_is_fixed() {
    let got = validate_refusal(&ReplaceError::Refused(CANARY.to_owned()));
    assert!(matches!(got, UiRefused::Invalid(_)), "{got:?}");
    no_input_text(&got);
}
