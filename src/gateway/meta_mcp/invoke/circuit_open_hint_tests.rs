// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F17-T14: the meta-route recovery hint for an open breaker carries the
//! failure that tripped it, and keeps today's text when there is none.

use super::classify_dispatch_error;
use crate::Error;
use crate::gateway::recovery::ErrorCategory;

#[test]
fn an_open_breaker_hint_names_the_backend_and_the_last_failure() {
    let error = Error::CircuitOpen {
        backend: "rt".into(),
        last_failure: Some("WebSocket connect timed out after 1s".into()),
    };
    let (category, detail) = classify_dispatch_error(&error);
    assert!(matches!(category, ErrorCategory::CircuitBreakerTrip));
    assert!(detail.contains("'rt'"), "{detail}");
    assert!(detail.contains("WebSocket connect timed out after 1s"), "{detail}");
}

#[test]
fn a_breaker_with_no_recorded_failure_keeps_todays_hint() {
    let error = Error::CircuitOpen {
        backend: "rt".into(),
        last_failure: None,
    };
    let (_, detail) = classify_dispatch_error(&error);
    assert_eq!(detail, "Circuit breaker is open for backend 'rt'");
}
