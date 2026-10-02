// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;
use crate::events::client::Answer;

const POLICY: Retry = Retry {
    base: Duration::from_secs(10),
    max_attempts: 5,
    window: Duration::from_secs(900),
};

fn status(code: u16) -> Result<Answer, CallbackFailure> {
    Ok(Answer {
        status: code,
        retry_after: None,
        body: Vec::new(),
    })
}

#[test]
fn delivered_gone_and_too_large_are_final() {
    let now = Utc::now();
    assert!(matches!(
        judge(&status(204), 1, now, now, POLICY, 0.5).0,
        Settle::Delivered
    ));
    for (code, want) in [(410, DeadReason::Gone), (413, DeadReason::TooLarge)] {
        let (settle, _) = judge(&status(code), 1, now, now, POLICY, 0.5);
        assert!(
            matches!(settle, Settle::Dead { reason, .. } if reason == want),
            "{code}"
        );
    }
}

#[test]
fn other_failures_retry_with_bounded_backoff_then_exhaust() {
    let now = Utc::now();
    let (settle, category) = judge(&status(503), 2, now, now, POLICY, 1.0);
    assert_eq!(category, "http_5xx");
    let Settle::Retry { next, .. } = settle else {
        panic!("retried");
    };
    assert_eq!(next - now, chrono::Duration::seconds(30), "base x 3");
    let (settle, category) = judge(&Err(CallbackFailure::Timeout), 5, now, now, POLICY, 0.0);
    assert_eq!(category, "timeout");
    assert!(matches!(
        settle,
        Settle::Dead {
            reason: DeadReason::Exhausted,
            ..
        }
    ));
    let late = now + chrono::Duration::seconds(900);
    let (settle, _) = judge(&status(307), 1, now, late, POLICY, 0.0);
    assert!(
        matches!(
            settle,
            Settle::Dead {
                reason: DeadReason::Exhausted,
                ..
            }
        ),
        "window over"
    );
}

#[test]
fn retry_after_is_honoured_inside_the_window() {
    let now = Utc::now();
    let answer = Ok(Answer {
        status: 429,
        retry_after: Some(Duration::from_secs(5000)),
        body: Vec::new(),
    });
    let (settle, _) = judge(&answer, 1, now, now, POLICY, 0.0);
    let Settle::Retry { next, .. } = settle else {
        panic!("retried");
    };
    assert_eq!(
        next - now,
        chrono::Duration::seconds(900),
        "clamped to the window"
    );
}

#[test]
fn an_attempt_past_its_bounds_is_overdue_before_it_is_sent() {
    let first = Utc::now();
    let inside = first + chrono::Duration::seconds(899);
    let after = first + chrono::Duration::seconds(900);
    assert!(
        !overdue(1, first, after, POLICY),
        "a first attempt always goes"
    );
    assert!(
        !overdue(5, first, inside, POLICY),
        "the last allowed attempt"
    );
    assert!(overdue(6, first, inside, POLICY), "past max_attempts");
    assert!(
        overdue(2, first, after, POLICY),
        "a retry at the window's end"
    );
}
