// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F13 cells with a circuit breaker: an open breaker refuses the fill, a
//! token is spent by it, and a failed fill trips the breaker (moved from
//! `f13_fetch_on_miss_tests.rs`).

use super::*;

/// F13-T12: open breaker, cold, `closed`: fails with no list and counts
/// `input_schema_fill_refused{reason="circuit"}` (a label base lacks).
#[cfg(feature = "metrics")]
#[test]
fn f13_t12_open_breaker_refuses_the_fill_and_counts_it() {
    let ((status, body, rec), rendered) = metered(async {
        let fx = cold(InputSchemaEnforcement::Closed, ListMode::Serve).await;
        fx.backend.trip_circuit_breaker_for_test();
        let (status, body) =
            call(&fx.router, Route::Direct, "edit", &nested_invented(), None).await;
        let refused = fx.rec.lists();
        // A refusal stamps no cooldown (M11b): once the breaker closes, a call lists.
        fx.backend.reset_circuit_breaker();
        let _ = call(&fx.router, Route::Direct, "edit", &nested_invented(), None).await;
        (status, body, (refused, fx.rec.lists(), fx.rec.calls()))
    });
    assert!(failed(status, &body), "{body}");
    assert_eq!(rec, (0, 1, 0), "lists at refusal, after reset; calls");
    assert!(
        counted(&rendered, &["input_schema_fill_refused", "circuit"]),
        "the fill-origin refusal was not counted: {rendered}"
    );
}

/// F13-T12b: one token, cold, `closed`, a valid call: the fill spends it on one
/// list and the dispatch is rate-limited (base: no list, the dispatch runs).
#[tokio::test]
async fn f13_t12b_one_token_is_spent_by_the_fill() {
    let mut failsafe = FailsafeConfig::default();
    failsafe.rate_limit.enabled = true;
    failsafe.rate_limit.requests_per_second = 1;
    failsafe.rate_limit.burst_size = 1;
    let fx = build(Setup {
        failsafe,
        ..Setup::default()
    })
    .await;
    let (status, body) = call(
        &fx.router,
        Route::Direct,
        "edit",
        &json!({"edits": []}),
        None,
    )
    .await;
    assert_eq!(fx.rec.lists(), 1, "the fill did not run: {body}");
    assert_eq!(fx.rec.calls(), 0, "the dispatch got a token: {body}");
    assert!(failed(status, &body), "{body}");
}

/// F13-T12c: threshold 1, one cold `closed` call with a failing list fails as
/// a dispatch (A3), sends no `tools/call` and opens the breaker. Red on base:
/// the call is forwarded and the list failure is never observed.
#[tokio::test]
async fn f13_t12c_failed_fill_trips_the_breaker() {
    let fx = build(Setup {
        failsafe: breaker(1),
        list: ListMode::Fail,
        ..Setup::default()
    })
    .await;
    let (_, body) = call(&fx.router, Route::Direct, "edit", &nested_invented(), None).await;
    assert!(as_dispatch(&body), "{body}");
    assert_eq!(fx.rec.calls(), 0, "the call was forwarded");
    assert!(
        fx.backend.is_circuit_tripped(),
        "the failed fill was not recorded"
    );
}
