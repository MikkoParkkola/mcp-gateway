// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 part 2 (P2), T17: the webhook "last received" statistic on a host
//! clock that reads before 1970.

use std::sync::atomic::Ordering;

use super::EndpointStats;

/// MIK-8202 RECORDER (stat) rule, P2 row 18: the counter still increments and
/// the previous `last_received_at` is kept; 0 is never stored. Mutant: store 0.
#[test]
fn t17_a_receive_on_an_unreadable_clock_counts_and_keeps_the_previous_time() {
    // GIVEN: a stat that last received at a known second
    let stats = EndpointStats::default();
    stats
        .last_received_at
        .store(1_700_000_000, Ordering::Relaxed);
    // WHEN
    let _clock = crate::clock::test_clock::before_epoch();
    stats.record_received();
    // THEN
    assert_eq!(stats.received.load(Ordering::Relaxed), 1);
    assert_eq!(
        stats.last_received_at.load(Ordering::Relaxed),
        1_700_000_000
    );
}

/// MIK-8202 E2-http: an `event:` POST the clock cannot date (before 1970) is
/// answered 503 with `Retry-After: 60` and is not recorded as seen, so the
/// sender's retry, once the clock reads, is accepted and emitted once.
#[tokio::test]
async fn an_event_post_on_an_unreadable_clock_is_refused_and_its_retry_accepted() {
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;

    let dir = tempfile::tempdir().expect("dir");
    let hub = crate::events::EventsHub::open(&crate::config::EventsConfig::default(), dir.path())
        .expect("hub");
    let mut intake = hub.take_intake();
    let mut definition = super::tests::make_definition(false);
    definition
        .transform
        .data
        .insert("id".to_owned(), "id".to_owned());
    definition.event = Some(crate::capability::WebhookEvent {
        delivery_id_header: Some("X-Delivery".to_owned()),
        ..crate::capability::WebhookEvent::default()
    });
    let mut state = super::tests::make_handler_state(super::tests::make_multiplexer(), definition);
    state.events = Some(std::sync::Arc::clone(&hub));
    let post = || {
        let mut headers = HeaderMap::new();
        headers.insert("X-Delivery", "d-1".parse().expect("header"));
        super::webhook_handler(
            State(state.clone()),
            headers,
            axum::body::Bytes::from_static(br#"{"id":"x"}"#),
        )
    };

    let refused = {
        let _clock = crate::clock::test_clock::before_epoch();
        post().await.into_response()
    };
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        refused.headers().get(axum::http::header::RETRY_AFTER),
        Some(&"60".parse().expect("value"))
    );
    assert!(
        intake.try_recv().is_err(),
        "emitted an occurrence dated 1969"
    );

    let retried = post().await.into_response();
    assert!(retried.status().is_success(), "{}", retried.status());
    assert!(intake.try_recv().is_ok(), "the retry is emitted");
    assert!(intake.try_recv().is_err(), "once");
}
