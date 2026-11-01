// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Caps, keep-alive, slow consumers and the lifetime.

use super::*;

fn hub(state: &AppState) -> &crate::gateway::ui::stream::StreamHub {
    state.dashboard_bootstrap.stream_hub()
}

#[tokio::test]
async fn stream_33_gets_503_with_retry_after_and_a_drop_admits_the_next() {
    let (state, _dir) = fixture().await;
    let mut held = Vec::new();
    for i in 0..MAX_UI_STREAMS {
        let key = format!("c{}", i / MAX_PER_CREDENTIAL);
        // Distinct credentials, so only the global cap can refuse.
        let h = state
            .dashboard_bootstrap
            .issue_session_at(Now::read(), &limits(&state));
        held.push((
            key,
            open(&state, request(STREAM, Who::Cookie(&h), None)).await,
        ));
    }
    let h = issue(&state);
    let over = open(&state, request(STREAM, Who::Cookie(&h), None)).await;
    assert_eq!(over.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(over.headers.contains_key(header::RETRY_AFTER));
    held.pop();
    assert!(yield_until(|| hub(&state).open_streams() < MAX_UI_STREAMS).await);
    let next = open(&state, request(STREAM, Who::Cookie(&h), None)).await;
    assert_eq!(next.status, StatusCode::OK);
}

#[tokio::test]
async fn one_credential_may_hold_four_streams() {
    let (state, _dir) = fixture().await;
    let mut held = Vec::new();
    for _ in 0..MAX_PER_CREDENTIAL {
        held.push(open(&state, request(STREAM, Who::Bearer(KEY), None)).await);
    }
    let fifth = open(&state, request(STREAM, Who::Bearer(KEY), None)).await;
    assert_eq!(fifth.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(fifth.headers.contains_key(header::RETRY_AFTER));
}

#[tokio::test]
async fn keep_alive_comments_arrive_when_nothing_changes() {
    let (state, _dir) = fixture().await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    s.until("status").await;
    let ping = s.until("comment").await;
    assert!(
        ping.data.is_empty() || ping.data.contains("keep"),
        "{ping:?}"
    );
}

#[tokio::test]
async fn a_client_that_stops_reading_is_closed_and_its_slot_comes_back() {
    let (state, _dir) = fixture().await;
    let stalled = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    assert!(yield_until(|| hub(&state).open_streams() == 1).await);
    // Never read: the transport buffer fills and the 30 s write limit expires.
    // The paused clock steps from timer to timer while the runtime is idle,
    // so the blocked write's 30 s limit fires whenever it was registered.
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert!(yield_until(|| hub(&state).open_streams() == 0).await);
    assert!(!hub(&state).watcher_running());
    drop(stalled);
    let fresh = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    assert_eq!(fresh.status, StatusCode::OK);
}

#[tokio::test]
async fn a_stream_ends_cleanly_after_one_hour() {
    let (state, _dir) = fixture().await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    s.until("status").await;
    assert!(s.ended().await);
    assert!(yield_until(|| hub(&state).open_streams() == 0).await);
}

#[tokio::test]
async fn a_changed_ignored_cookie_beside_one_bearer_takes_no_new_slot() {
    let (state, _dir) = fixture().await;
    let mut held = Vec::new();
    for i in 0..MAX_PER_CREDENTIAL {
        let cookie = format!("junk-{i}");
        held.push(open(&state, request(STREAM, Who::Both(BEARER, &cookie), None)).await);
    }
    let over = open(
        &state,
        request(STREAM, Who::Both(BEARER, "junk-last"), None),
    )
    .await;
    assert_eq!(over.status, StatusCode::SERVICE_UNAVAILABLE);
}
