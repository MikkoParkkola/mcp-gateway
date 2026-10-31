// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who may open the stream, and what it does to a session.

use super::*;

const NEARLY_IDLE: Duration = Duration::from_secs(1740);
const TWO_MINUTES: Duration = Duration::from_secs(120);

#[tokio::test]
async fn admin_bearer_and_admin_cookie_get_an_event_stream_with_hello() {
    let (state, _dir) = fixture().await;
    let cookie = issue(&state);
    for who in [Who::Bearer(BEARER), Who::Cookie(&cookie)] {
        let mut s = open(&state, request(STREAM, who, None)).await;
        assert_eq!(s.status, StatusCode::OK);
        let h = &s.headers;
        assert_eq!(h[header::CONTENT_TYPE], "text/event-stream");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        assert_eq!(h["x-accel-buffering"], "no");
        let hello = s.next().await.expect("hello");
        assert_eq!(hello.event, "hello");
        assert!(hello.id.is_none(), "hello carries no id");
        assert_eq!(
            hello.json()["kinds"],
            serde_json::json!(["status", "reload"])
        );
        assert!(hello.json()["head"].is_string());
    }
}

#[tokio::test]
async fn an_anonymous_caller_gets_401_and_no_stream() {
    let (state, _dir) = fixture().await;
    let s = open(&state, request(STREAM, Who::Nobody, None)).await;
    assert_eq!(s.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_non_admin_key_gets_status_only_and_counts_only() {
    let (state, _dir) = fixture().await;
    let mut s = open(&state, request(STREAM, Who::Bearer(KEY), None)).await;
    assert_eq!(s.status, StatusCode::OK);
    assert_eq!(
        s.until("hello").await.json()["kinds"],
        serde_json::json!(["status"])
    );
    let status = s.until("status").await.json();
    assert!(status.get("servers").is_none(), "counts only: {status}");
    assert_eq!(status["auth"]["admin"], false);
}

#[tokio::test]
async fn a_stream_and_its_reconnects_never_extend_a_session_but_a_plain_request_does() {
    let (state, _dir) = fixture().await;
    let h = issue(&state);
    let mut first = open(&state, request(STREAM, Who::Cookie(&h), None)).await;
    first.until("status").await;
    state.dashboard_bootstrap.backdate(&h, NEARLY_IDLE);
    let mut again = open(&state, request(STREAM, Who::Cookie(&h), None)).await;
    again.until("status").await;
    state.dashboard_bootstrap.backdate(&h, TWO_MINUTES);
    assert!(
        again.ended().await,
        "the idle limit passed with no activity"
    );
    assert!(first.ended().await);
    let refused = open(&state, request(STREAM, Who::Cookie(&h), None)).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_ordinary_ui_api_request_still_extends_the_session() {
    let (state, _dir) = fixture().await;
    let h = issue(&state);
    state.dashboard_bootstrap.backdate(&h, NEARLY_IDLE);
    let ok = open(&state, request(STATUS, Who::Cookie(&h), None)).await;
    assert_eq!(ok.status, StatusCode::OK);
    state.dashboard_bootstrap.backdate(&h, TWO_MINUTES);
    let still = open(&state, request(STATUS, Who::Cookie(&h), None)).await;
    assert_eq!(
        still.status,
        StatusCode::OK,
        "the touch restarted the idle clock"
    );
}

#[tokio::test]
async fn logging_out_ends_the_stream_within_a_tick() {
    let (state, _dir) = fixture().await;
    let h = issue(&state);
    let mut s = open(&state, request(STREAM, Who::Cookie(&h), None)).await;
    s.until("status").await;
    let out = Request::builder()
        .method("POST")
        .uri("/dashboard/logout")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={h}"))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_346))))
        .body(Body::empty())
        .unwrap();
    let _ = create_router(Arc::clone(&state))
        .oneshot(out)
        .await
        .unwrap();
    assert!(s.ended_within(REVOKED_WITHIN).await);
}

#[tokio::test]
async fn a_removed_configured_key_is_restart_required_and_stream_and_list_agree() {
    let (state, _dir) = fixture().await;
    let mut s = open(&state, request(STREAM, Who::Bearer(KEY), None)).await;
    s.until("status").await;
    state.live_config.edit(|c| c.auth.api_keys.clear());
    let list = open(&state, request(STATUS, Who::Bearer(KEY), None)).await;
    let still_open = tokio::time::timeout(Duration::from_secs(3), s.next()).await;
    assert_eq!(
        list.status == StatusCode::OK,
        still_open.map_or(true, |f| f.is_some()),
        "the stream follows exactly what ingress does for this key"
    );
}

#[tokio::test]
async fn a_frame_waiting_for_room_is_not_sent_after_the_credential_is_revoked() {
    let (state, _dir) = fixture_unpaused().await;
    tokio::time::pause();
    let h = issue(&state);
    let mut s = open(&state, request(STREAM, Who::Cookie(&h), None)).await;
    // Nobody reads: `hello` fills the one-frame channel and the first `status`
    // frame waits for room. Parking in 1 ms steps lets the runtime run it; 100
    // virtual ms stay inside the 1 s before any re-check tick.
    let hub = state.dashboard_bootstrap.stream_hub();
    for _ in 0..100 {
        if hub.sends_awaiting_room() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        hub.sends_awaiting_room(),
        1,
        "the write is pending, not delivered"
    );
    let out = Request::builder()
        .method("POST")
        .uri("/dashboard/logout")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={h}"))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_346))))
        .body(Body::empty())
        .unwrap();
    let _ = create_router(Arc::clone(&state))
        .oneshot(out)
        .await
        .unwrap();
    assert_eq!(s.next().await.expect("hello").event, "hello");
    let next = s.next().await;
    assert!(next.is_none(), "a revoked viewer got {next:?}");
}

#[tokio::test]
async fn a_credential_check_that_never_answers_ends_the_stream_within_its_deadline() {
    let (state, _dir) = fixture().await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    s.until("status").await;
    state
        .dashboard_bootstrap
        .stream_hub()
        .hang_validation_for_test(true);
    let bound = Duration::from_secs(5);
    assert!(s.ended_within(bound).await, "ended within {bound:?}");
}

/// A non-admin key's first status frame is the counts-only view, key for
/// key: none of the full view's fields (server rows, tool count, totals,
/// call windows) reach it, as `GET /ui/api/status` withholds them too.
#[tokio::test]
async fn a_non_admin_stream_status_frame_has_only_the_counts_view_keys() {
    let (state, _dir) = fixture().await;
    let mut s = open(&state, request(STREAM, Who::Bearer(KEY), None)).await;
    assert_eq!(s.status, StatusCode::OK);
    assert_eq!(
        s.until("hello").await.json()["kinds"],
        serde_json::json!(["status"])
    );
    let status = s.until("status").await.json();
    let mut keys: Vec<&str> = status
        .as_object()
        .expect("a status frame is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "auth",
            "degraded_count",
            "healthy_count",
            "server_count",
            "uptime_secs",
            "version"
        ],
        "{status}"
    );
}
