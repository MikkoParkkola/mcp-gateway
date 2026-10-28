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
