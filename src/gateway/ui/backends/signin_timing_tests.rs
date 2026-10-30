// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The sign-in flow's two windows on a paused Tokio clock: start to callback
//! (300 s) and callback to confirm (`SIGN_IN_CONFIRM_WINDOW`, 60 s). Each row
//! sets up with the real clock and real sockets, then pauses and advances;
//! none waits on a wall-clock window.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use tokio::sync::Notify;

use super::fixture::{Forms, Gw, Who};
use crate::oauth::client::sign_in::SIGN_IN_CONFIRM_WINDOW;

const START_WINDOW: Duration = Duration::from_secs(300);

/// Move the paused clock on and let every woken task run.
async fn pass(by: Duration) {
    tokio::time::advance(by).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

/// A token endpoint that answers only once `release` is notified: the
/// exchange, held for as long as a test needs.
async fn gated_token_endpoint() -> (String, Arc<Notify>) {
    use axum::{Json, Router, routing::post};
    let release = Arc::new(Notify::new());
    let held = Arc::clone(&release);
    let app = Router::new().route(
        "/token",
        post(move || {
            let held = Arc::clone(&held);
            async move {
                held.notified().await;
                Json(serde_json::json!({
                    "access_token": "access-a", "token_type": "Bearer", "expires_in": 3600,
                }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    (base, release)
}

/// A flow started by `owner` and approved, on the real clock; the clock is
/// paused on return. Returns the attempt id.
async fn approved_then_paused(gw: &Gw, owner: &Who) -> String {
    let reply = gw.start(owner).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let (url, attempt) = Gw::link(&reply);
    gw.approve(&url).await;
    tokio::time::pause();
    attempt
}

fn secs(reply_body: &serde_json::Value) -> u64 {
    reply_body["retry_after_secs"].as_u64().unwrap_or(u64::MAX)
}

// T1
#[tokio::test]
async fn start_to_callback_ends_at_300s() {
    let gw = Gw::new().await;
    let owner = gw.session();
    assert_eq!(gw.start(&owner).await.status, StatusCode::OK);
    tokio::time::pause();

    pass(START_WINDOW - Duration::from_secs(1)).await;
    assert_eq!(gw.row().await["sign_in_flow"]["phase"], "awaiting_callback");
    pass(Duration::from_secs(2)).await;

    assert!(
        gw.row().await["sign_in_flow"].is_null(),
        "no callback by 300 s ends the flow"
    );
    assert_eq!(
        gw.start(&owner).await.status,
        StatusCode::OK,
        "the gate is released"
    );
}

// T2
#[tokio::test]
async fn confirm_at_61s_after_the_callback_is_refused() {
    let gw = Gw::new().await;
    let owner = gw.session();
    let attempt = approved_then_paused(&gw, &owner).await;

    pass(SIGN_IN_CONFIRM_WINDOW + Duration::from_secs(1)).await;
    let reply = gw.confirm(&owner, &attempt, "confirm").await;

    assert_eq!(reply.status, StatusCode::NOT_FOUND, "{}", reply.body);
    assert_eq!(reply.json()["error"], "no_sign_in");
    assert!(gw.saved().is_none() && gw.row().await["sign_in_flow"].is_null());
    assert_eq!(
        gw.start(&owner).await.status,
        StatusCode::OK,
        "the gate is released"
    );
}

// T2b: expiry alone, with no confirm sent, ends the flow and frees the gate.
#[tokio::test]
async fn expiry_alone_discards_the_grant_and_releases_the_gate() {
    let gw = Gw::new().await;
    let owner = gw.session();
    let _ = approved_then_paused(&gw, &owner).await;

    pass(SIGN_IN_CONFIRM_WINDOW).await;

    assert!(
        gw.row().await["sign_in_flow"].is_null(),
        "the flow record is empty"
    );
    assert!(gw.saved().is_none());
    assert_eq!(
        gw.start(&owner).await.status,
        StatusCode::OK,
        "a new start succeeds"
    );
}

// T3
#[tokio::test]
async fn confirm_at_59s_after_the_callback_saves() {
    let gw = Gw::new().await;
    let owner = gw.session();
    let attempt = approved_then_paused(&gw, &owner).await;

    pass(Duration::from_secs(59)).await;
    let reply = gw.confirm(&owner, &attempt, "confirm").await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(gw.saved().is_some());
}

// T5: retry_after_secs, expires_at and the read's `until` agree exactly at
// three points; a constant 60 fails the first and the third.
#[tokio::test]
async fn retry_after_follows_the_confirm_window() {
    let gw = Gw::new().await;
    let owner = gw.session();
    let reply = gw.start(&owner).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let (url, _) = Gw::link(&reply);
    tokio::time::pause();
    let before = gw.start(&gw.session()).await.json();
    assert_eq!(secs(&before), START_WINDOW.as_secs(), "{before}");
    assert_eq!(
        before["expires_at"],
        gw.row().await["sign_in_flow"]["until"]
    );

    tokio::time::resume();
    gw.approve(&url).await;
    tokio::time::pause();
    let right_after = gw.start(&gw.session()).await.json();
    assert_eq!(
        secs(&right_after),
        SIGN_IN_CONFIRM_WINDOW.as_secs(),
        "{right_after}"
    );
    pass(Duration::from_secs(30)).await;
    let later = gw.start(&gw.session()).await.json();
    assert_eq!(secs(&later), 30, "{later}");
    assert_eq!(later["expires_at"], gw.row().await["sign_in_flow"]["until"]);
}

// T6: a CLI login holds the gate and reports its own deadline.
#[tokio::test]
async fn a_cli_held_gate_reports_its_own_deadline() {
    use crate::oauth::client::authorize_tests::client;
    let gw = Gw::new().await;
    let mut cli = client(gw.store.path(), Some(&gw.issuer))
        .with_login_gate(Arc::clone(&gw.backend.login_gate))
        .with_open_browser(Arc::new(|_: &str| true));
    tokio::spawn(async move { cli.authorize().await });
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }

    let reply = gw.start(&gw.session()).await;

    assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
    let body = reply.json();
    assert_eq!(body["error"], "sign_in_in_progress");
    assert_eq!(body["owner"], "gateway");
    assert!(
        secs(&body) > 0 && secs(&body) <= START_WINDOW.as_secs(),
        "{body}"
    );
}

/// A flow over a gated token endpoint, started by `owner`; the clock is
/// paused on return.
struct Gated {
    gw: Arc<Gw>,
    owner: Who,
    url: String,
    attempt: String,
    release: Arc<Notify>,
}

async fn gated_flow() -> Gated {
    let (issuer, release) = gated_token_endpoint().await;
    let gw = Arc::new(Gw::over(issuer, Forms::default()).await);
    let owner = gw.session();
    let reply = gw.start(&owner).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let (url, attempt) = Gw::link(&reply);
    tokio::time::pause();
    Gated {
        gw,
        owner,
        url,
        attempt,
        release,
    }
}

impl Gated {
    /// The person approving in the background: the callback answers only
    /// after the held exchange.
    fn approve_in_background(&self) {
        let (gw, url) = (Arc::clone(&self.gw), self.url.clone());
        tokio::spawn(async move { gw.approve(&url).await });
    }
}

// T4: the callback lands at 299 s and the exchange takes 20 s; the window runs
// from the callback, so a window measured from the exchange would accept
// callback + 61 s and fail the last case.
#[tokio::test]
async fn a_callback_near_300s_still_gets_60s_to_confirm() {
    for (after_exchange, expect) in [
        (0, StatusCode::OK),
        (39, StatusCode::OK),
        (41, StatusCode::NOT_FOUND),
    ] {
        let flow = gated_flow().await;
        pass(Duration::from_secs(299)).await;
        flow.approve_in_background();
        pass(Duration::from_secs(20)).await;
        flow.release.notify_one();
        pass(Duration::from_secs(after_exchange)).await;

        let reply = flow.gw.confirm(&flow.owner, &flow.attempt, "confirm").await;

        assert_eq!(
            reply.status, expect,
            "exchange + {after_exchange}s: {}",
            reply.body
        );
    }
}

// T7: one outcome wins, at most one save, and the gate is released once.
#[tokio::test]
async fn confirm_cancel_and_expiry_race_on_one_attempt() {
    let flow = gated_flow().await;
    tokio::time::resume();
    flow.release.notify_one();
    flow.gw.approve(&flow.url).await;
    tokio::time::pause();
    pass(SIGN_IN_CONFIRM_WINDOW - Duration::from_millis(1)).await;

    let (confirm, cancel, ()) = tokio::join!(
        flow.gw.confirm(&flow.owner, &flow.attempt, "confirm"),
        flow.gw.confirm(&flow.owner, &flow.attempt, "cancel"),
        pass(Duration::from_millis(1)),
    );

    let won = [confirm.status, cancel.status]
        .iter()
        .filter(|s| **s == StatusCode::OK)
        .count();
    assert!(
        won <= 1,
        "exactly one outcome wins: {} / {}",
        confirm.body,
        cancel.body
    );
    assert_eq!(
        flow.gw.saved().is_some(),
        confirm.status == StatusCode::OK,
        "a save only for a won confirm"
    );
    assert_eq!(
        flow.gw.start(&flow.owner).await.status,
        StatusCode::OK,
        "the gate is released"
    );
    assert_eq!(
        flow.gw.start(&flow.owner).await.status,
        StatusCode::CONFLICT,
        "and only once"
    );
}

// T8: an exchange still running when callback + 60 s passes saves nothing.
#[tokio::test]
async fn an_exchange_still_running_at_the_confirm_deadline_saves_nothing() {
    let flow = gated_flow().await;
    flow.approve_in_background();
    pass(Duration::from_secs(30)).await;
    let during = flow.gw.start(&flow.gw.session()).await.json();
    assert_eq!(
        secs(&during),
        30,
        "the second start follows the confirm window: {during}"
    );

    pass(SIGN_IN_CONFIRM_WINDOW).await;
    flow.release.notify_one();
    pass(Duration::from_secs(1)).await;

    let reply = flow.gw.confirm(&flow.owner, &flow.attempt, "confirm").await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND, "{}", reply.body);
    assert!(flow.gw.saved().is_none(), "the late exchange saved nothing");
    assert_eq!(flow.gw.start(&flow.owner).await.status, StatusCode::OK);
}
