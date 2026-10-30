// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Sign-in rows whose claim is about the token exchange, on the real clock.
//! The windows come through the backend's own sign-in windows, the same path
//! production reads; a row that expires mid-exchange uses a short window and
//! releases the held exchange only after it has observed the expired state,
//! and a row that completes inside its window uses a generous one. Nothing
//! sleeps for a fixed span and nothing pauses time.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use tokio::sync::Notify;

use super::fixture::{Forms, Gw, Who};
use super::timing_tests::gated_token_endpoint;
use crate::backend::sign_in_flow::SignInWindows;
use crate::test_wait::HANG_BOUND;

/// A flow over a gated token endpoint, started by `owner` under `windows`.
struct Flow {
    gw: Arc<Gw>,
    owner: Who,
    url: String,
    attempt: String,
    release: Arc<Notify>,
}

async fn flow_under(windows: SignInWindows) -> Flow {
    let (issuer, release) = gated_token_endpoint().await;
    let gw = Arc::new(Gw::over(issuer, Forms::default()).await);
    gw.backend.set_sign_in_windows_for_test(windows);
    let owner = gw.session();
    let reply = gw.start(&owner).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let (url, attempt) = Gw::link(&reply);
    Flow {
        gw,
        owner,
        url,
        attempt,
        release,
    }
}

impl Flow {
    /// The person approving in the background: the callback answers only
    /// after the held exchange.
    fn approve_in_background(&self) {
        let (gw, url) = (Arc::clone(&self.gw), self.url.clone());
        tokio::spawn(async move { gw.approve(&url).await });
    }

    /// Poll the read, yielding between looks, until the flow is in `phase`.
    async fn until_phase(&self, phase: &str) -> serde_json::Value {
        let began = std::time::Instant::now();
        while began.elapsed() < HANG_BOUND {
            let seen = self.gw.row().await["sign_in_flow"].clone();
            if seen["phase"] == phase {
                return seen;
            }
            tokio::task::yield_now().await;
        }
        panic!("the flow never reached {phase}");
    }

    /// Poll the read, yielding between looks, until no flow is in flight.
    async fn until_gone(&self) {
        let began = std::time::Instant::now();
        while began.elapsed() < HANG_BOUND {
            if self.gw.row().await["sign_in_flow"].is_null() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("the flow never ended");
    }
}

fn windows(start: u64, confirm: u64) -> SignInWindows {
    SignInWindows {
        start: Duration::from_secs(start),
        confirm: Duration::from_secs(confirm),
    }
}

fn parse(until: &serde_json::Value) -> chrono::DateTime<chrono::FixedOffset> {
    chrono::DateTime::parse_from_rfc3339(until.as_str().unwrap_or_default())
        .expect("until is RFC 3339")
}

// T4, completes inside the window: a delayed exchange still leaves the whole
// confirm window, counted from the callback.
#[tokio::test]
async fn a_delayed_exchange_inside_the_window_still_confirms() {
    let flow = flow_under(windows(60, 30)).await;
    flow.approve_in_background();
    flow.until_phase("awaiting_confirm").await;
    flow.release.notify_one();
    flow.gw.wait_until_held().await;

    let reply = flow.gw.confirm(&flow.owner, &flow.attempt, "confirm").await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
}

// T4, expires after the exchange: the window is counted from the callback, so
// once its stated end has passed a confirm is refused even though the
// exchange ended only moments before. A window counted from the exchange's
// end (M12) would still accept it.
#[tokio::test]
async fn the_window_counts_from_the_callback_not_the_exchange() {
    let flow = flow_under(windows(60, 2)).await;
    flow.approve_in_background();
    let confirming = flow.until_phase("awaiting_confirm").await;
    flow.release.notify_one();
    flow.gw.wait_until_held().await;
    let ends = parse(&confirming["until"]);
    let began = std::time::Instant::now();
    while chrono::Utc::now() < ends && began.elapsed() < HANG_BOUND {
        tokio::task::yield_now().await;
    }

    let reply = flow.gw.confirm(&flow.owner, &flow.attempt, "confirm").await;

    assert_eq!(reply.status, StatusCode::NOT_FOUND, "{}", reply.body);
    assert!(flow.gw.saved().is_none());
}

// T8: an exchange still running when the confirm window ends saves nothing.
#[tokio::test]
async fn an_exchange_still_running_at_the_confirm_deadline_saves_nothing() {
    let flow = flow_under(windows(60, 2)).await;
    flow.approve_in_background();
    flow.until_phase("awaiting_confirm").await;
    let during = flow.gw.start(&flow.gw.session()).await.json();
    let left = during["retry_after_secs"].as_u64().unwrap_or(u64::MAX);
    assert!(
        (1..=2).contains(&left),
        "the retry hint follows the window: {during}"
    );

    flow.until_gone().await;
    flow.release.notify_one();

    let reply = flow.gw.confirm(&flow.owner, &flow.attempt, "confirm").await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND, "{}", reply.body);
    assert!(flow.gw.saved().is_none(), "the late exchange saved nothing");
    assert_eq!(flow.gw.start(&flow.owner).await.status, StatusCode::OK);
}

// S9: the phase moves at the callback, before the exchange completes, and the
// read carries only `phase` and `until`.
#[tokio::test]
async fn the_flow_phase_moves_at_the_callback() {
    let flow = flow_under(windows(40, 30)).await;
    let waiting = flow.gw.row().await["sign_in_flow"].clone();
    assert_eq!(waiting["phase"], "awaiting_callback", "{waiting}");

    flow.approve_in_background();
    let confirming = flow.until_phase("awaiting_confirm").await;

    let keys = confirming.as_object().map_or(0, serde_json::Map::len);
    assert_eq!(keys, 2, "only `phase` and `until`: {confirming}");
    let gap = parse(&confirming["until"]) - parse(&waiting["until"]);
    let ten = chrono::Duration::seconds(10);
    let slack = chrono::Duration::from_std(HANG_BOUND).expect("a small bound");
    assert!(
        gap <= -ten + slack && gap >= -ten,
        "callback + 30 s against start + 40 s: {gap}"
    );
}
