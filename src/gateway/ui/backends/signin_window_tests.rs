// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Sign-in rows whose claim is about the token exchange, on the real clock.
//! The windows come through the backend's own sign-in windows, the same path
//! production reads; a row that expires mid-exchange uses a short window and
//! releases the held exchange only after it has observed the expired state,
//! and a row that completes inside its window uses a generous one. Polls
//! sleep a few milliseconds between looks at observed state, bounded by
//! `HANG_BOUND`, and nothing pauses time.

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
            tokio::time::sleep(Duration::from_millis(10)).await;
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
            tokio::time::sleep(Duration::from_millis(10)).await;
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
    while crate::clock::utc_now().expect("a readable clock") < ends && began.elapsed() < HANG_BOUND
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
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
    let ten = crate::duration_bound::delta!(seconds, 10);
    let slack = chrono::Duration::from_std(HANG_BOUND).expect("a small bound");
    assert!(
        gap <= -ten + slack && gap >= -ten,
        "callback + 30 s against start + 40 s: {gap}"
    );
}

// R17: the owner's cancel works before the callback, frees the gate, and a new
// sign-in then runs to a saved token. Mutant M21 refuses the early cancel.
#[tokio::test]
async fn the_owner_cancels_while_awaiting_the_callback_and_a_new_start_succeeds() {
    let gw = Gw::new().await;
    let owner = gw.session();
    let (_, first) = Gw::link(&gw.start(&owner).await);

    let cancel = gw.confirm(&owner, &first, "cancel").await;
    assert_eq!(cancel.status, StatusCode::OK, "{}", cancel.body);

    let (url, second) = Gw::link(&gw.start(&owner).await);
    let _ = gw.approve(&url).await;
    gw.wait_until_held().await;
    let confirm = gw.confirm(&owner, &second, "confirm").await;
    assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.body);
    assert!(gw.saved().is_some(), "the second sign-in saved its token");
}

// R18: a provider's late callback for a cancelled attempt reaches nothing: the
// cancelled login's listener is gone (the connection is refused), so there is
// no exchange, nothing saved, and the second flow keeps its own phase and the
// gate alone. Mutant M22 lets the late callback exchange.
#[tokio::test]
async fn a_late_callback_after_cancel_is_ignored() {
    let gw = Gw::new().await;
    let owner = gw.session();
    let (first_url, first) = Gw::link(&gw.start(&owner).await);
    let cancel = gw.confirm(&owner, &first, "cancel").await;
    assert_eq!(cancel.status, StatusCode::OK, "{}", cancel.body);
    let second = gw.start(&owner).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);

    let late = gw.try_approve(&first_url).await;

    assert!(
        late.is_none_or(|page| !page.contains("access-a") && !page.contains("fixture-code")),
        "a late callback shows no token and no code"
    );
    assert_eq!(gw.forms.lock().unwrap().len(), 0, "no exchange happened");
    assert!(gw.saved().is_none());
    let row = gw.row().await["sign_in_flow"].clone();
    assert_eq!(
        row["phase"], "awaiting_callback",
        "the second flow is untouched"
    );
    let third = gw.start(&owner).await;
    assert_eq!(
        third.status,
        StatusCode::CONFLICT,
        "the gate is the second flow's alone"
    );
}

// R19: a cancel that lands after the exchange has returned but before the
// flow task stores the grant wins. The cancel takes the flow out of the slot
// under the lock the task stores through, so the late grant has nowhere to go
// (mutant M23 leaves the flow in the slot, and the grant lands on it). The old
// task keeps the login gate until it ends, so no other attempt has a flow in
// the meantime: a start is refused until it resumes.
#[tokio::test]
async fn a_cancel_during_the_exchange_discards_the_token() {
    let gw = Arc::new(Gw::new().await);
    let owner = gw.session();
    let (reached, release) = gw.backend.sign_in.hold_pause.arm();
    let (url, attempt) = Gw::link(&gw.start(&owner).await);
    let _ = gw.approve(&url).await;
    crate::test_pause::within("the flow task reaches its hold", reached.notified()).await;

    // The cancel answers only once the gate reflects it, which waits for the
    // parked task: run it on a task of its own.
    let cancel = tokio::spawn({
        let (gw, owner) = (Arc::clone(&gw), owner.clone());
        async move { gw.confirm(&owner, &attempt, "cancel").await }
    });
    for _ in 0..500 {
        tokio::task::yield_now().await;
    }
    let blocked = gw.start(&owner).await;
    assert_eq!(
        blocked.status,
        StatusCode::CONFLICT,
        "the old task still holds the gate: {}",
        blocked.body
    );
    release.notify_one();
    let cancel = tokio::time::timeout(HANG_BOUND, cancel)
        .await
        .expect("the cancel answers")
        .expect("the request ran");
    assert_eq!(cancel.status, StatusCode::OK, "{}", cancel.body);
    let began = std::time::Instant::now();
    while gw.backend.login_gate.in_flight() && began.elapsed() < HANG_BOUND {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(
        gw.row().await["sign_in_flow"].is_null(),
        "no flow is left to hold the old token"
    );
    let held = gw
        .backend
        .with_flow(|slot| slot.as_ref().is_some_and(|f| f.grant.is_some()));
    assert!(!held, "a grant is held for the cancelled attempt");
    let began = std::time::Instant::now();
    let mut again = gw.start(&owner).await;
    while again.status != StatusCode::OK && began.elapsed() < HANG_BOUND {
        tokio::time::sleep(Duration::from_millis(10)).await;
        again = gw.start(&owner).await;
    }

    assert_eq!(
        again.status,
        StatusCode::OK,
        "the gate is free: {}",
        again.body
    );
    assert!(gw.saved().is_none(), "the old exchange saved nothing");
    let held = gw
        .backend
        .with_flow(|slot| slot.as_ref().map(|f| f.grant.is_some()));
    assert_eq!(
        held,
        Some(false),
        "the new flow holds no token from the old one"
    );
}

// The callback page of a UI-started sign-in tells the person to go back to the
// dashboard and confirm: closing the window would abandon an unsaved login.
// Red today: the page is the generic "you can close this window" one.
#[tokio::test]
async fn a_ui_callback_page_asks_for_confirmation() {
    let gw = Gw::new().await;
    let (url, _) = Gw::link(&gw.start(&gw.session()).await);

    let page = gw.approve(&url).await;

    assert!(
        page.to_lowercase()
            .contains("return to the dashboard and confirm"),
        "{page}"
    );
    assert!(!page.to_lowercase().contains("close this window"), "{page}");
}

// 14.4: the saved token carries the exchange's own expiry and lifetime, with
// time passing both before the grant enters `hold` and before the confirm. The
// thread's clock is set, not slept. Red today: the confirm stamps the expiry
// from the confirm-time clock.
#[tokio::test]
async fn a_confirmed_token_keeps_the_exchange_expiry() {
    let t0 = crate::clock::unix_secs().expect("a readable clock");
    let clock = crate::clock::test_clock::at_secs(t0);
    let gw = Gw::new().await;
    let owner = gw.session();
    let (reached, release) = gw.backend.sign_in.hold_pause.arm();
    let (url, attempt) = Gw::link(&gw.start(&owner).await);
    let _ = gw.approve(&url).await;
    crate::test_pause::within("the task reaches its hold", reached.notified()).await;
    drop(clock);
    let clock = crate::clock::test_clock::at_secs(t0 + 10);
    release.notify_one();
    gw.wait_until_held().await;
    drop(clock);
    let _clock = crate::clock::test_clock::at_secs(t0 + 30);

    let confirm = gw.confirm(&owner, &attempt, "confirm").await;

    assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.body);
    let saved = gw.saved().expect("the token is saved");
    assert_eq!(
        saved.expires_at,
        Some(t0 + 3600),
        "the exchange's own expiry"
    );
    assert_eq!(
        saved.lifetime_secs,
        Some(3600),
        "the exchange's own lifetime"
    );
}
