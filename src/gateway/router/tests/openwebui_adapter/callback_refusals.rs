// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Callback refusals before any exchange (design §6.2 steps 1-6, §7): binding,
//! expiry, replay, races, issuer, config change, provider errors, BC-2, the
//! oversize-state cap and T-GUARD2.

use std::time::Duration;

use super::*;

/// T-C02c: the right state with a swapped or missing binding cookie fails
/// the journey terminally; the right cookie afterwards is refused too.
#[tokio::test(flavor = "multi_thread")]
async fn t_c02c_swapped_binding_is_terminal_and_exchanges_nothing() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let alice = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    let bob = begin(&gw, BOB, BOB_TOKEN, WORK).await;
    // WHEN
    let swapped = callback(&gw, &code_query(&alice), &[&bob.cookie]).await;
    let retried = complete(&gw, &alice).await;
    let bare = callback(&gw, &code_query(&bob), &[]).await;
    // THEN
    assert_outcome(&swapped, "browser_mismatch");
    assert!(!retried.2.contains("connected"), "{}", retried.2);
    assert_outcome(&bare, "browser_mismatch");
    for (subject, flow) in [(ALICE, &alice), (BOB, &bob)] {
        let status = journey_status(&gw, subject, &flow.id).await;
        assert_eq!(status["status"], "failed");
        assert_eq!(status["reason"], "browser_mismatch");
    }
    assert!(gw.fixture.exchanges().is_empty());
}

/// T-C03a, T-R3-2: a first callback after `callback_by` is an expiry, never
/// a replay, and exchanges nothing.
#[tokio::test(flavor = "multi_thread")]
async fn t_c03a_late_first_callback_is_expired_not_replayed() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let flow = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    gw.fixture.advance(601);
    // WHEN
    let outcome = complete(&gw, &flow).await;
    // THEN
    assert_outcome(&outcome, "expired");
    let status = journey_status(&gw, ALICE, &flow.id).await;
    assert_eq!(status["status"], "expired");
    assert_eq!(status["replay_refused"], false);
    assert_eq!(status["replay_refusals"], 0);
    assert!(gw.fixture.exchanges().is_empty());
    assert_eq!(gw.fixture.state(&key_of(&gw, ALICE, WORK)).await, "absent");
}

/// T-C03b, T-R2-3: the same callback URL again, even past `callback_by`, is
/// a replay; the journey stays connected and nothing is exchanged again.
#[tokio::test(flavor = "multi_thread")]
async fn t_c03b_replay_after_connect_keeps_connected_and_exchanges_once() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let flow = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    assert_outcome(&complete(&gw, &flow).await, "connected");
    gw.fixture.advance(601);
    // WHEN
    let replay = complete(&gw, &flow).await;
    // THEN
    assert_outcome(&replay, "already used");
    let status = journey_status(&gw, ALICE, &flow.id).await;
    assert_eq!(status["status"], "connected");
    assert_eq!(status["replay_refused"], true);
    assert_eq!(status["replay_refusals"], 1);
    assert_eq!(gw.fixture.exchanges().len(), 1);
}

/// T-C03c: two concurrent callbacks, the first held at `/token`: exactly one
/// exchange, and the other is refused as a replay.
#[tokio::test(flavor = "multi_thread")]
async fn t_c03c_racing_callbacks_exchange_exactly_once() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let flow = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    let hold = gw.fixture.token.hold();
    let first = tokio::spawn(
        gw.router
            .clone()
            .oneshot(callback_request(&code_query(&flow), &[&flow.cookie])),
    );
    tokio::time::timeout(Duration::from_secs(5), hold.entered.notified())
        .await
        .expect("first callback reached /token");
    // WHEN
    let second = complete(&gw, &flow).await;
    hold.release.notify_one();
    let first = tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .expect("held callback finished")
        .unwrap()
        .unwrap();
    // THEN
    assert_outcome(&second, "already used");
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(gw.fixture.exchanges().len(), 1);
    assert_eq!(
        journey_status(&gw, ALICE, &flow.id).await["status"],
        "connected"
    );
}

/// T-C03e: an `iss` naming another issuer, and a descriptor replaced by a
/// reload between start and callback, both fail before any exchange.
#[tokio::test(flavor = "multi_thread")]
async fn t_c03e_wrong_issuer_or_changed_config_never_exchanges() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let mixed_up = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    let reloaded = begin(&gw, ALICE, ALICE_TOKEN, HOME).await;
    let mut config = gw.config.clone();
    let descriptors = config
        .accounts
        .as_mut()
        .unwrap()
        .descriptors
        .as_mut()
        .unwrap();
    descriptors.get_mut(HOME).unwrap().redirect_uri =
        Some("https://chat.fixture.test/accounts/v1/callback?v=2".into());
    // WHEN
    let query = format!("{}&iss=https://evil.example", code_query(&mixed_up));
    let issuer = callback(&gw, &query, &[&mixed_up.cookie]).await;
    gw.state.live_config.set(config);
    let changed = complete(&gw, &reloaded).await;
    // THEN
    assert_outcome(&issuer, "issuer_mismatch");
    assert_outcome(&changed, "config_changed");
    assert!(!issuer.2.contains("evil.example"), "{}", issuer.2);
    assert_eq!(
        journey_status(&gw, ALICE, &mixed_up.id).await["reason"],
        "issuer_mismatch"
    );
    assert_eq!(
        journey_status(&gw, ALICE, &reloaded.id).await["reason"],
        "config_changed"
    );
    assert!(gw.fixture.exchanges().is_empty());
}

/// T-C04a: declining on a connected account cancels the journey and leaves
/// the grant untouched; the provider's description reaches no surface.
#[tokio::test(flavor = "current_thread")]
async fn t_c04a_access_denied_cancels_and_keeps_the_existing_grant() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let first = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    assert_outcome(&complete(&gw, &first).await, "connected");
    let flow = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    let marker = "MARKER-provider-text-2b9c";
    let (captured, guard) = capture();
    // WHEN
    let query = format!(
        "error=access_denied&error_description={marker}&error_uri=https://x.test/{marker}&state={}",
        flow.state
    );
    let outcome = callback(&gw, &query, &[&flow.cookie]).await;
    drop(guard);
    // THEN
    assert_outcome(&outcome, "user_denied");
    let status = journey_status(&gw, ALICE, &flow.id).await;
    assert_eq!(status["status"], "cancelled");
    assert_eq!(status["reason"], "user_denied");
    let token = gw.fixture.access_token(&key_of(&gw, ALICE, WORK)).await;
    assert_eq!(token.as_deref(), Some("fresh-access-1-9e4a"));
    assert_eq!(gw.fixture.exchanges().len(), 1);
    let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    for surface in [
        format!("{:?}{}", outcome.1, outcome.2),
        status.to_string(),
        logs,
    ] {
        assert!(!surface.contains(marker), "{surface}");
    }
}

/// T-C04b: `server_error` and an unrecognised code fail with closed reasons;
/// the raw code is matched, never echoed.
#[tokio::test(flavor = "multi_thread")]
async fn t_c04b_provider_errors_map_to_closed_reasons() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let busy = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    let odd = begin(&gw, ALICE, ALICE_TOKEN, HOME).await;
    // WHEN
    let busy_query = format!("error=server_error&state={}", busy.state);
    let unavailable = callback(&gw, &busy_query, &[&busy.cookie]).await;
    let odd_query = format!("error=weird_code_4d1f&state={}", odd.state);
    let unrecognised = callback(&gw, &odd_query, &[&odd.cookie]).await;
    // THEN
    assert_outcome(&unavailable, "provider_unavailable");
    assert_outcome(&unrecognised, "provider_error");
    assert!(
        !unrecognised.2.contains("weird_code_4d1f"),
        "{}",
        unrecognised.2
    );
    for (flow, reason) in [(&busy, "provider_unavailable"), (&odd, "provider_error")] {
        let status = journey_status(&gw, ALICE, &flow.id).await;
        assert_eq!(status["status"], "failed");
        assert_eq!(status["reason"], reason);
    }
    assert!(gw.fixture.exchanges().is_empty());
}

/// T-BC2: declined and never-attempted are both `Absent` in the store; the
/// status API tells them apart.
#[tokio::test(flavor = "multi_thread")]
async fn t_bc2_declined_is_distinguishable_from_never_attempted() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let flow = begin(&gw, BOB, BOB_TOKEN, WORK).await;
    // WHEN
    let query = format!("error=access_denied&state={}", flow.state);
    assert_outcome(&callback(&gw, &query, &[&flow.cookie]).await, "user_denied");
    let declined = journey_status(&gw, BOB, &flow.id).await;
    let never = journey_status(&gw, BOB, &"0".repeat(32)).await;
    // THEN
    assert_eq!(declined["status"], "cancelled");
    assert_eq!(never["error"]["code"], "not_found");
    assert_eq!(gw.fixture.state(&key_of(&gw, BOB, WORK)).await, "absent");
    assert_eq!(gw.fixture.state(&key_of(&gw, BOB, HOME)).await, "absent");
}

/// Review finding: a `state` or binding cookie longer than 64 characters is
/// refused before any store work, so an attacker-sized value is never
/// HMAC'd under the authority lock. The positive control proves the probe
/// sees the callback's store acquisitions at all.
#[tokio::test(flavor = "multi_thread")]
async fn oversize_state_or_binding_is_refused_before_any_store_call() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let flow = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    let long_state = format!("code={CODE}&state={}", "s".repeat(65));
    let long_cookie = format!("__Secure-mcpgw-journey-{}={}", flow.id, "b".repeat(65));
    // WHEN
    let recording = gw.fixture.watch_store();
    let by_state = callback(&gw, &long_state, &[&flow.cookie]).await;
    let by_cookie = callback(&gw, &code_query(&flow), &[&long_cookie]).await;
    let untouched = recording.ops();
    let control = callback(&gw, &format!("code={CODE}&state={}", "s".repeat(43)), &[]).await;
    let touched = recording.ops();
    drop(recording);
    // THEN
    for refused in [&by_state, &by_cookie, &control] {
        assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{}", refused.2);
        assert_hardened_page(&refused.1, &refused.2);
    }
    assert!(untouched.is_empty(), "store reached: {untouched:?}");
    assert!(
        !touched.is_empty(),
        "positive control: the probe sees callbacks"
    );
    assert_eq!(
        journey_status(&gw, ALICE, &flow.id).await["status"],
        "started"
    );
    assert!(gw.fixture.exchanges().is_empty());
}

/// T-GUARD2: the callback is the landing step (200, no 3xx, asserted by every
/// row here), while a cross-site navigation straight to `/complete` is still
/// refused by the origin guard.
#[tokio::test(flavor = "multi_thread")]
async fn t_guard2_complete_is_not_exempt_from_the_origin_guard() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let request = |site: &str| {
        Request::get(COMPLETE)
            .header("host", HOSTED_HOST)
            .header("sec-fetch-site", site)
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-dest", "document")
            .header("cookie", cookie_of(ALICE_TOKEN))
            .body(Body::empty())
            .unwrap()
    };
    // WHEN
    let cross = send(&gw, request("cross-site")).await;
    let same = send(&gw, request("same-origin")).await;
    // THEN
    assert_eq!(cross.0, StatusCode::FORBIDDEN, "{}", cross.2);
    assert_eq!(same.0, StatusCode::OK, "positive control: {}", same.2);
    assert_hardened_page(&same.1, &same.2);
}
