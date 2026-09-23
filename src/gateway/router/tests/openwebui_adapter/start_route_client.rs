// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T-BRIDGE-*: the session client's rules on a real socket, plus T-COOKIE,
//! the start rate page, the expired page and the never-leak rule (§4.3).

use std::time::{Duration, Instant};

use axum::http::{StatusCode, header};

use super::super::fake_owui::session_body;
use super::*;

/// T-BRIDGE-REDIRECT: a 302 is refused, not followed; the target, which
/// would have answered a valid session, receives nothing.
#[tokio::test]
async fn bridge_redirect_is_not_followed() {
    // GIVEN
    let target = FakeOwui::start(users(), Answer::Session).await;
    let owui = FakeOwui::start(users(), Answer::Redirect(target.url.clone())).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    // WHEN / THEN
    assert_refused_like_sign_in(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    assert_eq!(owui.seen().len(), 1);
    assert!(target.seen().is_empty(), "{:?}", target.seen());
}

/// T-BRIDGE-STATUS: only 200 is a session, whatever the body says.
#[tokio::test]
async fn bridge_refuses_every_status_but_200() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    let valid = session_body(&users()[0]);
    // WHEN / THEN
    for status in [201, 204, 401, 500] {
        owui.answer(Answer::Fixed(status, valid.clone()));
        assert_refused_like_sign_in(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    }
    owui.answer(Answer::Fixed(200, valid));
    let (status, _, body) = start(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "positive control: {body}");
}

/// A valid session body padded to exactly `len` bytes.
fn padded_body(len: usize) -> String {
    let base = session_body(&users()[0]);
    let head = base.strip_suffix('}').unwrap();
    let frame = format!("{head},\"pad\":\"\"}}").len();
    format!("{head},\"pad\":\"{}\"}}", "x".repeat(len - frame))
}

/// T-BRIDGE-SIZE: 64 KiB is read whole; one byte more is refused, never
/// truncated. The extra byte is trailing whitespace, so a truncating read
/// would still parse: only the cap refuses it.
#[tokio::test]
async fn bridge_caps_the_body_at_64_kib_without_truncating() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    let exact = padded_body(64 * 1024);
    assert_eq!(exact.len(), 65_536);
    // WHEN / THEN
    owui.answer(Answer::Fixed(200, format!("{exact} ")));
    assert_refused_like_sign_in(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    owui.answer(Answer::Fixed(200, exact));
    let (status, _, body) = start(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "exactly 64 KiB: {body}");
}

/// T-BRIDGE-TIMEOUT: a session endpoint that answers after 8 s is refused at
/// about 5 s.
#[tokio::test]
async fn bridge_times_out_at_five_seconds() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Slow(Duration::from_secs(8))).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    // WHEN
    let began = Instant::now();
    let response = start(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    let elapsed = began.elapsed();
    // THEN
    assert_no_start(&response);
    assert!(elapsed >= Duration::from_millis(4500), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(7500), "{elapsed:?}");
    assert_eq!(journey_status(&gw, ALICE, &id).await["status"], "pending");
}

/// T-COOKIE (start half): two parallel journeys in one browser get two
/// cookies, each named for its own journey, and both stay started.
#[tokio::test]
async fn parallel_journeys_get_distinct_binding_cookies() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let work = create(&gw, ALICE, WORK).await;
    let home = create(&gw, ALICE, HOME).await;
    // WHEN
    let (work_status, work_headers, _) = start(&gw, &work, &[&cookie_of(ALICE_TOKEN)]).await;
    let (home_status, home_headers, _) = start(&gw, &home, &[&cookie_of(ALICE_TOKEN)]).await;
    // THEN
    assert_eq!(
        (work_status, home_status),
        (StatusCode::SEE_OTHER, StatusCode::SEE_OTHER)
    );
    let (work_name, work_value, _) = binding_cookie(&work_headers);
    let (home_name, home_value, _) = binding_cookie(&home_headers);
    assert_eq!(work_name, format!("__Secure-mcpgw-journey-{work}"));
    assert_eq!(home_name, format!("__Secure-mcpgw-journey-{home}"));
    assert_ne!(work_value, home_value);
    for id in [&work, &home] {
        assert_eq!(journey_status(&gw, ALICE, id).await["status"], "started");
    }
}

/// A re-start rotates the binding and keeps `callback_by` (§3): Max-Age
/// counts down to the same deadline, never re-extends it.
#[tokio::test]
async fn restart_rotates_binding_and_keeps_the_deadline() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    let (_, first, _) = start(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    let deadline = journey_status(&gw, ALICE, &id).await["expires_at"].clone();
    let deadline = deadline.as_u64().unwrap();
    // Cross a second boundary, so a re-extended deadline or a constant
    // Max-Age of 600 cannot pass.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    // WHEN
    let before = unix_now();
    let (status, second, _) = start(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    let after = unix_now();
    // THEN
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_ne!(binding_cookie(&first).1, binding_cookie(&second).1);
    assert_eq!(
        journey_status(&gw, ALICE, &id).await["expires_at"],
        deadline
    );
    let line = binding_cookie(&second).2;
    let max_age: u64 = line.rsplit("Max-Age=").next().unwrap().parse().unwrap();
    assert!(
        (deadline - after..=deadline - before).contains(&max_age),
        "{line}"
    );
}

/// Starts are rate limited per user (§5.3): past the limit, a retry page with
/// `Retry-After`, no redirect and no cookie.
#[tokio::test]
async fn start_past_the_rate_renders_the_retry_page() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = gateway(&owui, 1).await;
    let id = create(&gw, ALICE, WORK).await;
    let (first, _, _) = start(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    // WHEN
    let response = start(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    // THEN
    assert_eq!(first, StatusCode::SEE_OTHER);
    assert_eq!(response.0, StatusCode::TOO_MANY_REQUESTS);
    assert_no_start(&response);
    let retry: u64 = response.1[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&retry), "{retry}");
}

/// Step 1 before step 2: a journey id the store does not hold renders the
/// expired page and Open `WebUI` is never asked; it differs from sign-in.
#[tokio::test]
async fn start_of_absent_journey_renders_expired_page_without_asking_owui() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    let sign_in = sign_in_page(&gw, &id).await;
    let absent = "0123456789abcdef0123456789abcdef";
    // WHEN
    let response = start(&gw, absent, &[&cookie_of(ALICE_TOKEN)]).await;
    // THEN
    assert_no_start(&response);
    assert_eq!(response.0, StatusCode::NOT_FOUND);
    assert_ne!(response.2, sign_in.1);
    assert!(owui.seen().is_empty(), "{:?}", owui.seen());
}

/// §4.3 never-leak: the session token and the profile fields Open `WebUI`
/// echoes appear in no log line, page, `Location` or cookie.
#[tokio::test(flavor = "current_thread")]
async fn bridge_never_leaks_the_session_token_or_profile_fields() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    let (captured, guard) = capture();
    // WHEN
    let ok = start(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    let refused = start(&gw, &id, &[&cookie_of(BOB_TOKEN)]).await;
    drop(guard);
    // THEN
    assert_eq!(ok.0, StatusCode::SEE_OTHER);
    let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("/accounts/v1/journeys/{id}/start"),
        "positive control: {logs}"
    );
    let surfaces = [
        format!("{:?}{}", ok.1, ok.2),
        format!("{:?}{}", refused.1, refused.2),
        logs,
    ];
    for secret in [
        ALICE_TOKEN,
        BOB_TOKEN,
        "SECRET@example.test",
        "Synthetic User",
    ] {
        for surface in &surfaces {
            assert!(!surface.contains(secret), "{secret} leaked: {surface}");
        }
    }
}
