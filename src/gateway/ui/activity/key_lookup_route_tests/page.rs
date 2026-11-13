// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The sealed page token of the admin email lookup: whose it is, what opens
//! it, what spends it, and what a refusal looks like.

use super::*;

fn now_secs() -> u64 {
    crate::clock::unix_secs().expect("a test host clock reads after 1970")
}

fn refusal_of(
    fx: &Fx,
    who: AuthenticatedClient,
    token: &str,
) -> (StatusCode, Option<String>, Option<String>, Value) {
    let (status, cache, value) = fx.next_page(who, token, &json!({}));
    let retry = fx.retry_after.borrow().clone();
    (status, cache, retry, value)
}

/// A page token belongs to the credential principal it was minted for: another
/// admin presenting it is refused, and the refusal is the same fixed answer
/// every bad token gets.
/// Mutant: leave the principal out of the AAD or the redemption check.
#[test]
fn a_page_token_is_refused_to_another_principal_with_the_one_fixed_answer() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    let first = fx.lookup(EMAIL, &json!({"limit": 1}));
    let token = first["next_cursor"].as_str().expect("cursor").to_owned();
    let other = refusal_of(&fx, admin("b"), &token);
    assert_eq!(other.0, StatusCode::BAD_REQUEST, "{other:?}");
    let garbage = refusal_of(&fx, admin("a"), "not-a-token");
    assert_eq!(other, garbage, "a wrong principal must look like garbage");
    assert!(!other.3.to_string().contains(EMAIL));
}

/// Every way a token can fail to open gives one answer, byte for byte: status,
/// cache header, retry header and body. Tampered, garbage, empty, expired,
/// another purpose, another keyring, an old hash key id, an old hash version,
/// past the chain ceiling.
/// Mutant: a distinct message or status for any one cause.
#[test]
fn every_token_that_does_not_open_gets_the_same_answer() {
    use crate::protocol::continuation::{ContinuationPurpose, Keyring, Payload};
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    let who = admin("a");
    let now = now_secs();
    let good = fx.seal_by_hand(&who, &fx.scope(now), now);
    let mut tampered = good.clone();
    let last = tampered.pop().expect("a token");
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    // Past its own expiry but inside the chain ceiling, then far past both.
    let expired = fx.seal_by_hand(&who, &fx.scope(now - 400), now - 400);
    let long_gone = fx.seal_by_hand(&who, &fx.scope(now - 10_000), now - 10_000);
    let old_ceiling = {
        let mut scope = fx.scope(now - 1_000);
        scope.born = now - 1_000;
        fx.seal_by_hand(&who, &scope, now)
    };
    let mut wrong_key = fx.scope(now);
    wrong_key.key_id = "another-key".into();
    let mut wrong_version = fx.scope(now);
    wrong_version.version += 1;
    let preview = fx
        .state
        .continuation
        .keyring()
        .mint(&Payload::mint_preview(fingerprint(&who), "d".into(), now))
        .expect("a preview token");
    let other_ring = Keyring::new(&[(1, [9u8; 32])])
        .expect("a ring")
        .mint(&Payload::mint_lookup(
            fingerprint(&who),
            serde_json::to_string(&fx.scope(now)).expect("scope"),
            now,
        ))
        .expect("a token");
    // A lookup scope sealed under another purpose: the purpose is checked on
    // its own, not left to the missing scope of other purposes' tokens.
    let wrong_purpose = fx
        .state
        .continuation
        .keyring()
        .mint(
            &Payload::mint_lookup(
                fingerprint(&who),
                serde_json::to_string(&fx.scope(now)).expect("scope"),
                now,
            )
            .with_purpose(ContinuationPurpose::BackendInput),
        )
        .expect("a token");
    let tokens = [
        wrong_purpose,
        tampered,
        "garbage".to_owned(),
        String::new(),
        expired,
        long_gone,
        old_ceiling,
        fx.seal_by_hand(&who, &wrong_key, now),
        fx.seal_by_hand(&who, &wrong_version, now),
        preview,
        other_ring,
    ];
    let reference = refusal_of(&fx, who.clone(), "garbage");
    assert_eq!(reference.0, StatusCode::BAD_REQUEST, "{reference:?}");
    for token in &tokens {
        assert_eq!(
            refusal_of(&fx, who.clone(), token),
            reference,
            "a token that fails to open answered differently: {token}"
        );
    }
    // The good one still opens, so the rows above refused for their reasons.
    let (status, _, _) = fx.next_page(who, &good, &json!({}));
    assert_eq!(status, StatusCode::OK);
}

/// A page token carries the whole scope and gives it back: hash, version, key
/// id, window and log position survive seal and open for the same principal,
/// and `open` is opaque: `None` for another principal, an empty principal, or a
/// stale scope.
/// Mutant: drop the window from the scope, or open for any principal.
#[test]
fn seal_and_open_round_trip_the_scope_for_one_principal_only() {
    let fx = Fx::new();
    let who = admin("a");
    let now = now_secs();
    let mut scope = fx.scope(now);
    scope.from = Some("2000-01-01T00:00:00Z".into());
    scope.to = Some("2100-01-01T00:00:00Z".into());
    let token = fx.seal_by_hand(&who, &scope, now);
    let open = |principal: &str, token: &str| {
        super::super::key_lookup::open(&fx.state, principal, token, now, &fx.ks.email_key)
    };
    let got = open(&fingerprint(&who), &token)
        .expect("opens for its principal")
        .scope;
    assert_eq!(got.hash, scope.hash);
    assert_eq!(got.from, scope.from);
    assert_eq!(got.to, scope.to);
    assert_eq!(got.born, scope.born);
    assert!(open(&fingerprint(&admin("b")), &token).is_none());
    // Even a token the keyring sealed for the empty principal does not open
    // for it: the guard is `open`'s own, not a mismatch that happens to refuse.
    let for_nobody = fx
        .state
        .continuation
        .keyring()
        .mint(&crate::protocol::continuation::Payload::mint_lookup(
            String::new(),
            serde_json::to_string(&scope).expect("scope"),
            now,
        ))
        .expect("a token");
    assert!(
        open("", &for_nobody).is_none(),
        "an empty principal never opens"
    );
    assert!(open("", &token).is_none());
}

/// A caller with no credential principal gets a first page, but when a next
/// page would exist it is told no token can be issued (503, a fixed line), and
/// no token is minted. Mutant: mint a token bound to the empty principal.
#[test]
fn a_caller_without_a_principal_is_given_no_page_token() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    let mut nobody = admin("a");
    nobody.principal = crate::gateway::record_principal::InternalPrincipal::new(String::new());
    fx.state.process.lookup_budget().reset_for_test();
    let (status, _, body) = fx.post(
        nobody.clone(),
        &json!({"email": EMAIL, "limit": 1}).to_string(),
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.get("next_cursor").is_none(), "{body}");
    // And a last page needs no token, so it still answers.
    fx.state.process.lookup_budget().reset_for_test();
    let (status, _, body) = fx.post(nobody, &json!({"email": EMAIL, "limit": 10}).to_string());
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A page token is single use, and it is spent by the page it serves: a 429
/// (the budget is spent), leaves it redeemable; once a page has been answered
/// it is spent and the same token is refused with the fixed answer.
/// Mutant: never consume (replayable), or consume before the budget charge.
#[test]
fn a_token_is_spent_by_the_page_it_serves_and_not_by_a_throttle() {
    let fx = Fx::new();
    for subject in ["s1", "s2", "s3"] {
        fx.plant(subject, EMAIL, &fx.ks.email_key);
    }
    let first = fx.lookup(EMAIL, &json!({"limit": 1}));
    let token = first["next_cursor"].as_str().expect("cursor").to_owned();
    // Spend the whole budget, then ask with the token: a 429, token intact.
    let who = admin("a");
    let body = json!({"cursor": token, "limit": 1}).to_string();
    fx.state.process.lookup_budget().reset_for_test();
    loop {
        let (status, _, _) = fx.post(who.clone(), &json!({"email": "x@corp.invalid"}).to_string());
        if status == StatusCode::TOO_MANY_REQUESTS {
            break;
        }
    }
    let (status, _, throttled) = fx.post(who.clone(), &body);
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{throttled}");
    // Budget back: the same token serves a page once.
    fx.state.process.lookup_budget().reset_for_test();
    let (status, _, second) = fx.post(who.clone(), &body);
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(subjects(&second), vec!["s2"], "{second}");
    // And only once.
    let replay = refusal_of(&fx, who.clone(), &token);
    assert_eq!(replay, refusal_of(&fx, who, "garbage"), "{replay:?}");
}

/// A scan that fails (503) does not spend the token: the retry gets the page.
/// Unix only: the failure is a log file the process may not read.
/// Mutant: consume the token at open, before the scan.
#[cfg(unix)]
#[test]
fn a_failed_scan_leaves_the_token_redeemable() {
    use std::os::unix::fs::PermissionsExt as _;
    let fx = Fx::new();
    for subject in ["s1", "s2"] {
        fx.plant(subject, EMAIL, &fx.ks.email_key);
    }
    let first = fx.lookup(EMAIL, &json!({"limit": 1}));
    let token = first["next_cursor"].as_str().expect("cursor").to_owned();
    let files: Vec<_> = std::fs::read_dir(fx.dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_none_or(|x| x != "lock"))
        .collect();
    for f in &files {
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let (status, _, down) = fx.next_page(admin("a"), &token, &json!({"limit": 1}));
    for f in &files {
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{down}");
    let (status, _, again) = fx.next_page(admin("a"), &token, &json!({"limit": 1}));
    assert_eq!(status, StatusCode::OK, "the token was burned: {again}");
}

/// The order is pinned so a token cannot be probed through other errors: a
/// bad limit, or no key server, answers its own refusal BEFORE the token is
/// opened, whatever the token is.
/// Mutant: open the token before the limit check or the key-server check.
#[test]
fn every_refusal_that_is_not_about_the_token_comes_before_it_is_opened() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    let first = fx.lookup(EMAIL, &json!({"limit": 1}));
    let good = first["next_cursor"].as_str().expect("cursor").to_owned();
    let bad_limit = |token: &str| {
        fx.state.process.lookup_budget().reset_for_test();
        fx.post(
            admin("a"),
            &json!({"cursor": token, "limit": 0}).to_string(),
        )
    };
    let (s1, _, b1) = bad_limit(&good);
    let (s2, _, b2) = bad_limit("garbage");
    assert_eq!(
        (s1, &b1),
        (s2, &b2),
        "limit error must not depend on the token"
    );
    assert_eq!(s1, StatusCode::BAD_REQUEST);
    assert_ne!(
        b1,
        refusal_of(&fx, admin("a"), "garbage").3,
        "a bad limit and a bad token are different refusals"
    );
}

/// A page request is a lookup: it is charged to the shared budget before the
/// body is read, so a stolen token cannot dodge the throttle.
/// Mutant: skip the charge on a cursor request.
#[test]
fn a_cursor_request_is_charged_to_the_shared_budget() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    fx.state.process.lookup_budget().reset_for_test();
    let mut statuses = Vec::new();
    for _ in 0..4 {
        let (status, _, _) = fx.post(admin("a"), &json!({"cursor": "garbage"}).to_string());
        statuses.push(status);
    }
    assert_eq!(
        statuses,
        vec![
            StatusCode::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS
        ],
        "burst 2, then throttled, bad tokens included"
    );
}

/// Two requests that present one token at the same moment: both may scan (the
/// token is spent after its page is read, so a throttle or a failed read does
/// not burn it), but the ledger lets exactly one deliver. The other gets the
/// fixed refusal and its page is dropped. The cost of the race is one extra
/// read under the shared budget, bound to the same principal and the same
/// data; the loser learns nothing the winner did not.
/// Mutant: deliver on both (spend ignored), or deliver on neither.
#[test]
fn two_requests_with_one_token_deliver_exactly_one_page() {
    let fx = Fx::new();
    for subject in ["s1", "s2", "s3"] {
        fx.plant(subject, EMAIL, &fx.ks.email_key);
    }
    let first = fx.lookup(EMAIL, &json!({"limit": 1}));
    let token = first["next_cursor"].as_str().expect("cursor").to_owned();
    fx.state.process.lookup_budget().reset_for_test();
    let call = || {
        let request = Request::builder()
            .method("POST")
            .uri(routes::UI_KEY_SERVER_LOOKUP_EMAIL)
            .header("content-type", "application/json")
            .extension(fx.live.generation())
            .extension(admin("a"))
            .body(Body::from(json!({"cursor": token, "limit": 1}).to_string()))
            .expect("request");
        let router = crate::gateway::ui::api_router().with_state(fx.state.clone());
        async move { router.oneshot(request).await.expect("infallible").status() }
    };
    let (one, two) = fx.rt.block_on(async { tokio::join!(call(), call()) });
    let mut got = [one, two];
    got.sort();
    assert_eq!(
        got,
        [StatusCode::OK, StatusCode::BAD_REQUEST],
        "exactly one request delivers the page"
    );
}

/// Every dashboard session carries one constant principal, so a token bound to
/// it would open in any other browser session. A session binds to its own
/// cookie handle: another session's token is the fixed refusal, the same
/// session pages on, and a session whose cookie is gone mints nothing.
/// Mutant: bind a dashboard session to the shared principal.
#[test]
fn a_dashboard_session_pages_only_its_own_tokens() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    let session = |cookie: &str, body: &Value| {
        let mut c = client(true, &["*"], CredentialKind::DashboardSession);
        c.principal = crate::gateway::record_principal::InternalPrincipal::new(
            "dashboard-session".to_owned(),
        );
        let request = Request::builder()
            .method("POST")
            .uri(routes::UI_KEY_SERVER_LOOKUP_EMAIL)
            .header("content-type", "application/json")
            .header("cookie", format!("mcp_gateway_session={cookie}"))
            .extension(fx.live.generation())
            .extension(c)
            .body(Body::from(body.to_string()))
            .expect("request");
        fx.state.process.lookup_budget().reset_for_test();
        fx.rt.block_on(async {
            let response = crate::gateway::ui::api_router()
                .with_state(fx.state.clone())
                .oneshot(request)
                .await
                .expect("infallible");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("body");
            (
                status,
                serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
            )
        })
    };
    let (status, first) = session("handle-one", &json!({"email": EMAIL, "limit": 1}));
    assert_eq!(status, StatusCode::OK, "{first}");
    let token = first["next_cursor"].as_str().expect("cursor").to_owned();
    let (status, _) = session("handle-two", &json!({"cursor": token}));
    assert_eq!(status, StatusCode::BAD_REQUEST, "another session opened it");
    let (status, second) = session("handle-one", &json!({"cursor": token}));
    assert_eq!(
        status,
        StatusCode::OK,
        "the same session pages on: {second}"
    );
}

/// A token is judged again at delivery: inside its expiry and its chain's
/// ceiling at that moment, not only at the start of the request. Mutant: skip
/// the second check, or drop either bound.
#[test]
fn a_token_is_alive_until_its_expiry_and_its_chains_ceiling() {
    let fx = Fx::new();
    let who = admin("a");
    let now = now_secs();
    let token = fx.seal_by_hand(&who, &fx.scope(now), now);
    let opened = super::super::key_lookup::open(
        &fx.state,
        &fingerprint(&who),
        &token,
        now,
        &fx.ks.email_key,
    )
    .expect("opens");
    assert!(opened.alive_at(now + 299));
    assert!(opened.alive_at(now + 300), "the expiry second is the last");
    assert!(!opened.alive_at(now + 301), "past its own expiry");
    // A chain born 800 s ago, sealed fresh: its own expiry is far off but the
    // ceiling (born + 900) ends it first.
    let old = fx.seal_by_hand(&who, &fx.scope(now - 800), now);
    let opened =
        super::super::key_lookup::open(&fx.state, &fingerprint(&who), &old, now, &fx.ks.email_key)
            .expect("opens inside the ceiling");
    assert!(opened.alive_at(now + 100), "born + 900 is now + 100");
    assert!(!opened.alive_at(now + 101), "past the chain ceiling");
    // Opening itself refuses a chain already past its ceiling: the check at
    // open is not left to the one at delivery, which answers the same way.
    let past = fx.seal_by_hand(&who, &fx.scope(now - 1000), now);
    assert!(
        super::super::key_lookup::open(&fx.state, &fingerprint(&who), &past, now, &fx.ks.email_key)
            .is_none(),
        "open accepted a chain past its ceiling"
    );
}

/// A token the route would itself refuse for its length is never issued.
/// Mutant: drop the length check in `seal`.
#[test]
fn a_token_longer_than_open_accepts_is_not_issued() {
    let fx = Fx::new();
    let who = admin("a");
    let now = now_secs();
    let mut scope = fx.scope(now);
    scope.from = Some("2".repeat(4096));
    assert!(
        super::super::key_lookup::seal(&fx.state, &fingerprint(&who), &scope, now).is_none(),
        "an oversized scope was sealed into a token open would refuse"
    );
}

/// A dashboard session with an empty cookie handle has nothing to bind a token
/// to: a result with a next page is the 503, and no token is minted.
/// Mutant: accept an empty handle.
#[test]
fn a_dashboard_session_without_a_handle_is_given_no_token() {
    let fx = Fx::new();
    for subject in ["s1", "s2"] {
        fx.plant(subject, EMAIL, &fx.ks.email_key);
    }
    let mut c = client(true, &["*"], CredentialKind::DashboardSession);
    c.principal =
        crate::gateway::record_principal::InternalPrincipal::new("dashboard-session".to_owned());
    let request = Request::builder()
        .method("POST")
        .uri(routes::UI_KEY_SERVER_LOOKUP_EMAIL)
        .header("content-type", "application/json")
        .header("cookie", "mcp_gateway_session=")
        .extension(fx.live.generation())
        .extension(c)
        .body(Body::from(json!({"email": EMAIL, "limit": 1}).to_string()))
        .expect("request");
    fx.state.process.lookup_budget().reset_for_test();
    let status = fx.rt.block_on(async {
        crate::gateway::ui::api_router()
            .with_state(fx.state.clone())
            .oneshot(request)
            .await
            .expect("infallible")
            .status()
    });
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// What a token binds to, pinned to literal digests that do not come from the
/// route's own function: a bearer or key binds to a tagged digest of its one
/// secret, a dashboard session to a tagged digest of its cookie handle, two
/// principals differ, and a caller with nothing to bind to gets none.
/// Mutant: drop a tag, hash the wrong material, or bind a kind to nothing.
#[test]
fn what_a_token_binds_to_is_pinned_to_literal_digests() {
    use super::super::key_lookup::cursor_principal;
    let none = axum::http::HeaderMap::new();
    assert_eq!(
        cursor_principal(Some(&admin("a")), &none).as_deref(),
        Some("677c3467fe5e899f2c412330f74dfe3bbeb4caca43731f7d5e1fb93eb3e50f4d"),
        "a static bearer binds to the tagged digest of its principal"
    );
    assert_ne!(
        cursor_principal(Some(&admin("a")), &none),
        cursor_principal(Some(&admin("b")), &none),
        "two principals bind differently"
    );
    let mut dashboard = client(true, &["*"], CredentialKind::DashboardSession);
    dashboard.principal =
        crate::gateway::record_principal::InternalPrincipal::new("dashboard-session".to_owned());
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("cookie", "mcp_gateway_session=handle-one".parse().unwrap());
    assert_eq!(
        cursor_principal(Some(&dashboard), &headers).as_deref(),
        Some("7e87019ce880f23e93201bdf91f6749f3bf44ab6b59b3b669bd13ce0b5b75349"),
        "a dashboard session binds to the tagged digest of its cookie handle"
    );
    assert_eq!(
        cursor_principal(Some(&dashboard), &none),
        None,
        "no cookie, no binding"
    );
    let mut local = admin("a");
    local.credential_kind = CredentialKind::LocalTransport;
    assert_eq!(
        cursor_principal(Some(&local), &none),
        None,
        "stdio has nothing to bind to"
    );
    assert_eq!(cursor_principal(None, &none), None);
}

/// A token that is alive when it opens but dead by the time its page is read
/// is refused at delivery, with the fixed answer, and its page is not handed
/// over. The route's clock is the test clock: the first read (the start of the
/// request) is inside the token's life, the second (delivery) is past its
/// expiry but inside its chain's ceiling. No sleeps, so no race under load.
/// Mutant: judge expiry only when the request starts.
#[test]
fn a_token_that_expires_while_its_read_runs_is_refused_at_delivery() {
    let fx = Fx::new();
    for subject in ["s1", "s2"] {
        fx.plant(subject, EMAIL, &fx.ks.email_key);
    }
    let who = admin("a");
    let sealed_at = now_secs();
    let token = fx.seal_by_hand(&who, &fx.scope(sealed_at), sealed_at);
    let request = Request::builder()
        .method("POST")
        .uri(routes::UI_KEY_SERVER_LOOKUP_EMAIL)
        .header("content-type", "application/json")
        .extension(fx.live.generation())
        .extension(who)
        .body(Body::from(json!({"cursor": token, "limit": 1}).to_string()))
        .expect("request");
    fx.state.process.lookup_budget().reset_for_test();
    let _clock = crate::clock::test_clock::queued(&[Some(sealed_at), Some(sealed_at + 400)]);
    let status = fx.rt.block_on(async {
        crate::gateway::ui::api_router()
            .with_state(fx.state.clone())
            .oneshot(request)
            .await
            .expect("infallible")
            .status()
    });
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a token dead at delivery was honoured"
    );
}
