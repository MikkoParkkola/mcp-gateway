// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Real-wire acceptance for the personal-account provider transport.
//!
//! TARGET PATH: `src/personal_accounts/provider/wire_tests.rs`, wired by
//! `#[cfg(test)] mod wire_tests;` in `src/personal_accounts/provider.rs`.
//! Two submodules beside it: `wire_tests/fixture.rs` (the recording TLS server,
//! its pause barrier and the clients under test) and `wire_tests/gateway.rs`
//! (startup over the wire). PROPOSAL ONLY — not applied to the worktree, and it
//! does NOT compile there yet: it names constructor seams that do not exist
//! (`GatewayProviderHttp::for_test`, `Gateway::new_evaluated_with_account_http`,
//! `start_custody_with_http`) plus one re-export, all specified in
//! `minimal-seams.patch.json`.
//!
//! WHAT THESE PROVE THAT THE POLICY TESTS DO NOT. The approved policy tests
//! drive a fake `ProviderHttp`, so every claim about TLS, redirects, body bounds
//! and startup ordering is a claim about a fake. Here the client is the
//! PRODUCTION `GatewayProviderHttp` over a real rustls listener on loopback: a
//! handshake happens, bytes are recorded as the server saw them, and every
//! negative is asserted against an OBSERVED absence (zero recorded requests,
//! unchanged connection counts) rather than against an enum value a fake could
//! have returned for any reason.
//!
//! WHAT THEY DELIBERATELY DO NOT PROVE. The client reaches the fixture through
//! `ClientBuilder::resolve`, a test-only static DNS override that takes
//! priority over the configured resolver. So these tests say NOTHING about
//! `PinningResolver` and MUST NOT be cited as DNS-pinning evidence — the
//! resolver keeps its own tests in `src/security/ssrf/`. What the override buys
//! is the one thing pinning would otherwise forbid: a public-form hostname
//! whose certificate can be validated for real against loopback. The IP-literal
//! half of the SSRF policy is a different mechanism and IS driven here, through
//! the production guard, in `embedded_userinfo_and_an_ip_literal_never_reach_the_wire`.
//!
//! NO RELAXED SECURITY ANYWHERE — AND THE HONEST FORM OF THAT CLAIM. The test
//! client is built from the SAME strict builder production uses
//! (`strict_builder`, seam S1) and the fixtures add exactly two things: a test
//! CA root and a static name override. The closure `for_test` takes COULD
//! override an earlier setting — `reqwest::ClientBuilder` is last-call-wins, so
//! a later `.redirect(...)`, `.https_only(false)` or `danger_accept_invalid_*`
//! would win. Nothing in the seam prevents that; r1 claimed otherwise and was
//! wrong. What bounds it is a review boundary: `for_test` exists only under
//! `cfg(test)`, its callers are the two functions in `wire_tests/fixture.rs`,
//! and a third addition would be visible in a diff.
//!
//! DETERMINISM. Each test owns its listener, its task and its temp dir. No
//! sleep, no process-environment write, no shared static, no public network.
//! Every wait is a bounded `timeout`; fixtures are stopped and joined
//! explicitly.
//!
//! CREDENTIALS ARE SYNTHETIC MARKERS. The sentinels in `fixture.rs` are
//! random-looking strings that exist so their ABSENCE from a recorded request is
//! assertable. They authenticate nothing.

mod fixture;
mod gateway;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fixture::{
    Fixture, HOST, MAX_BODY_BYTES, SENTINEL_REFRESH, SENTINEL_SECRET, expect_terminal, json_200,
    responder, response, token_form, trusting_client, untrusting_client,
};

use super::{ProviderHttp as _, TerminalFailure};

// ── 1. Credentials on the wire ───────────────────────────────────────────────

/// The metadata GET carries no credential, and the token POST carries exactly
/// the form fields the caller passed — no Basic header, no URL credentials.
///
/// FALSIFIER: a client that grew an `authorization` header, a cookie store, or
/// a builder that turned a form into HTTP Basic would fail on the recorded
/// bytes, not on a policy assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_metadata_get_carries_no_credential_and_a_token_post_sends_only_its_form() {
    let fixture = Fixture::start(responder(|request| {
        if request.target.starts_with("/token") {
            json_200(
                r#"{"access_token":"synthetic-wire-access","token_type":"Bearer","expires_in":3600}"#,
            )
        } else {
            json_200(r#"{"issuer":"https://example.invalid"}"#)
        }
    }))
    .await;
    let client = trusting_client(&fixture);

    let metadata = client
        .get_metadata(&fixture.url("/.well-known/oauth-authorization-server"))
        .await
        .expect("a trusted fixture serves the metadata GET");
    assert_eq!(metadata.status, 200);

    let token = client
        .post_token(&fixture.url("/token"), &token_form())
        .await
        .expect("a trusted fixture serves the token POST");
    assert_eq!(token.status, 200);

    let recorded = fixture.requests();
    assert_eq!(recorded.len(), 2, "exactly two requests reached the wire");

    let get = &recorded[0];
    assert_eq!(get.method, "GET");
    assert_eq!(get.target, "/.well-known/oauth-authorization-server");
    assert_eq!(get.header("accept"), Some("application/json"));
    assert!(get.body.is_empty(), "a metadata GET carries no body");
    for header in ["authorization", "cookie", "proxy-authorization"] {
        assert!(
            get.header(header).is_none(),
            "the metadata GET must carry no {header} header"
        );
    }
    for secret in [SENTINEL_REFRESH, SENTINEL_SECRET] {
        assert!(
            !get.raw.contains(secret),
            "no credential may appear anywhere in the metadata request"
        );
    }

    let post = &recorded[1];
    assert_eq!(post.method, "POST");
    assert_eq!(post.target, "/token", "credentials never travel in the URL");
    assert!(
        post.header("authorization").is_none() && post.header("cookie").is_none(),
        "the token POST authenticates in the body, never with a synthesized header"
    );
    assert_eq!(
        post.form(),
        token_form().into_iter().collect::<BTreeMap<_, _>>(),
        "the wire form is exactly what the caller passed: no field added, none dropped"
    );

    fixture.stop().await;
}

// ── 2. Untrusted certificate ─────────────────────────────────────────────────

/// An untrusted certificate ends the flow, after a REAL dial and a REAL
/// handshake attempt, with no HTTP request served.
///
/// The positive control on the same listener is what makes the refusal mean
/// "certificate": a fixture that refused everything would satisfy the negative
/// alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_untrusted_certificate_is_terminal_after_a_real_handshake_attempt() {
    let fixture = Fixture::start(responder(|_| {
        json_200(r#"{"issuer":"https://example.invalid"}"#)
    }))
    .await;
    let url = fixture.url("/.well-known/oauth-authorization-server");

    trusting_client(&fixture)
        .get_metadata(&url)
        .await
        .expect("control: this listener does serve a client that trusts its CA");
    let served = fixture.log().requests.len();
    assert_eq!(served, 1, "the control request was served");

    let failure = expect_terminal(
        untrusting_client(&fixture).get_metadata(&url).await,
        "an untrusted certificate",
    );
    assert!(
        matches!(
            failure,
            TerminalFailure::Certificate | TerminalFailure::Unclassified
        ),
        "a rejected certificate is terminal; reqwest cannot always name it and both spellings are terminal, got {failure:?}"
    );

    // The client's terminal answer is a CLIENT-side fact and says nothing about
    // what the server has recorded yet. Wait for the SERVER's own observation of
    // the failed handshake; the fixture counts a connection before the handshake
    // and records a request only after it, so this one signal orders all three
    // assertions below.
    fixture.failed_handshakes_reached(1).await;

    // Snapshot under the lock, assert after releasing it: an assertion that
    // panicked while holding the guard poisoned the mutex the fixture's own task
    // then locked, turning one failure into a PoisonError cascade.
    let (connections, handshakes_failed, requests) = {
        let log = fixture.log();
        (log.connections, log.handshakes_failed, log.requests.len())
    };
    assert_eq!(
        connections, 2,
        "the refusal happened on the wire: the client dialled the fixture"
    );
    assert_eq!(
        handshakes_failed, 1,
        "the fixture observed exactly one failed handshake — this is what makes the refusal real rather than injected"
    );
    assert_eq!(
        requests, served,
        "no HTTP request may follow a rejected certificate"
    );

    fixture.stop().await;
}

// ── 3. Delivered redirect ────────────────────────────────────────────────────

/// A 302 is terminal for both operations and nothing follows it — not to the
/// SAME origin, and not to another one.
///
/// The metadata hop is SAME-ORIGIN on purpose: a cross-origin target alone
/// would be refused by the `https_only`/SSRF layer even if redirects were
/// followed, so the test would pass without `Policy::none()` doing anything.
/// The token hop points at a second listener, which records zero connections —
/// the control that no hop of any kind was attempted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivered_302_is_terminal_for_both_operations_and_nothing_follows_it() {
    let elsewhere = Fixture::start(responder(|_| json_200("{}"))).await;
    let elsewhere_url = elsewhere.url("/followed");
    let redirector = Fixture::start(responder(move |request| {
        let location = if request.target.starts_with("/token") {
            elsewhere_url.clone()
        } else {
            "/followed".to_string()
        };
        response(302, "Found", &[("location", location.as_str())], b"")
    }))
    .await;
    let client = trusting_client(&redirector);

    let metadata = client
        .get_metadata(&redirector.url("/.well-known/oauth-authorization-server"))
        .await;
    assert_eq!(
        expect_terminal(metadata, "a same-origin redirected metadata GET"),
        TerminalFailure::Redirect,
        "a delivered 3xx is Redirect, never an ordinary non-200 that discovery could walk past"
    );

    let token = client
        .post_token(&redirector.url("/token"), &token_form())
        .await;
    assert_eq!(
        expect_terminal(token, "a cross-origin redirected token POST"),
        TerminalFailure::Redirect,
        "a token POST is refused on a redirect too: no credential is ever re-sent"
    );

    let targets: Vec<String> = redirector
        .requests()
        .into_iter()
        .map(|request| request.target)
        .collect();
    assert_eq!(
        targets,
        vec![
            "/.well-known/oauth-authorization-server".to_string(),
            "/token".to_string()
        ],
        "each operation made exactly one request; /followed was never fetched"
    );
    assert_eq!(
        elsewhere.log().connections,
        0,
        "the redirect target was not dialled: not one connection, let alone a request"
    );

    redirector.stop().await;
    elsewhere.stop().await;
}

// ── 4. Body bound ────────────────────────────────────────────────────────────

/// Exactly 256 KiB is accepted intact; one byte more is refused.
///
/// The pair is the point: the positive proves the bound is not simply "refuse
/// large bodies", and the negative proves the refusal is the bound rather than
/// a transport failure. Both run through the production streaming read.
///
/// HONEST LIMIT: this observes the OUTCOME of the streaming read, not its
/// internals. It cannot distinguish "counted as chunks arrived" from "buffered
/// then measured" — what it does prove is that the process survived the
/// oversize response and answered `Unacceptable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_body_bound_accepts_exactly_256_kib_and_refuses_one_byte_more() {
    let served = Arc::new(AtomicUsize::new(0));
    let fixture = Fixture::start({
        let served = Arc::clone(&served);
        responder(move |request| {
            let size = if request.target == "/over" {
                MAX_BODY_BYTES + 1
            } else {
                MAX_BODY_BYTES
            };
            served.store(size, Ordering::SeqCst);
            // ASCII so the refusal cannot be blamed on UTF-8 validation, which
            // is a different reason wearing the same enum spelling.
            response(
                200,
                "OK",
                &[("content-type", "application/json")],
                &vec![b'a'; size],
            )
        })
    })
    .await;
    let client = trusting_client(&fixture);

    let accepted = client
        .get_metadata(&fixture.url("/at"))
        .await
        .expect("a body exactly at the bound is accepted");
    assert_eq!(accepted.body.len(), MAX_BODY_BYTES, "and it arrives intact");
    assert_eq!(served.load(Ordering::SeqCst), MAX_BODY_BYTES);

    assert_eq!(
        expect_terminal(
            client.get_metadata(&fixture.url("/over")).await,
            "an oversize body"
        ),
        TerminalFailure::Unacceptable,
        "one byte past the bound is refused as unacceptable, not as a transport error"
    );
    assert_eq!(
        served.load(Ordering::SeqCst),
        MAX_BODY_BYTES + 1,
        "the fixture really did attempt the oversize response"
    );
    assert_eq!(fixture.log().requests.len(), 2);

    fixture.stop().await;
}

// ── 5. Credentials in the URL never reach the wire ───────────────────────────

/// An embedded `user:pass@` URL is refused on both operations with no request
/// made, and an HTTPS IP literal is Blocked before any connection.
///
/// SCOPE. The exact terminal spelling for embedded userinfo belongs to the
/// production guard and is NOT reimplemented or re-asserted here: this test
/// asserts only that the refusal is terminal and that NOTHING reached the wire.
/// The IP-literal half is a different mechanism — `validate_url_not_ssrf` inside
/// the production guard — and IS pinned to `Blocked`. Neither has anything to do
/// with the test DNS override, which maps one public-form NAME and no address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_userinfo_and_an_ip_literal_never_reach_the_wire() {
    let fixture = Fixture::start(responder(|_| {
        json_200(r#"{"issuer":"https://example.invalid"}"#)
    }))
    .await;
    let client = trusting_client(&fixture);

    // The anchor. Without a request that DOES arrive, "no request arrived"
    // below would also pass against a fixture that never worked.
    client
        .get_metadata(&fixture.url("/.well-known/oauth-authorization-server"))
        .await
        .expect("anchor: an ordinary request reaches this fixture");
    let (connections, requests) = {
        let log = fixture.log();
        (log.connections, log.requests.len())
    };
    assert_eq!(requests, 1, "the anchor request was recorded");

    let port = fixture.addr.port();
    let userinfo = format!("https://not-a-real-user:not-a-real-secret@{HOST}:{port}/token");
    expect_terminal(
        client.get_metadata(&userinfo).await,
        "a metadata GET with embedded userinfo",
    );
    expect_terminal(
        client.post_token(&userinfo, &token_form()).await,
        "a token POST with embedded userinfo",
    );

    assert_eq!(
        expect_terminal(
            client
                .get_metadata(&format!(
                    "https://127.0.0.1:{port}/.well-known/openid-configuration"
                ))
                .await,
            "an HTTPS IP literal",
        ),
        TerminalFailure::Blocked,
        "an IP literal is refused by the production SSRF guard, before any socket"
    );

    let log = fixture.log();
    assert_eq!(
        log.requests.len(),
        requests,
        "no refused URL produced an HTTP request"
    );
    assert_eq!(
        log.connections, connections,
        "and none opened a connection either: these refusals precede the wire"
    );
    drop(log);

    fixture.stop().await;
}

// ── 6. An abandoned barrier answers nothing ──────────────────────────────────

/// A barrier that is entered and then DROPPED without release must not produce a
/// response, even though this fixture's responder would serve valid metadata.
///
/// This is the regression for the r2 defect: `hold` swallowed a dropped release
/// and fell through to the responder, so an "unanswered" window was in fact
/// answered and any ordering claim built on the barrier was inferred, not proved.
/// The positive half lives in `gateway.rs`, where a RELEASED barrier does serve —
/// without it, a fixture that answered nothing at all would pass this test too.
///
/// Deterministic by construction: the drop is the control signal. No sleep, and
/// no test that waits out the fixture bound — the timeout arm is the same
/// `Ok(Ok(()))` match as this one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_pause_serves_no_metadata_however_valid_the_responder() {
    let (fixture, mut pause) = Fixture::start_paused(responder(|_| {
        json_200(r#"{"issuer":"https://example.invalid"}"#)
    }))
    .await;
    let client = trusting_client(&fixture);
    let url = fixture.url("/.well-known/oauth-authorization-server");

    let call = tokio::spawn(async move { client.get_metadata(&url).await });

    // The witness: the request really arrived and is parked, unanswered.
    let held = pause.wait_entered().await;
    assert_eq!(held.target, "/.well-known/oauth-authorization-server");
    drop(pause);

    let result = tokio::time::timeout(fixture::FIXTURE_TIMEOUT, call)
        .await
        .expect("the client returns once the abandoned barrier closes the connection")
        .expect("the spawned call did not panic");
    assert!(
        result.is_err(),
        "an abandoned barrier must answer nothing; got a served response: {result:?}"
    );

    assert_eq!(
        fixture.requests().len(),
        1,
        "exactly one request crossed the boundary, and it was the held one"
    );

    fixture.stop().await;
}
