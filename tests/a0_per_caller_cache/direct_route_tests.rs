// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A0 cells on the direct route (`/mcp/{name}`): two callers never share a
//! cached or stored idempotent result (moved from `a0_per_caller_cache.rs`).

use super::*;

/// Two direct-route calls with one idempotency key; returns the deliveries.
/// Runs under [`resolved`], so every direct cell also asserts that neither
/// caller was left unresolved.
async fn direct_pair(setup: Setup, first: Caller, second: Caller) -> (usize, Value) {
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, _dir) = gateway(setup, &calls).await;
    let (a, b) = resolved(async {
        let a = post_direct(&state, 1, "shared", first).await;
        let b = post_direct(&state, 2, "shared", second).await;
        (a, b)
    })
    .await;
    ok("first", &a);
    ok("second", &b);
    (calls.load(Ordering::SeqCst), b.1)
}

/// T4 — two API keys on the direct route, one idempotency key.
#[tokio::test]
async fn direct_route_idempotency_separates_api_key_callers() {
    let (calls, second) = direct_pair(Setup::two_keys(false), with_key(ALICE), with_key(BOB)).await;
    assert_eq!(calls, 2, "bob replayed alice on the direct route: {second}");
}

/// T5 — two mTLS certificates with different SANs, auth off.
#[tokio::test]
async fn direct_route_idempotency_separates_mtls_callers() {
    let (calls, second) = direct_pair(
        Setup::auth_off(),
        mtls("spiffe://example.test/alice"),
        mtls("spiffe://example.test/bob"),
    )
    .await;
    assert_eq!(calls, 2, "two certificates shared one entry: {second}");
}

/// T6 (i) — two OAuth agents, auth off and no credential, so only the agent
/// identity can separate the callers.
#[tokio::test]
async fn direct_route_idempotency_separates_oauth_agents() {
    let (calls, second) = direct_pair(Setup::auth_off(), agent("agent-a"), agent("agent-b")).await;
    assert_eq!(calls, 2, "two OAuth agents shared one entry: {second}");
}

/// T5 control — one certificate sending one key twice is deduplicated, so
/// the separation above is not the guard being skipped for everyone.
#[tokio::test]
async fn direct_route_same_mtls_caller_still_deduplicates() {
    let (calls, second) = direct_pair(
        Setup::auth_off(),
        mtls("spiffe://example.test/alice"),
        mtls("spiffe://example.test/alice"),
    )
    .await;
    assert_eq!(calls, 1, "the keyed repeat ran twice: {second}");
    assert_eq!(delivery(&second).as_deref(), Some("call-1"));
}

/// T6 (i) control — one OAuth agent sending one key twice is deduplicated.
#[tokio::test]
async fn direct_route_same_oauth_agent_still_deduplicates() {
    let (calls, second) = direct_pair(Setup::auth_off(), agent("agent-a"), agent("agent-a")).await;
    assert_eq!(calls, 1, "the keyed repeat ran twice: {second}");
    assert_eq!(delivery(&second).as_deref(), Some("call-1"));
}

/// T6 (ii) control — one trusted subject sending one key twice is deduplicated.
#[tokio::test]
async fn direct_route_same_trusted_header_still_deduplicates() {
    let setup = Setup::trusted_proxy();
    let (calls, second) =
        direct_pair(setup, trusted_header("alice"), trusted_header("alice")).await;
    assert_eq!(calls, 1, "the keyed repeat ran twice: {second}");
    assert_eq!(delivery(&second).as_deref(), Some("call-1"));
}

/// T6 (ii) — trusted identity headers, trust ON, auth off, no credential.
#[tokio::test]
async fn direct_route_idempotency_separates_trusted_headers() {
    let setup = Setup::trusted_proxy();
    let (calls, second) = direct_pair(setup, trusted_header("alice"), trusted_header("bob")).await;
    assert_eq!(calls, 2, "two trusted subjects shared one entry: {second}");
}

/// A8-T1 (HTTP) — the meta route answers an identity header from a peer
/// that is not a trusted proxy with 403, and the call never reaches the
/// backend; the same header through the proxy does.
#[tokio::test]
async fn meta_route_refuses_untrusted_peer_identity_header() {
    let calls = Arc::new(AtomicUsize::new(0));
    // Auth on: a modern keyed call needs a verified principal, and the header
    // only selects the end user under it.
    let setup = Setup {
        caller_identity: Setup::trusted_proxy().caller_identity,
        ..Setup::two_keys(false)
    };
    let (state, _dir) = gateway(setup, &calls).await;
    let keyed = |caller: Caller| Caller {
        bearer: Some(ALICE),
        ..caller
    };
    let (status, body) = post_meta(&state, 1, Some("k-1"), keyed(untrusted_header("alice"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a refused caller reached the backend"
    );
    ok(
        "trusted",
        &post_meta(&state, 2, Some("k-2"), keyed(trusted_header("alice"))).await,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// A8-T13 — the direct route refuses an identity header from a peer that is
/// not a trusted proxy, before the idempotency guard: both sends are 403, the
/// backend never runs, and the key was not reserved, so the same key from
/// the proxy afterwards runs the backend rather than replaying anything.
#[tokio::test]
async fn direct_route_refuses_untrusted_peer_identity_header() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, _dir) = gateway(Setup::trusted_proxy(), &calls).await;
    for id in [1, 2] {
        let (status, body) = post_direct(&state, id, "shared", untrusted_header("alice")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "send {id}: {body}");
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a refused caller reached the backend"
    );
    let trusted = post_direct(&state, 3, "shared", trusted_header("alice")).await;
    ok("trusted", &trusted);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the refused sends reserved the key"
    );
    assert_eq!(delivery(&trusted.1).as_deref(), Some("call-1"));
}

/// T6 control — trust OFF: the headers are ignored, both requests are the one
/// principal their shared certificate proves, and they pool. Headers are not
/// trusted by default.
#[tokio::test]
async fn direct_route_ignores_identity_headers_when_trust_is_off() {
    // One verified certificate on both calls: a keyed direct call needs an
    // execution principal (the anonymous-caller rule). The headers still differ, and
    // with trust off they must not split the one caller into two.
    let as_cert = |caller: Caller| Caller {
        cert: mtls("spiffe://test/one").cert,
        ..caller
    };
    let (calls, second) = direct_pair(
        Setup::auth_off(),
        as_cert(trusted_header("alice")),
        as_cert(trusted_header("bob")),
    )
    .await;
    assert_eq!(calls, 1, "untrusted headers separated callers: {second}");
    assert_eq!(delivery(&second).as_deref(), Some("call-1"));
}

/// T7 — positive control: one API key sending one idempotency key twice on
/// the direct route is deduplicated, and the replay is the first result.
#[tokio::test]
async fn direct_route_same_caller_still_deduplicates() {
    let (calls, second) =
        direct_pair(Setup::two_keys(false), with_key(ALICE), with_key(ALICE)).await;
    assert_eq!(calls, 1, "the keyed repeat ran twice: {second}");
    assert_eq!(delivery(&second).as_deref(), Some("call-1"));
}
