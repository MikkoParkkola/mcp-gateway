// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! #2155: the per-caller firewall controls key on the caller, not on "".
//!
//! On a modern `POST /mcp` there is no session, so the control identity is the
//! caller's key. Before #2155 that key came from an API-key client only, so a
//! caller proven by an OAuth agent token or an mTLS certificate reached the
//! firewall with an empty identity and every per-caller control refused it.
//!
//! Every row drives the real router with the real firewall. The discriminating
//! observable is a call budget of 1: a second call under the SAME key is
//! refused with the budget's own reason, a call under a DIFFERENT key is not.
//! A refusal is always classified by its reason, so "refused, but because the
//! caller had no identity" can never pass for "refused by the budget".

use super::{TOOL, state_with_firewalls_and_auth};
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::gateway::oauth::{AgentIdentity as OAuthAgentIdentity, Scope};
use crate::gateway::router::create_router;
use crate::mtls::identity::CertIdentity;
use crate::security::firewall::{Firewall, FirewallConfig, budget_guard::BudgetGuardConfig};
use axum::body::to_bytes;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const MODERN: &str = "2026-07-28";

/// What happened to one call, read off the HTTP response.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Delivered: the backend's result reached the client.
    Delivered,
    /// Refused by the call budget: the key was counted and is spent.
    BudgetSpent,
    /// Refused by the tenant guard: this key already reached its tenant limit.
    TenantReach,
    /// Refused because the caller had no identity to key on.
    NoIdentity,
    /// Any other refusal (auth, dispatch, another firewall rule), verbatim, so
    /// a call stopped for an unrelated reason can never read as delivered.
    Other(String),
}

fn classify(body: &Value) -> Outcome {
    if body.get("result").is_some_and(|r| !r.is_null()) && body.get("error").is_none() {
        return Outcome::Delivered;
    }
    let message = body
        .pointer("/error/message")
        .and_then(Value::as_str)
        .map_or_else(|| body.to_string(), str::to_string);
    // The firewall wraps its refusals as -32600 "Firewall blocked: …". Requiring
    // the code as well keeps a same-worded refusal from another guard (e.g. a
    // -32003 spend limit) from ever reading as the firewall's own.
    let firewall = body.pointer("/error/code").and_then(Value::as_i64) == Some(-32600);
    if firewall && message.contains("Call budget exceeded") {
        Outcome::BudgetSpent
    } else if firewall && message.contains("Cross-tenant reach exceeded") {
        Outcome::TenantReach
    } else if message.contains("no caller identity") {
        Outcome::NoIdentity
    } else {
        Outcome::Other(message)
    }
}

/// Budget of one call per window; or, with `anomaly`, the anomaly detector
/// (which exists only with a transition tracker to learn from).
fn firewall(anomaly: bool) -> Arc<Firewall> {
    Arc::new(
        Firewall::from_config(
            FirewallConfig {
                enabled: true,
                scan_requests: true,
                scan_responses: false,
                anomaly_detection: anomaly,
                anomaly_block_threshold: anomaly.then_some(0.99),
                // Pinned rather than inherited, so a changed default cannot move
                // the warm-up under these rows (the first call per key warms up).
                anomaly_min_observations: 20,
                budget: BudgetGuardConfig {
                    enabled: !anomaly,
                    max_calls_per_window: 1,
                    window_secs: 3600,
                },
                ..FirewallConfig::default()
            },
            anomaly.then(|| Arc::new(crate::transition::TransitionTracker::new())),
        )
        .keyed_for_test(),
    )
}

fn api_key(secret: &str, name: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec!["demo".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
    }
}

/// Auth on, with the given API keys.
fn keys(keys: Vec<ApiKeyConfig>) -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: keys,
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    }
}

fn agent(client_id: &str) -> OAuthAgentIdentity {
    let scope = format!("tools:demo:{TOOL}:execute");
    OAuthAgentIdentity {
        quota_principal: None,
        client_id: client_id.to_string(),
        agent_name: "same display name".to_string(),
        scopes: vec![Scope::parse(&scope).unwrap()],
        raw_scopes: vec![scope],
    }
}

/// A certificate identity as `CertIdentity::from_der` would build it. Each
/// distinct (SAN URI, CN) pair stands for a distinct certificate, so it gets its
/// own `quota_principal`: a key derived from the certificate bytes would then
/// separate a renewal from its predecessor (mutant m5 against H5).
fn cert(san_uri: Option<&str>, cn: Option<&str>) -> CertIdentity {
    issued(san_uri, cn, 0)
}

/// The `serial`-th certificate issued for one subject: same SAN URI and CN,
/// different bytes, so a different `quota_principal`, as two live certificates
/// for one workload always are.
fn issued(san_uri: Option<&str>, cn: Option<&str>, serial: u32) -> CertIdentity {
    let der = format!("der:{san_uri:?}:{cn:?}:{serial}");
    CertIdentity {
        san_uris: san_uri.map(str::to_string).into_iter().collect(),
        common_name: cn.map(str::to_string),
        display_name: san_uri.or(cn).unwrap_or("<unknown>").to_string(),
        quota_principal: Some(crate::gateway::auth::QuotaPrincipal::client_certificate(
            der.as_bytes(),
        )),
        ..Default::default()
    }
}

/// Who a call is from. Each field is an independent proof the router reads.
#[derive(Default, Clone)]
struct Caller {
    bearer: Option<&'static str>,
    agent: Option<OAuthAgentIdentity>,
    cert: Option<CertIdentity>,
}

/// One `tools/call` of the surfaced tool. `modern` sends the 2026-07-28 shape
/// (no session); otherwise a legacy call, resuming `session` when given.
fn call(
    caller: &Caller,
    modern: bool,
    session: Option<&str>,
    n: usize,
) -> axum::http::Request<axum::body::Body> {
    call_with(caller, modern, session, n, &json!({}))
}

/// [`call`] with explicit tool arguments.
fn call_with(
    caller: &Caller,
    modern: bool,
    session: Option<&str>,
    n: usize,
    arguments: &Value,
) -> axum::http::Request<axum::body::Body> {
    let mut params = json!({ "name": TOOL, "arguments": arguments });
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    if modern {
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": MODERN,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": { "name": "caller-key", "version": "1.0.0" },
        });
        // No idempotency key: a keyed call is admitted only for an OIDC or
        // API-key principal (`meta_mcp/admission.rs`), which would stop an
        // agent- or certificate-only caller AFTER the firewall for a reason
        // unrelated to its firewall key. Unkeyed calls are admitted under the
        // default `server.idempotency_key: optional`. That admission gap is
        // #2207, not this file's subject.
        builder = builder
            .header("mcp-protocol-version", MODERN)
            .header("mcp-method", "tools/call")
            .header("mcp-name", TOOL);
    }
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    if let Some(bearer) = caller.bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    let body = json!({ "jsonrpc": "2.0", "id": n, "method": "tools/call", "params": params });
    let mut request = builder
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    if let Some(agent) = caller.agent.clone() {
        request.extensions_mut().insert(agent);
    }
    if let Some(cert) = caller.cert.clone() {
        request.extensions_mut().insert(cert);
    }
    request
}

/// Send and classify; also return the session id a legacy call was given.
async fn send(
    router: &axum::Router,
    request: axum::http::Request<axum::body::Body>,
) -> (Outcome, Option<String>, Value) {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    // A result only counts as delivered on HTTP 200; any other status with a
    // result body is reported verbatim instead.
    let outcome = match classify(&body) {
        Outcome::Delivered if status != axum::http::StatusCode::OK => {
            Outcome::Other(format!("HTTP {status} with a result body"))
        }
        outcome => outcome,
    };
    (outcome, session, body)
}

/// Modern calls from `callers`, in order, against one gateway; the outcomes.
async fn modern_run(fw: Arc<Firewall>, auth: &AuthConfig, callers: &[Caller]) -> Vec<Outcome> {
    let (state, _store) = state_with_firewalls_and_auth(Arc::clone(&fw), fw, auth).await;
    let router = create_router(state);
    let mut out = Vec::new();
    for (n, caller) in callers.iter().enumerate() {
        let (outcome, _, body) = send(&router, call(caller, true, None, n)).await;
        eprintln!("call {n}: {outcome:?} {body}");
        out.push(outcome);
    }
    out
}

fn by_agent(id: &str) -> Caller {
    Caller {
        agent: Some(agent(id)),
        ..Caller::default()
    }
}

fn by_issued(san_uri: Option<&str>, cn: Option<&str>, serial: u32) -> Caller {
    Caller {
        cert: Some(issued(san_uri, cn, serial)),
        ..Caller::default()
    }
}

fn by_cert(san_uri: Option<&str>, cn: Option<&str>) -> Caller {
    Caller {
        cert: Some(cert(san_uri, cn)),
        ..Caller::default()
    }
}

use Outcome::{BudgetSpent, Delivered, NoIdentity, TenantReach};

// ── KEY.OAUTH.1 / KEY.MTLS.1: an agent or certificate caller is scored ──────

#[tokio::test]
async fn h1_an_oauth_agent_caller_reaches_the_anomaly_detector() {
    let got = modern_run(
        firewall(true),
        &AuthConfig::default(),
        &[by_agent("agent-a")],
    )
    .await;
    assert_eq!(
        got,
        [Delivered],
        "an agent-proven caller was refused as unkeyed"
    );
}

#[tokio::test]
async fn h2_an_mtls_caller_reaches_the_anomaly_detector() {
    let got = modern_run(
        firewall(true),
        &AuthConfig::default(),
        &[by_cert(Some("spiffe://t/a"), None)],
    )
    .await;
    assert_eq!(
        got,
        [Delivered],
        "a certificate-proven caller was refused as unkeyed"
    );
}

// ── KEY.DISTINCT.1 (restated): one key per subject, never per display ────────

#[tokio::test]
async fn h3_each_oauth_agent_has_its_own_budget() {
    let got = modern_run(
        firewall(false),
        &AuthConfig::default(),
        &[
            by_agent("agent-a"),
            by_agent("agent-a"),
            by_agent("agent-b"),
        ],
    )
    .await;
    assert_eq!(got, [Delivered, BudgetSpent, Delivered]);
}

#[tokio::test]
async fn h4_each_certificate_subject_has_its_own_budget() {
    let a = |serial| by_issued(Some("spiffe://t/a"), None, serial);
    let got = modern_run(
        firewall(false),
        &AuthConfig::default(),
        &[a(1), a(2), by_cert(Some("spiffe://t/b"), None)],
    )
    .await;
    assert_eq!(got, [Delivered, BudgetSpent, Delivered]);
}

#[tokio::test]
async fn h5_a_renewed_certificate_keeps_its_budget() {
    // Same SAN URI, a different CN: the renewal of one workload identity.
    let got = modern_run(
        firewall(false),
        &AuthConfig::default(),
        &[
            by_cert(Some("spiffe://t/a"), Some("old")),
            by_cert(Some("spiffe://t/a"), Some("new")),
        ],
    )
    .await;
    assert_eq!(got, [Delivered, BudgetSpent], "rotation reset the bucket");
}

#[tokio::test]
async fn h6_without_a_san_uri_the_cn_is_the_subject() {
    let got = modern_run(
        firewall(false),
        &AuthConfig::default(),
        &[
            by_issued(None, Some("cn-a"), 1),
            by_issued(None, Some("cn-a"), 2),
            by_cert(None, Some("cn-b")),
        ],
    )
    .await;
    assert_eq!(got, [Delivered, BudgetSpent, Delivered]);
}

// ── Decision 4: a resolved subject wins over the credential ──────────────────

#[tokio::test]
async fn h7_two_credentials_of_one_subject_share_one_budget() {
    let auth = keys(vec![api_key("key-one", "one"), api_key("key-two", "two")]);
    let as_a = |bearer| Caller {
        bearer: Some(bearer),
        agent: Some(agent("agent-a")),
        cert: None,
    };
    let got = modern_run(firewall(false), &auth, &[as_a("key-one"), as_a("key-two")]).await;
    assert_eq!(
        got,
        [Delivered, BudgetSpent],
        "the credential outranked the subject"
    );
}

// ── Guards: what must not change ─────────────────────────────────────────────

#[tokio::test]
async fn h8_a_caller_with_no_identity_is_still_refused_unscored() {
    let got = modern_run(firewall(true), &AuthConfig::default(), &[Caller::default()]).await;
    assert_eq!(got, [NoIdentity]);
}

#[tokio::test]
async fn h9_a_certificate_naming_no_subject_is_not_an_identity() {
    // Neither SAN URI nor CN: its display name is a constant every such
    // certificate shares, so it must never become a key.
    let got = modern_run(
        firewall(true),
        &AuthConfig::default(),
        &[by_cert(None, None)],
    )
    .await;
    assert_eq!(got, [NoIdentity]);
}

#[tokio::test]
async fn h10_that_certificate_with_an_api_key_keys_on_the_credential() {
    let auth = keys(vec![api_key("key-one", "one")]);
    let c = || Caller {
        bearer: Some("key-one"),
        agent: None,
        cert: Some(cert(None, None)),
    };
    let got = modern_run(firewall(false), &auth, &[c(), c()]).await;
    assert_eq!(got, [Delivered, BudgetSpent]);
}

/// MIK-7971: an auth-off legacy caller is keyed on the session it RESUMES; a
/// call resuming none (no header, so the gateway mints one) keys on the one
/// shared session-less identity. A fresh session no longer buys a fresh
/// bucket: that was a new budget per request.
#[tokio::test]
async fn h11_an_auth_off_legacy_caller_is_keyed_on_its_resumed_session() {
    let fw = firewall(false);
    let (state, _store) =
        state_with_firewalls_and_auth(Arc::clone(&fw), fw, &AuthConfig::default()).await;
    let router = create_router(state);
    let anon = Caller::default();
    let (first, session, body) = send(&router, call(&anon, false, None, 0)).await;
    assert_eq!(first, Delivered, "{body}");
    let session = session.expect("a legacy call is given a session");
    let (fresh, _, body) = send(&router, call(&anon, false, None, 1)).await;
    assert_eq!(
        fresh, BudgetSpent,
        "no session resumed: the shared session-less bucket: {body}"
    );
    let (resumed, _, body) = send(&router, call(&anon, false, Some(&session), 2)).await;
    assert_eq!(
        resumed, Delivered,
        "a resumed session is its own bucket: {body}"
    );
    let (again, _, body) = send(&router, call(&anon, false, Some(&session), 3)).await;
    assert_eq!(again, BudgetSpent, "same session, same bucket: {body}");
}

// ── #1785 in this PR: one caller, one key, on both routes ─────────────────────

/// The same `tools/call` on the per-backend route, `POST /mcp/demo`.
fn direct_call(bearer: &str, n: usize) -> axum::http::Request<axum::body::Body> {
    direct_call_with(bearer, n, &json!({}))
}

/// [`direct_call`] with explicit tool arguments.
fn direct_call_with(
    bearer: &str,
    n: usize,
    arguments: &Value,
) -> axum::http::Request<axum::body::Body> {
    let body = json!({
        "jsonrpc": "2.0", "id": n, "method": "tools/call",
        "params": { "name": TOOL, "arguments": arguments }
    });
    axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn h14_one_caller_spends_one_budget_across_both_routes() {
    // Before the fix the per-backend route keys every caller on
    // `direct:demo`, so a caller who spent its budget on /mcp gets a fresh one
    // there: the second call is delivered.
    let fw = firewall(false);
    let auth = keys(vec![api_key("key-one", "one")]);
    let (state, _store) = state_with_firewalls_and_auth(Arc::clone(&fw), fw, &auth).await;
    // Only the FIREWALL budget may bind here. The direct route also runs a
    // cost-governance spend guard (refusing -32003, keyed on the API-key name),
    // and it would refuse the second call whether or not the caller key is
    // wired. It is off by construction: the fixture's Meta-MCP has no budget
    // enforcer, and it is asserted so. An `Other(-32003)` below therefore means
    // this fixture broke, never that the fix did; do not loosen the oracle.
    #[cfg(feature = "cost-governance")]
    assert!(
        state.meta_mcp.budget_enforcer.is_none(),
        "a spend limit is configured, so it could bind before the firewall budget"
    );
    let router = create_router(state);
    let meta = Caller {
        bearer: Some("key-one"),
        ..Caller::default()
    };
    let (first, _, body) = send(&router, call(&meta, true, None, 0)).await;
    assert_eq!(first, Delivered, "the meta call is the first spend: {body}");
    let (second, _, body) = send(&router, direct_call("key-one", 1)).await;
    assert_eq!(
        second, BudgetSpent,
        "the direct route opened a second budget: {body}"
    );
}

// ── CONTROL.4: a keyed direct-route caller is a tracked identity ─────────────

/// A gateway whose session lifecycle records every key a sweep reclaims, so a
/// row can assert WHICH key was tracked (the shape of
/// `tests/mik_7215_control4_track_acs.rs`).
async fn tracked_gateway(
    auth: &AuthConfig,
) -> (
    axum::Router,
    Arc<crate::gateway::session_lifecycle::SessionLifecycle>,
    Arc<std::sync::Mutex<Vec<String>>>,
    tempfile::TempDir,
) {
    use crate::gateway::session_lifecycle::SessionLifecycle;
    let lifecycle = Arc::new(SessionLifecycle::new());
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    lifecycle.register("recorder", move |key| {
        sink.lock().expect("recorder").push(key.to_string());
    });
    let fw = firewall(false);
    let (mut state, store) = state_with_firewalls_and_auth(Arc::clone(&fw), fw, auth).await;
    Arc::get_mut(&mut state)
        .expect("a freshly built state has one owner")
        .session_lifecycle = Some(Arc::clone(&lifecycle));
    (create_router(state), lifecycle, seen, store)
}

#[tokio::test]
async fn h17_a_keyed_direct_route_caller_is_tracked_under_its_key() {
    use crate::gateway::session_lifecycle::{IDLE_TTL, now_unix};
    let auth = keys(vec![api_key("key-one", "one")]);
    let (router, lifecycle, reclaimed, _store) = tracked_gateway(&auth).await;
    let before = now_unix().expect("clock after 1970");
    let (outcome, _, body) = send(&router, direct_call("key-one", 0)).await;
    assert_eq!(outcome, Delivered, "{body}");
    assert_eq!(
        lifecycle.tracked_count(),
        1,
        "the direct route scored a caller it never tracks, so its state is never reclaimed"
    );
    // The same caller on /mcp renews that one entry rather than adding a
    // second: both routes track the caller under ONE key.
    let meta = Caller {
        bearer: Some("key-one"),
        ..Caller::default()
    };
    let _ = send(&router, call(&meta, true, None, 1)).await;
    assert_eq!(
        lifecycle.tracked_count(),
        1,
        "the direct and meta routes tracked one caller under two keys"
    );
    // Same deadline as the meta route's write site: one IDLE_TTL out
    // (tests/mik_7215_control4_track_acs.rs:71-80; `reap` is strict).
    assert_eq!(
        lifecycle.reap(before + IDLE_TTL.as_secs() - 1),
        0,
        "reclaimed before its deadline"
    );
    assert_eq!(
        lifecycle.reap(now_unix().expect("clock after 1970") + IDLE_TTL.as_secs() + 1),
        1,
        "not reclaimed past its deadline"
    );
    let keys = reclaimed.lock().expect("recorder").clone();
    assert!(
        keys.len() == 1 && keys[0].starts_with("credential:"),
        "tracked under a key that is not the caller's: {keys:?}"
    );
}

#[tokio::test]
async fn h17b_the_per_backend_fallback_is_never_tracked() {
    // Auth off: no caller key, so the direct route falls back to its
    // per-backend bucket, which is shared state and must not be reclaimed.
    let (router, lifecycle, _reclaimed, _store) = tracked_gateway(&AuthConfig::default()).await;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "id": 0, "method": "tools/call",
                    "params": { "name": TOOL, "arguments": {} } })
            .to_string(),
        ))
        .unwrap();
    let (outcome, _, body) = send(&router, request).await;
    assert_eq!(outcome, Delivered, "{body}");
    assert_eq!(
        lifecycle.tracked_count(),
        0,
        "the shared per-backend bucket was tracked"
    );
}

// ── #1785 tenant arm: the tenant guard's decision follows the caller key ─────

/// Tenant guard on (one tenant per caller per window, tenant named by the
/// `tenant` argument); budget and anomaly off, so only the tenant guard binds.
fn tenant_firewall() -> Arc<Firewall> {
    Arc::new(
        Firewall::from_config(
            FirewallConfig {
                enabled: true,
                scan_requests: true,
                scan_responses: false,
                tenant_guard: crate::security::firewall::tenant_guard::TenantGuardConfig {
                    enabled: true,
                    max_tenants_per_window: 1,
                    window_secs: 3600,
                    arg_keys: vec!["tenant".to_string()],
                    ..Default::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .keyed_for_test(),
    )
}

#[tokio::test]
async fn h18_one_caller_has_one_tenant_breadth_across_both_routes() {
    // Before the fix the per-backend route keys every caller on
    // `direct:demo`, so a caller who used its one tenant on /mcp reaches a
    // second tenant there: the second call is delivered.
    let fw = tenant_firewall();
    let auth = keys(vec![api_key("key-one", "one")]);
    let (state, _store) = state_with_firewalls_and_auth(Arc::clone(&fw), fw, &auth).await;
    let router = create_router(state);
    let meta = Caller {
        bearer: Some("key-one"),
        ..Caller::default()
    };
    let (first, _, body) = send(
        &router,
        call_with(&meta, true, None, 0, &json!({ "tenant": "acme" })),
    )
    .await;
    assert_eq!(
        first, Delivered,
        "the first tenant is within the limit: {body}"
    );
    let (second, _, body) = send(
        &router,
        direct_call_with("key-one", 1, &json!({ "tenant": "globex" })),
    )
    .await;
    assert_eq!(
        second, TenantReach,
        "the direct route gave the caller a second tenant breadth: {body}"
    );
}

// ── Credential and subject never share a key ─────────────────────────────────

#[tokio::test]
async fn h12_a_credential_and_the_subject_behind_it_are_different_keys() {
    // One API key throughout; the second call also proves an agent. A resolved
    // subject outranks the credential, so the second call is keyed on
    // Subject(agent-a), not on Credential(key-one), and has its own budget.
    // Before the fix the agent is ignored: both calls are Credential(key-one),
    // and the second is budget-refused.
    let auth = keys(vec![api_key("key-one", "one")]);
    let key_only = Caller {
        bearer: Some("key-one"),
        ..Caller::default()
    };
    let key_and_agent = Caller {
        bearer: Some("key-one"),
        agent: Some(agent("agent-a")),
        cert: None,
    };
    let got = modern_run(firewall(false), &auth, &[key_only, key_and_agent]).await;
    assert_eq!(
        got,
        [Delivered, Delivered],
        "a subject shared its credential's key"
    );
}

// ── /mcp/{name} keys a subject-only caller on its subject ────────────────────

#[tokio::test]
async fn h20_mcp_name_keys_an_agent_only_caller_on_its_subject() {
    // No API key: only the resolved grant subject can key this caller. If
    // /mcp/{name} stopped receiving it, both agents would fall back to the
    // shared per-backend bucket and agent-b's first call would be refused.
    let fw = firewall(false);
    let (state, _store) =
        state_with_firewalls_and_auth(Arc::clone(&fw), fw, &AuthConfig::default()).await;
    let router = create_router(state);
    let per_backend_as = |id: &str, n: usize| {
        let body = json!({
            "jsonrpc": "2.0", "id": n, "method": "tools/call",
            "params": { "name": TOOL, "arguments": {} }
        });
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp/demo")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        request.extensions_mut().insert(agent(id));
        request
    };
    let mut got = Vec::new();
    for (n, id) in ["agent-a", "agent-a", "agent-b"].into_iter().enumerate() {
        let (outcome, _, body) = send(&router, per_backend_as(id, n)).await;
        eprintln!("call {n}: {outcome:?} {body}");
        got.push(outcome);
    }
    assert_eq!(got, [Delivered, BudgetSpent, Delivered]);
}

#[path = "caller_key_routes.rs"]
mod routes;

mod tenant_reads;
