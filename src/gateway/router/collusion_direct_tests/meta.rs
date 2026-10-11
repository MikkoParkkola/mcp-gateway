// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COLLUDE.1 §13.3: relay detection on the meta route (`/mcp`), rows M1, M2,
//! M4, M5, M7, M10, M11 and M13, on the direct suite's fixture with the
//! Meta-MCP holding the same firewall, so both routes share one detector.

use super::*;

/// The direct fixture, its Meta-MCP replaced by one holding the router's
/// firewall, idempotency, and `cache` when a row reads the response cache.
pub(super) async fn meta_fixture(
    setup: Setup,
    cache: Option<Arc<crate::cache::ResponseCache>>,
) -> Fixture {
    meta_fixture_with(setup, cache, |meta| meta).await
}

/// [`meta_fixture`] with `configure` applied to the Meta-MCP before it is
/// installed.
async fn meta_fixture_with(
    setup: Setup,
    cache: Option<Arc<crate::cache::ResponseCache>>,
    configure: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fixture {
    let mut fx = fixture(setup).await;
    let st = Arc::get_mut(&mut fx.state).expect("state is unique");
    let ttl = Duration::from_secs(600);
    let mut meta = MetaMcp::with_features(Arc::clone(&st.backends), cache, None, None, ttl);
    // The replacement gateway mints with the keyring the router's firewall
    // exempts, as startup pairs them (#2210, MIK-8276).
    if let Some(firewall) = &st.firewall {
        meta.share_keyring_with_for_test(firewall);
    }
    meta.set_firewall(st.firewall.clone());
    meta.enable_idempotency(Arc::new(IdempotencyCache::new()), Duration::from_secs(300));
    st.meta_mcp = Arc::new(configure(meta));
    fx
}

/// The `_meta` of a modern request, with `extra` merged in.
fn meta_of(extra: &Value) -> Value {
    let mut meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                          "io.modelcontextprotocol/clientCapabilities": {}});
    if let (Some(meta), Some(extra)) = (meta.as_object_mut(), extra.as_object()) {
        meta.extend(extra.clone());
    }
    meta
}

/// `_meta` carrying an idempotency key.
fn keyed(key: &str) -> Value {
    json!({ IDEMPOTENCY_KEY_META: key })
}

/// `gateway_invoke` arguments for `alpha:{tool}`.
fn invoke(tool: &str, arguments: &Value) -> Value {
    json!({"server": "alpha", "tool": tool, "arguments": arguments})
}

/// POST one meta `tools/call` of `name` to `/mcp` as bearer `who`.
async fn post(
    fx: &Fixture,
    who: Option<&str>,
    name: &str,
    arguments: &Value,
    extra: &Value,
) -> (u16, String) {
    post_with(fx, who, name, arguments, extra, None).await
}

/// [`post`], the caller also presenting `identity` as a verified OIDC caller.
async fn post_with(
    fx: &Fixture,
    who: Option<&str>,
    name: &str,
    arguments: &Value,
    extra: &Value,
    identity: Option<crate::key_server::oidc::VerifiedIdentity>,
) -> (u16, String) {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": name, "arguments": arguments, "_meta": meta_of(extra)}});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name);
    if let Some(who) = who {
        request = request.header("authorization", format!("Bearer {who}"));
    }
    let mut request = request
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    if let Some(identity) = identity {
        request.extensions_mut().insert(identity);
    }
    let response = create_router(Arc::clone(&fx.state))
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// `who` reads `alpha:read` through `gateway_invoke`; the answer must be
/// delivered and carry the orchard text.
async fn meta_read(fx: &Fixture, who: Option<&str>) {
    let (status, body) = post(
        fx,
        who,
        "gateway_invoke",
        &invoke("read", &json!({})),
        &json!({}),
    )
    .await;
    let answer = envelope(&body);
    assert_eq!(status, 200, "base: the read is answered: {body}");
    assert!(
        answer.get("error").is_none(),
        "base: the read is delivered: {body}"
    );
    assert!(
        body.contains("orchard ledger"),
        "base: the read carries the text: {body}"
    );
}

/// `who` sends `text` through `gateway_invoke` of `alpha:send`.
async fn meta_send(fx: &Fixture, who: Option<&str>, text: &str) -> (u16, String) {
    let args = invoke("send", &json!({"text": text}));
    post(fx, who, "gateway_invoke", &args, &json!({})).await
}

/// A relay refusal with `-32002`, before the backend was called.
fn assert_meta_refused(fx: &Fixture, (_, body): &(u16, String), sends: usize) {
    let answer = envelope(body);
    assert_eq!(answer["error"]["code"], -32002, "relay not refused: {body}");
    let message = answer["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("Relay detection blocked"), "{body}");
    assert!(answer.get("result").is_none(), "{body}");
    assert_eq!(fx.sends(), sends, "the backend was called: {body}");
}

/// A send that reached the backend and was answered.
fn assert_meta_sent(fx: &Fixture, (status, body): &(u16, String), sends: usize) {
    let answer = envelope(body);
    assert_eq!(*status, 200, "{body}");
    assert!(answer.get("error").is_none(), "not sent: {body}");
    assert!(answer.get("result").is_some(), "{body}");
    assert_eq!(fx.sends(), sends, "{body}");
}

/// M1: A reads through `gateway_invoke`; B sending it through `gateway_invoke`
/// is refused before dispatch, and the key is released for a clean call.
#[tokio::test]
async fn meta_invoke_relay_refused() {
    let fx = meta_fixture(Setup::default(), None).await;
    meta_read(&fx, Some("a")).await;
    let relay = invoke("send", &json!({"text": PROSE}));
    let refused = post(&fx, Some("b"), "gateway_invoke", &relay, &keyed("key-m1")).await;
    assert_meta_refused(&fx, &refused, 0);
    assert_eq!(refused.0, 403, "{}", refused.1);
    let clean = invoke("send", &json!({"text": "hello"}));
    let sent = post(&fx, Some("b"), "gateway_invoke", &clean, &keyed("key-m1")).await;
    assert_meta_sent(&fx, &sent, 1);
}

/// M2: a chain step keeps `-32002`.
#[tokio::test]
async fn meta_chain_relay_refused() {
    let fx = meta_fixture(Setup::default(), None).await;
    meta_read(&fx, Some("a")).await;
    let chain = json!({"chain": [{"tool": "alpha:send", "arguments": {"text": PROSE}}]});
    let refused = post(&fx, Some("b"), "gateway_execute", &chain, &json!({})).await;
    assert_meta_refused(&fx, &refused, 0);
}

/// M2: a playbook step is refused as "not permitted" (A3) and never sent.
#[tokio::test]
async fn meta_playbook_relay_not_sent() {
    let fx = meta_fixture(Setup::default(), None).await;
    let definition: crate::playbook::PlaybookDefinition = serde_json::from_value(json!({
        "name": "relay_pb", "description": "sends the orchard text", "on_error": "abort",
        "steps": [{"name": "send", "server": "alpha", "tool": "send",
                   "arguments": {"text": PROSE}}]
    }))
    .expect("playbook fixture parses");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    fx.state.meta_mcp.set_playbook_engine(engine);
    meta_read(&fx, Some("a")).await;
    let run = json!({"name": "relay_pb", "arguments": {}});
    let (_, body) = post(&fx, Some("b"), "gateway_run_playbook", &run, &json!({})).await;
    assert_eq!(
        fx.sends(),
        0,
        "the refused step reached its backend: {body}"
    );
    assert_eq!(envelope(&body)["error"]["code"], -32003, "{body}");
}

/// M4: A's text in `_meta.progressToken` or `_meta.baggage` is forwarded, so
/// it is checked.
#[tokio::test]
async fn meta_relay_in_outbound_meta_refused() {
    let fx = meta_fixture(Setup::default(), None).await;
    meta_read(&fx, Some("a")).await;
    let clean = invoke("send", &json!({"text": "hello"}));
    for field in ["progressToken", "baggage"] {
        let extra = json!({ field: PROSE });
        let refused = post(&fx, Some("b"), "gateway_invoke", &clean, &extra).await;
        assert_meta_refused(&fx, &refused, 0);
    }
}

/// M5: a read the response firewall refused records nothing: B, with no
/// copy, sends it. The control then records a delivered read.
#[tokio::test]
async fn meta_refused_delivery_not_recorded() {
    let setup = Setup {
        rules: "[{match: read, action: block}]",
        ..Setup::default()
    };
    let fx = meta_fixture(setup, None).await;
    fx.answer_read(Read::Injected);
    let args = invoke("read", &json!({}));
    let (_, body) = post(&fx, Some("a"), "gateway_invoke", &args, &json!({})).await;
    assert!(
        envelope(&body).get("error").is_some(),
        "base: the read is refused: {body}"
    );
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), PROSE).await, 1);
    fx.answer_read(Read::Text(PROSE.to_string()));
    meta_read(&fx, Some("a")).await;
    assert_meta_refused(&fx, &meta_send(&fx, Some("b"), PROSE).await, 1);
}

/// A second note, distinct from [`PROSE`], so a refusal of B's send can only
/// come from the second read's receipt.
const OTHER: &str = "Minutes of the harbour committee list the mooring fees for the winter \
    quarter, the dredging contract awarded to the lowest bidder, the complaint about the \
    floodlights over the fish market, and the vote to repaint the lighthouse keeper's cottage.";

/// MIN.2 x M5: a read the tenant guard withheld records no receipt either.
/// A reads tenant t1, then t2 (withheld under `block`); B, who never saw t2's
/// text, sends it and is not refused. The control: B then reads t2 as its own
/// first tenant, delivered, and A's relay of that text is refused.
#[tokio::test]
async fn meta_tenant_withheld_delivery_not_recorded() {
    let setup = Setup {
        tenants: true,
        ..Setup::default()
    };
    let fx = meta_fixture(setup, None).await;
    let named =
        |tenant: &str, note: &str| format!("{{\"customer_id\":\"{tenant}\",\"note\":\"{note}\"}}");
    fx.answer_read(Read::Text(named("t1", PROSE)));
    meta_read(&fx, Some("a")).await;
    fx.answer_read(Read::Text(named("t2", OTHER)));
    let args = invoke("read", &json!({}));
    let (_, body) = post(&fx, Some("a"), "gateway_invoke", &args, &json!({})).await;
    assert!(
        body.contains("Response withheld"),
        "base: the second tenant's read is withheld by the tenant guard: {body}"
    );
    let text = named("t2", OTHER);
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), &text).await, 1);
    // Control: delivered, the same text records a receipt. The added space
    // changes the response-cache key, as in M7.
    let (_, delivered) = post(&fx, Some("b"), "gateway_invoke", &args, &json!({})).await;
    assert!(
        envelope(&delivered).get("error").is_none(),
        "control: B's first tenant is delivered: {delivered}"
    );
    let relay = format!("{text} ");
    assert_meta_refused(&fx, &meta_send(&fx, Some("a"), &relay).await, 1);
}

/// M7: a response-cache hit renews A's receipt after the first expired.
#[tokio::test]
async fn meta_cache_hit_recorded() {
    let setup = Setup {
        window_secs: 1,
        ..Setup::default()
    };
    let cache = Some(Arc::new(crate::cache::ResponseCache::new()));
    let fx = meta_fixture(setup, cache).await;
    meta_read(&fx, Some("a")).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), PROSE).await, 1);
    let reads = fx.reads();
    meta_read(&fx, Some("a")).await;
    assert_eq!(fx.reads(), reads, "base: the re-read must be a cache hit");
    // Not B's first call again: that one is in B's own response cache, served
    // without a backend call and so without an egress to check. The added
    // space changes the cache key and leaves the fingerprints alone.
    let relay = format!("{PROSE} ");
    assert_meta_refused(&fx, &meta_send(&fx, Some("b"), &relay).await, 1);
}

/// M10: an unkeyed meta egress is refused under `block`.
#[tokio::test]
async fn meta_unkeyed_block_refused() {
    let setup = Setup {
        auth: false,
        ..Setup::default()
    };
    let fx = meta_fixture(setup, None).await;
    let refused = meta_send(&fx, None, "hello").await;
    assert_meta_refused(&fx, &refused, 0);
    assert!(refused.1.contains("authenticated caller"), "{}", refused.1);
}

/// M10: under `observe` an unkeyed relay is let through (green on the base by
/// nature: nothing refuses there yet).
#[tokio::test]
async fn meta_unkeyed_observe_allowed() {
    let setup = Setup {
        auth: false,
        action: CollusionAction::Observe,
        ..Setup::default()
    };
    let fx = meta_fixture(setup, None).await;
    meta_read(&fx, None).await;
    assert_meta_sent(&fx, &meta_send(&fx, None, PROSE).await, 1);
}

/// M11: each chain step records under its own target. A's chain sends
/// (unrelated) then reads; B's own `alpha:read` copy then excuses B, which it
/// would not if A's receipt were filed under the chain's first target.
#[tokio::test]
async fn meta_chain_attribution_per_step() {
    let fx = meta_fixture(Setup::default(), None).await;
    let chain = json!({"chain": [
        {"tool": "alpha:send", "arguments": {"text": "hello"}},
        {"tool": "alpha:read", "arguments": {}}
    ]});
    let (_, body) = post(&fx, Some("a"), "gateway_execute", &chain, &json!({})).await;
    assert!(
        envelope(&body).get("error").is_none(),
        "base: the chain runs: {body}"
    );
    assert_eq!(fx.sends(), 1, "base: the chain's first step ran: {body}");
    assert_meta_refused(&fx, &meta_send(&fx, Some("b"), PROSE).await, 1);
    meta_read(&fx, Some("b")).await;
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), PROSE).await, 2);
}

/// M13: an `isError` result A was delivered is a source.
#[tokio::test]
async fn meta_is_error_result_recorded() {
    let fx = meta_fixture(Setup::default(), None).await;
    fx.answer_read(Read::IsError);
    let args = invoke("read", &json!({}));
    let (_, body) = post(&fx, Some("a"), "gateway_invoke", &args, &json!({})).await;
    assert!(
        envelope(&body).get("error").is_none(),
        "base: delivered: {body}"
    );
    assert!(
        body.contains("orchard ledger"),
        "base: carries the text: {body}"
    );
    assert_meta_refused(&fx, &meta_send(&fx, Some("b"), PROSE).await, 0);
}

/// r3 #3: an outer replay of a single-target call renews the caller's
/// receipt after the first expired.
#[tokio::test]
async fn meta_replay_renews_the_receipt() {
    let setup = Setup {
        window_secs: 1,
        ..Setup::default()
    };
    let fx = meta_fixture(setup, None).await;
    let read = invoke("read", &json!({}));
    let (_, first) = post(&fx, Some("a"), "gateway_invoke", &read, &keyed("key-r3")).await;
    assert!(first.contains("orchard ledger"), "base: {first}");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), PROSE).await, 1);
    let reads = fx.reads();
    let (_, replay) = post(&fx, Some("a"), "gateway_invoke", &read, &keyed("key-r3")).await;
    assert!(replay.contains("orchard ledger"), "base: {replay}");
    assert_eq!(
        fx.reads(),
        reads,
        "base: the re-issue must be a replay: {replay}"
    );
    assert_meta_refused(&fx, &meta_send(&fx, Some("b"), PROSE).await, 1);
}

/// Row 13 on the meta route: an allowlisted flow is not refused under `block`.
#[tokio::test]
async fn meta_allowed_flow_not_refused() {
    let setup = Setup {
        allowed_flows: vec![crate::security::firewall::AllowedFlow {
            source: "alpha:read".to_string(),
            egress: "alpha:send".to_string(),
        }],
        ..Setup::default()
    };
    let fx = meta_fixture(setup, None).await;
    meta_read(&fx, Some("a")).await;
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), PROSE).await, 1);
}

/// MIK-7800 (pin): on the meta route a read whose delivery record the log
/// refuses under `fail-closed` is replaced before the receipts commit (the
/// record is written inside the dispatch since MIK-7799): B sending A's text
/// is not refused; the next read is audited, delivered and recorded.
#[tokio::test]
async fn meta_read_record_failure_leaves_no_receipt() {
    use crate::security::TransparencyLogger;
    use crate::security::audit::AuditFailurePolicy;
    use crate::security::transparency_log::TransparencyLogConfig;
    let mut fx = meta_fixture(
        Setup {
            tenants: true,
            ..Setup::default()
        },
        None,
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "rv".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log")
        .with_failure_policy(AuditFailurePolicy::FailClosed),
    );
    let state = Arc::get_mut(&mut fx.state).expect("state is unique");
    Arc::get_mut(&mut state.meta_mcp)
        .expect("meta is unique")
        .enable_transparency_log(Arc::clone(&log));
    let text = format!("{{\"customer_id\":\"t1\",\"note\":\"{PROSE}\"}}");
    fx.answer_read(Read::Text(text.clone()));
    let args = invoke("read", &json!({}));
    log.fail_next_append_for_test();
    let (_, body) = post(&fx, Some("a"), "gateway_invoke", &args, &json!({})).await;
    assert!(
        body.contains("-32005"),
        "base: the failed read record withholds the read: {body}"
    );
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), &text).await, 1);
    let (_, delivered) = post(&fx, Some("a"), "gateway_invoke", &args, &json!({})).await;
    assert!(
        envelope(&delivered).get("error").is_none(),
        "control: the audited read is delivered: {delivered}"
    );
    let relay = format!("{text} ");
    assert_meta_refused(&fx, &meta_send(&fx, Some("b"), &relay).await, 1);
}

/// MIK-7830: as above for the grant-decision record. A personal capability
/// read whose decision record the log refuses under `fail-closed` is
/// withheld before the receipts commit: B sending its text is not refused;
/// the next read is decided, delivered and recorded, and B relaying it is.
#[tokio::test]
async fn meta_grant_decision_failure_leaves_no_receipt() {
    use crate::gateway::meta_mcp::grant_audit_fixture::{
        CAPS, DECISION_KIND, PERSONAL, capability_backend, grant, grants, logger,
    };
    use crate::security::audit::AuditFailurePolicy;
    // A personal capability needs a proven caller identity, which a bearer
    // key never carries on HTTP: caller A also presents a verified identity,
    // and that identity owns the capability.
    const ALICE: (&str, &str) = ("https://idp.example.invalid", "alice-sub");
    let alice = || crate::key_server::oidc::VerifiedIdentity {
        subject: ALICE.1.to_string(),
        email: "alice@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: ALICE.0.to_string(),
    };
    // The capability's endpoint answers the relayable prose.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = axum::Router::new().route(
        "/read",
        axum::routing::get(|| async { axum::Json(json!({ "note": PROSE })) }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, endpoint).await;
    });
    let mut fx = meta_fixture(
        Setup {
            sources: vec![format!("{CAPS}:{PERSONAL}")],
            ..Setup::default()
        },
        None,
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let log = logger(&dir, AuditFailurePolicy::FailClosed);
    let state = Arc::get_mut(&mut fx.state).expect("state is unique");
    let meta = Arc::get_mut(&mut state.meta_mcp).expect("meta is unique");
    meta.enable_transparency_log(Arc::clone(&log));
    meta.set_identity_grants(grants(vec![grant("g1", ALICE, ALICE)]));
    meta.set_capabilities(capability_backend(port, ALICE));
    let args = json!({"server": CAPS, "tool": PERSONAL, "arguments": {}});

    log.fail_next_append_of_kind_for_test(DECISION_KIND);
    let (_, body) = post_with(
        &fx,
        Some("a"),
        "gateway_invoke",
        &args,
        &json!({}),
        Some(alice()),
    )
    .await;
    assert_eq!(
        envelope(&body)["error"]["code"],
        -32005,
        "base: the failed decision record withholds the read: {body}"
    );
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), PROSE).await, 1);
    let (_, delivered) = post_with(
        &fx,
        Some("a"),
        "gateway_invoke",
        &args,
        &json!({}),
        Some(alice()),
    )
    .await;
    assert!(
        envelope(&delivered).get("error").is_none() && delivered.contains(PROSE),
        "control: the decided read is delivered: {delivered}"
    );
    assert_meta_refused(&fx, &meta_send(&fx, Some("b"), PROSE).await, 1);
}

#[path = "meta/writes.rs"]
mod writes;
