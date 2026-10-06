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
    let mut fx = fixture(setup).await;
    let st = Arc::get_mut(&mut fx.state).expect("state is unique");
    let ttl = Duration::from_secs(600);
    let mut meta = MetaMcp::with_features(Arc::clone(&st.backends), cache, None, None, ttl);
    meta.set_firewall(st.firewall.clone());
    meta.enable_idempotency(Arc::new(IdempotencyCache::new()), Duration::from_secs(300));
    st.meta_mcp = Arc::new(meta);
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
    let request = request
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
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

/// MIK-7991 (replay): an idempotent replay of a failed read serves the
/// recovery hint the gateway wrote on the first call, unchanged; the
/// replay's receipt keeps the backend's failure text and leaves the hint out.
#[tokio::test]
async fn meta_replay_leaves_the_gateway_hint_out_of_the_receipt() {
    use crate::gateway::meta_mcp::invoke::receipt_test_support::{backend_failure, own_hint_text};
    let fx = meta_fixture(Setup::default(), None).await;
    let failed = backend_failure(PROSE);
    fx.answer_read(Read::Failed(failed.clone()));
    let read = invoke("read", &json!({}));
    let (_, first) = post(&fx, Some("a"), "gateway_invoke", &read, &keyed("key-7991")).await;
    let own = own_hint_text(&envelope(&first)["result"], &failed);
    let reads = fx.reads();
    let (_, replay) = post(&fx, Some("a"), "gateway_invoke", &read, &keyed("key-7991")).await;
    assert_eq!(
        fx.reads(),
        reads,
        "base: the re-issue must be a replay: {replay}"
    );
    assert_eq!(
        own_hint_text(&envelope(&replay)["result"], &failed),
        own,
        "the replay serves the hint it stored: {replay}"
    );
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), &own).await, 1);
    assert_meta_refused(&fx, &meta_send(&fx, Some("b"), &failed).await, 1);
}

/// A cost category long enough that the gateway's suggestion naming it is
/// text a receipt holding it would be caught on (79 chars and more).
#[cfg(feature = "cost-governance")]
const CATEGORY: &str =
    "cellar inventory of pressed cider barrels sorted by vintage, cask size and orchard row";

/// `dear` costs 1.0 and `cheap`, in the same [`CATEGORY`], 0.1: every answer
/// to `dear` gets the gateway's `_cost_suggestion` naming the category.
#[cfg(feature = "cost-governance")]
fn suggest(fx: &mut Fixture, dear: &str, cheap: &str) {
    use crate::cost_accounting::config::CostGovernanceConfig;
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.tool_costs.insert(dear.to_string(), 1.0);
    cfg.tool_costs.insert(cheap.to_string(), 0.1);
    cfg.alternatives = Some(
        [(
            CATEGORY.to_string(),
            vec![dear.to_string(), cheap.to_string()],
        )]
        .into_iter()
        .collect(),
    );
    let registry = Arc::new(crate::cost_accounting::registry::CostRegistry::new(&cfg));
    let enforcer = Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
        cfg,
        Arc::clone(&registry),
    ));
    let state = Arc::get_mut(&mut fx.state).expect("state is unique");
    let meta = Arc::get_mut(&mut state.meta_mcp).expect("meta is unique");
    meta.budget_enforcer = Some(enforcer);
    meta.cost_registry = Some(registry);
}

/// MIK-7991.CACHE.1: a response-cache hit serves the cost suggestion the
/// gateway wrote on the first call; the hit's receipt leaves it out and
/// keeps the backend's text.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn meta_cache_hit_leaves_the_cost_suggestion_out_of_the_receipt() {
    let cache = Some(Arc::new(crate::cache::ResponseCache::new()));
    let mut fx = meta_fixture(Setup::default(), cache).await;
    suggest(&mut fx, "read", "send");
    let read = invoke("read", &json!({}));
    let (_, first) = post(&fx, Some("a"), "gateway_invoke", &read, &json!({})).await;
    assert!(
        first.contains(CATEGORY),
        "base: the gateway suggested a cheaper tool: {first}"
    );
    let reads = fx.reads();
    let (_, hit) = post(&fx, Some("a"), "gateway_invoke", &read, &json!({})).await;
    assert_eq!(fx.reads(), reads, "base: the re-read must be a cache hit");
    assert!(
        hit.contains(CATEGORY),
        "the hit serves the suggestion: {hit}"
    );
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), CATEGORY).await, 1);
    let relay = format!("{PROSE} ");
    assert_meta_refused(&fx, &meta_send(&fx, Some("b"), &relay).await, 1);
}

/// MIK-7991 (replay): an idempotent replay of a successful read serves the
/// cost suggestion the gateway wrote on the first call; the replay's
/// receipt leaves it out and keeps the backend's text.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn meta_replay_leaves_the_cost_suggestion_out_of_the_receipt() {
    let mut fx = meta_fixture(Setup::default(), None).await;
    suggest(&mut fx, "read", "send");
    let read = invoke("read", &json!({}));
    let (_, first) = post(
        &fx,
        Some("a"),
        "gateway_invoke",
        &read,
        &keyed("key-7991-ok"),
    )
    .await;
    assert!(
        first.contains(CATEGORY),
        "base: the gateway suggested a cheaper tool: {first}"
    );
    let reads = fx.reads();
    let (_, replay) = post(
        &fx,
        Some("a"),
        "gateway_invoke",
        &read,
        &keyed("key-7991-ok"),
    )
    .await;
    assert_eq!(fx.reads(), reads, "base: the re-issue must be a replay");
    assert!(
        replay.contains(CATEGORY),
        "the replay serves the suggestion: {replay}"
    );
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), CATEGORY).await, 1);
    let relay = format!("{PROSE} ");
    assert_meta_refused(&fx, &meta_send(&fx, Some("b"), &relay).await, 1);
}

/// MIK-7991 (R5): an unkeyed read, a keyed response-cache hit on it (which
/// settles the key with the cached answer) and a keyed replay of that key
/// all serve the first call's suggestion unchanged, and after each hit the
/// receipt still leaves it out and keeps the backend's text.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn meta_cache_hit_then_replay_leave_the_suggestion_out() {
    let cache = Some(Arc::new(crate::cache::ResponseCache::new()));
    let mut fx = meta_fixture(Setup::default(), cache).await;
    suggest(&mut fx, "read", "send");
    let read = invoke("read", &json!({}));
    let key = keyed("key-7991-r5");
    let (_, first) = post(&fx, Some("a"), "gateway_invoke", &read, &json!({})).await;
    let own = cost_suggestion(&first);
    let reads = fx.reads();
    let (_, hit) = post(&fx, Some("a"), "gateway_invoke", &read, &key).await;
    assert_eq!(fx.reads(), reads, "base: the keyed re-read is a hit: {hit}");
    assert_eq!(cost_suggestion(&hit), own, "the hit serves it unchanged");
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), CATEGORY).await, 1);
    let (_, replay) = post(&fx, Some("a"), "gateway_invoke", &read, &key).await;
    assert_eq!(fx.reads(), reads, "base: the keyed re-issue is a replay");
    assert_eq!(
        cost_suggestion(&replay),
        own,
        "the replay serves it unchanged"
    );
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), CATEGORY).await, 2);
    let relay = format!("{PROSE} ");
    assert_meta_refused(&fx, &meta_send(&fx, Some("b"), &relay).await, 2);
}

/// The `_cost_suggestion` a meta answer carries, read from the result or
/// from the JSON text it is wrapped in.
#[cfg(feature = "cost-governance")]
fn cost_suggestion(body: &str) -> Value {
    let result = &envelope(body)["result"];
    let wrapped = result["content"][0]["text"]
        .as_str()
        .and_then(|text| serde_json::from_str::<Value>(text).ok());
    let found = wrapped.as_ref().unwrap_or(result)["_cost_suggestion"].clone();
    assert!(
        found.to_string().contains(CATEGORY),
        "base: no suggestion: {body}"
    );
    found
}

/// MIK-7991 (R4): a plan step's cache entry holds only that step's writes.
/// Step A (`send`) gets the gateway's suggestion; step B (`read`) answers
/// with a backend member equal to it. A later hit on B's entry keeps that
/// backend member in the receipt, so relaying it is refused.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn meta_chain_step_entry_holds_only_its_own_writes() {
    let cache = Some(Arc::new(crate::cache::ResponseCache::new()));
    let mut fx = meta_fixture(Setup::default(), cache).await;
    suggest(&mut fx, "send", "read");
    let (_, sent) = meta_send(&fx, Some("a"), "hello").await;
    let mut answer = json!({"content": [{"type": "text", "text": "seven rows"}], "isError": false});
    answer["_cost_suggestion"] = cost_suggestion(&sent);
    fx.answer_read(Read::Raw(answer));
    let chain = json!({"chain": [
        {"tool": "alpha:send", "arguments": {"text": "hello"}},
        {"tool": "alpha:read", "arguments": {}}
    ]});
    let (_, body) = post(&fx, Some("a"), "gateway_execute", &chain, &json!({})).await;
    assert!(
        envelope(&body).get("error").is_none() && fx.sends() == 2,
        "base: the chain runs: {body}"
    );
    let reads = fx.reads();
    let read = invoke("read", &json!({}));
    let (_, hit) = post(&fx, Some("a"), "gateway_invoke", &read, &json!({})).await;
    assert_eq!(
        fx.reads(),
        reads,
        "base: the read is a hit on B's entry: {hit}"
    );
    assert_meta_refused(&fx, &meta_send(&fx, Some("b"), CATEGORY).await, 2);
}

/// The notice the gateway settles a key with when a post-dispatch gate
/// withheld the answer (`side_effect_markers::withheld_side_effect`).
const WITHHELD: &str = "Side effect executed; the response was withheld by a post-dispatch \
    gate. Retrying with the same idempotency key will not re-execute it.";

/// MIK-7991 (notice): a keyed read the response firewall refuses settles its
/// key with the gateway's withheld notice. Replaying it serves that notice,
/// the gateway's own text, so it puts nothing in the replay's receipt.
#[tokio::test]
async fn meta_replayed_gateway_notice_is_not_receipted() {
    let setup = Setup {
        rules: "[{match: read, action: block}]",
        ..Setup::default()
    };
    let fx = meta_fixture(setup, None).await;
    fx.answer_read(Read::Injected);
    let read = invoke("read", &json!({}));
    let key = keyed("key-7991-notice");
    let (_, first) = post(&fx, Some("a"), "gateway_invoke", &read, &key).await;
    assert!(
        envelope(&first).get("error").is_some(),
        "base: the read is refused: {first}"
    );
    let reads = fx.reads();
    let (_, replay) = post(&fx, Some("a"), "gateway_invoke", &read, &key).await;
    assert_eq!(
        fx.reads(),
        reads,
        "base: the re-issue is a replay: {replay}"
    );
    assert!(
        replay.contains(WITHHELD),
        "base: the replay serves the notice: {replay}"
    );
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), WITHHELD).await, 1);
}
