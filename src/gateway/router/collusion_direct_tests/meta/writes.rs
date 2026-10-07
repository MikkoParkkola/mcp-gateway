// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7991: what the gateway wrote into an answer stays out of the relay
//! receipts of a response-cache hit and of an idempotent replay.

use super::*;

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
/// Step A (`send`, unlike the first send so not a cache hit) gets the
/// gateway's suggestion; step B (`read`) answers
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
        {"tool": "alpha:send", "arguments": {"text": "hello again"}},
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

/// Response signing on: an external `gateway_invoke` then waits for signing
/// admission, so the sync admission leaves its key to the invoke path's own
/// idempotency guard, whose replay arm the rows below drive (MIK-7991).
fn signing(meta: &mut MetaMcp) {
    use crate::security::message_signing::MessageSigner;
    let key = b"collusion-meta-signing-key-0123456789abcdef".to_vec();
    let signer = MessageSigner::new(key, None, "collusion-meta".into());
    meta.enable_message_signing(signer, Duration::from_secs(300), false);
}

/// MIK-7991 (notice): a keyed read that anomaly screening refuses after
/// dispatch settles its key with the gateway's withheld notice (the
/// reservation's drop value; a firewall refusal stores its own marked error
/// instead). Replaying it serves that notice, the gateway's own text, so it
/// puts nothing in the replay's receipt.
#[tokio::test]
async fn meta_replayed_gateway_notice_is_not_receipted() {
    let fx = meta_fixture_with(Setup::default(), None, |meta| {
        signing(meta);
        meta.enable_response_inspection_action_mode();
    })
    .await;
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

/// MIK-7991 (replay, invoke-path guard): with signing on, an idempotent
/// replay of a successful read is served by the invoke path's own guard; its
/// receipt leaves the stored suggestion out and keeps the backend's text.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn meta_signed_replay_leaves_the_cost_suggestion_out() {
    let mut fx = meta_fixture_with(Setup::default(), None, signing).await;
    suggest(&mut fx, "read", "send");
    let read = invoke("read", &json!({}));
    let key = keyed("key-7991-signed");
    let (_, first) = post(&fx, Some("a"), "gateway_invoke", &read, &key).await;
    let own = cost_suggestion(&first);
    let reads = fx.reads();
    let (_, replay) = post(&fx, Some("a"), "gateway_invoke", &read, &key).await;
    assert_eq!(
        fx.reads(),
        reads,
        "base: the re-issue is a replay: {replay}"
    );
    assert_eq!(
        cost_suggestion(&replay),
        own,
        "the replay serves it unchanged"
    );
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), CATEGORY).await, 1);
    let relay = format!("{PROSE} ");
    assert_meta_refused(&fx, &meta_send(&fx, Some("b"), &relay).await, 1);
}
