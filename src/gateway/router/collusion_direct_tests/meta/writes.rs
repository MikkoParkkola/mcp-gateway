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

/// A receipt window short enough that a row can let the first call's receipt
/// lapse, so a later control proves the hit or replay staged its own.
#[cfg(feature = "cost-governance")]
fn short_window() -> Setup {
    Setup {
        window_secs: 1,
        ..Setup::default()
    }
}

/// Let every receipt staged so far lapse ([`short_window`]).
#[cfg(feature = "cost-governance")]
async fn lapse() {
    tokio::time::sleep(Duration::from_millis(1200)).await;
}

/// `dear` costs 1.0 and `cheap`, in the same [`CATEGORY`], 0.1: every answer
/// to `dear` gets the gateway's `_cost_suggestion` naming the category.
#[cfg(feature = "cost-governance")]
fn suggest(fx: &mut Fixture, dear: &str, cheap: &str) {
    let state = Arc::get_mut(&mut fx.state).expect("state is unique");
    let meta = Arc::get_mut(&mut state.meta_mcp).expect("meta is unique");
    meta.suggest_cheaper_for_test(CATEGORY, dear, cheap);
}

/// MIK-7991.CACHE.1: a response-cache hit serves the cost suggestion the
/// gateway wrote on the first call; the hit's receipt leaves it out and
/// keeps the backend's text.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn meta_cache_hit_leaves_the_cost_suggestion_out_of_the_receipt() {
    let cache = Some(Arc::new(crate::cache::ResponseCache::new()));
    let mut fx = meta_fixture(short_window(), cache).await;
    suggest(&mut fx, "read", "send");
    let read = invoke("read", &json!({}));
    let (_, first) = post(&fx, Some("a"), "gateway_invoke", &read, &json!({})).await;
    assert!(
        first.contains(CATEGORY),
        "base: the gateway suggested a cheaper tool: {first}"
    );
    lapse().await;
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
    let mut fx = meta_fixture(short_window(), None).await;
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
    lapse().await;
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
    // Not the first send's text, or the response cache would answer it.
    let again = format!("{CATEGORY} ");
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), &again).await, 2);
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

/// The notice the gateway settles a key with when a round was lost after
/// the send (`side_effect_markers::UNCERTAIN_TEXT`).
const UNCERTAIN: &str = "The call may have reached the backend; its outcome is unknown: it \
    may have executed. Retrying with the same idempotency key will not re-execute it and will \
    return this same notice. Reconcile at the backend before assuming the effect either ran \
    or did not.";

/// Response signing on: an external `gateway_invoke` then waits for signing
/// admission, so the sync admission leaves its key to the invoke path's own
/// idempotency guard, whose replay arm the rows below drive (MIK-7991).
fn signing(mut meta: MetaMcp) -> MetaMcp {
    use crate::security::message_signing::MessageSigner;
    let key = b"collusion-meta-signing-key-0123456789abcdef".to_vec();
    let signer = MessageSigner::new(key, None, "collusion-meta".into());
    meta.enable_message_signing(signer, Duration::from_secs(300), false);
    meta
}

/// MIK-7991 (notice): a keyed read whose round is lost after the send
/// settles its key with the gateway's uncertainty notice (MIK-7979). With
/// signing on, the invoke path's guard replays it as a result: the gateway's
/// own text, so it puts nothing in the replay's receipt.
#[tokio::test]
async fn meta_replayed_gateway_notice_is_not_receipted() {
    let fx = meta_fixture_with(Setup::default(), None, signing).await;
    fx.answer_read(Read::Lost);
    let read = invoke("read", &json!({}));
    let key = keyed("key-7991-notice");
    let (_, first) = post(&fx, Some("a"), "gateway_invoke", &read, &key).await;
    assert!(
        envelope(&first).get("error").is_some(),
        "base: the lost round answers an error: {first}"
    );
    let reads = fx.reads();
    let (_, replay) = post(&fx, Some("a"), "gateway_invoke", &read, &key).await;
    assert_eq!(
        fx.reads(),
        reads,
        "base: the re-issue is a replay: {replay}"
    );
    assert!(
        replay.contains("may have reached the backend"),
        "base: the replay serves the notice: {replay}"
    );
    assert_meta_sent(&fx, &meta_send(&fx, Some("b"), UNCERTAIN).await, 1);
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

/// MIK-7991 r4 (R10): a surfaced tool is called by its own name, so its
/// replay by the sync admission stages the stored result itself, not a
/// `gateway_invoke` wrapper; the suggestion the gateway wrote stays out of
/// that receipt as well, and the backend's text stays in it.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn meta_surfaced_replay_leaves_the_cost_suggestion_out() {
    let surfaced = |meta: MetaMcp| {
        meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
            server: "alpha".to_string(),
            tool: "read".to_string(),
        }])
    };
    let mut fx = meta_fixture_with(Setup::default(), None, surfaced).await;
    suggest(&mut fx, "read", "send");
    let key = keyed("key-7991-surfaced");
    let (_, first) = post(&fx, Some("a"), "read", &json!({}), &key).await;
    let own = cost_suggestion(&first);
    let reads = fx.reads();
    let (_, replay) = post(&fx, Some("a"), "read", &json!({}), &key).await;
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
