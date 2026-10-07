// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.1: tenant attribution on the meta invocation record
//! (test plan T7-T11, T25).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::{api_key_caller, context, meta, only_record, records};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::security::firewall::tenant_guard::TenantGuardConfig;
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::hash_argument;

fn h(id: &str) -> String {
    hash_argument(&json!(id))
}

fn sorted(ids: &[&str]) -> Value {
    let mut hashes: Vec<String> = ids.iter().map(|id| h(id)).collect();
    hashes.sort();
    json!(hashes)
}

/// AWS's documented example access key id, which response inspection rates
/// HIGH. Assembled at runtime so secret scanners do not flag the source.
fn example_access_key() -> String {
    ["AKIA", "IOSFODNN7", "EXAMPLE"].concat()
}

/// A tool result whose text block is JSON naming `tenant`.
fn reply_naming(tenant: &str, extra_text: &str) -> Value {
    let rows = json!({"rows": [{"customer_id": tenant}], "note": extra_text});
    json!({"content": [{"type": "text", "text": rows.to_string()}], "isError": false})
}

/// Attribution on: `arg_keys` set, the guard itself off (observe-only).
fn attributing(mut meta: MetaMcp) -> MetaMcp {
    meta.set_firewall(Some(Arc::new(Firewall::from_config(
        FirewallConfig {
            tenant_guard: TenantGuardConfig {
                arg_keys: vec!["customer_id".to_string()],
                ..TenantGuardConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ))));
    meta
}

fn args_for(tenant: Option<&str>) -> Value {
    let arguments = tenant.map_or_else(|| json!({}), |t| json!({"customer_id": t}));
    json!({"server": "alpha", "tool": "read", "arguments": arguments})
}

fn log_text(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap_or_default()
}

/// T7. The record names request and response tenants, hashed and sorted,
/// next to the kernel's data classes. Also proves the dispatch notes reach
/// the writer after the scope ends.
#[tokio::test]
async fn allowed_call_record_carries_tenants_and_data_classes() {
    let dir = tempfile::tempdir().unwrap();
    let meta = attributing(meta(Ok(reply_naming("cust-9", "")), &dir));
    let who = api_key_caller();
    meta.invoke_tool(&args_for(Some("cust-1")), None, &context(&AllowAll, &who))
        .await
        .expect("allowed call");
    let record = only_record(&dir);
    assert_eq!(record["tenants"], sorted(&["cust-1", "cust-9"]), "{record}");
    assert!(
        record["data_classes"]
            .as_array()
            .is_some_and(|classes| !classes.is_empty()),
        "{record}"
    );
    let text = log_text(&dir);
    for raw in ["cust-1", "cust-9"] {
        assert!(!text.contains(raw), "{raw} written raw: {text}");
    }
}

/// T8. A response the inspection gate refuses still records the response's
/// tenants (captured before the gates), and no data classes (never
/// classified).
#[tokio::test]
async fn gate_refused_response_keeps_response_tenants() {
    let dir = tempfile::tempdir().unwrap();
    let note = format!("AWS_ACCESS_KEY_ID={}", example_access_key());
    let mut refusing = meta(Ok(reply_naming("cust-9", &note)), &dir);
    refusing.enable_response_inspection_action_mode();
    let meta = attributing(refusing);
    let who = api_key_caller();
    let _ = meta
        .invoke_tool(&args_for(Some("cust-1")), None, &context(&AllowAll, &who))
        .await;
    let record = only_record(&dir);
    assert_ne!(record["outcome"], json!("ok"), "{record}");
    let tenants = record["tenants"].as_array().cloned().unwrap_or_default();
    assert!(tenants.contains(&json!(h("cust-9"))), "{record}");
    assert!(record.get("data_classes").is_none(), "{record}");
}

/// T9. No firewall, no attribution: the record keeps its schema.
#[tokio::test]
async fn no_firewall_means_no_attribution_fields() {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta(Ok(reply_naming("cust-9", "")), &dir);
    let who = api_key_caller();
    meta.invoke_tool(&args_for(Some("cust-1")), None, &context(&AllowAll, &who))
        .await
        .expect("allowed call");
    let record = only_record(&dir);
    assert!(record.get("tenants").is_none(), "{record}");
    assert!(record.get("data_classes").is_none(), "{record}");
}

/// T10. A call touching no tenant writes neither field. `data_classes` is
/// never empty, so this catches an unconditional write.
#[tokio::test]
async fn tenantless_call_writes_no_attribution_fields() {
    let dir = tempfile::tempdir().unwrap();
    let plain = json!({"content": [{"type": "text", "text": "{\"ok\":true}"}], "isError": false});
    let meta = attributing(meta(Ok(plain), &dir));
    let who = api_key_caller();
    meta.invoke_tool(&args_for(None), None, &context(&AllowAll, &who))
        .await
        .expect("allowed call");
    let record = only_record(&dir);
    assert!(record.get("tenants").is_none(), "{record}");
    assert!(record.get("data_classes").is_none(), "{record}");
}

/// T11 (route half). The attributed meta record verifies as part of the chain.
#[tokio::test]
async fn attributed_meta_record_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let meta = attributing(meta(Ok(reply_naming("cust-9", "")), &dir));
    let who = api_key_caller();
    meta.invoke_tool(&args_for(Some("cust-1")), None, &context(&AllowAll, &who))
        .await
        .expect("allowed call");
    assert!(only_record(&dir).get("tenants").is_some());
    let verified =
        crate::security::transparency_log::verify_log(&dir.path().join("audit.jsonl")).unwrap();
    assert!(verified.ok, "{verified:?}");
}

/// T25. A response-cache hit records the delivered value's tenants, marked
/// as a cached delivery, without data classes: a post-gate value cannot be
/// re-classified as the raw response was.
#[tokio::test]
async fn cache_hit_record_carries_delivered_tenants() {
    let dir = tempfile::tempdir().unwrap();
    let mut cached = meta(Ok(reply_naming("cust-9", "")), &dir);
    cached.cache = Some(Arc::new(crate::cache::ResponseCache::new()));
    cached.default_cache_ttl = Duration::from_secs(300);
    let meta = attributing(cached);
    let who = api_key_caller();
    for _ in 0..2 {
        meta.invoke_tool(&args_for(Some("cust-1")), None, &context(&AllowAll, &who))
            .await
            .expect("allowed call");
    }
    let all = records(&dir);
    assert_eq!(all.len(), 2, "{all:?}");
    let (miss, hit) = (&all[0], &all[1]);
    assert!(miss.get("attribution").is_none(), "{miss}");
    assert_eq!(hit["attribution"], json!("cached_delivery"), "{hit}");
    assert_eq!(hit["tenants"], sorted(&["cust-1", "cust-9"]), "{hit}");
    assert!(hit.get("data_classes").is_none(), "{hit}");
}

/// A tool result whose one text block is valid JSON naming `tenant`, padded
/// past the 1 MiB attribution parse bound.
fn oversize_reply_naming(tenant: &str) -> Value {
    let pad = "x".repeat(1024 * 1024);
    let rows = json!({"rows": [{"customer_id": tenant}], "pad": pad});
    json!({"content": [{"type": "text", "text": rows.to_string()}], "isError": false})
}

/// MIN.1 gap 2. A response too large to inspect is recorded as such: the
/// record carries `attribution: "uninspected"` and no tenant it could not read.
#[tokio::test]
async fn oversize_response_record_says_uninspected() {
    let dir = tempfile::tempdir().unwrap();
    let meta = attributing(meta(Ok(oversize_reply_naming("cust-9")), &dir));
    let who = api_key_caller();
    meta.invoke_tool(&args_for(None), None, &context(&AllowAll, &who))
        .await
        .expect("allowed call");
    let record = only_record(&dir);
    assert_eq!(record["attribution"], json!("uninspected"), "{record}");
    assert!(record.get("tenants").is_none(), "{record}");
}

/// MIN.1 gap 3. A reply whose JSON is nested past the parse depth limit,
/// though far under 1 MiB, is recorded uninspected, not as naming no tenant.
#[tokio::test]
async fn deep_nested_response_record_says_uninspected() {
    let dir = tempfile::tempdir().unwrap();
    let deep = format!(
        "{}{{\"customer_id\":\"cust-9\"}}{}",
        "[".repeat(200),
        "]".repeat(200)
    );
    let reply = json!({"content": [{"type": "text", "text": deep}], "isError": false});
    let meta = attributing(meta(Ok(reply), &dir));
    let who = api_key_caller();
    meta.invoke_tool(&args_for(None), None, &context(&AllowAll, &who))
        .await
        .expect("allowed call");
    let record = only_record(&dir);
    assert_eq!(record["attribution"], json!("uninspected"), "{record}");
    assert!(record.get("tenants").is_none(), "{record}");
}

/// MIN.1 gap 2. A cache hit of that response says both: no gate ran, and
/// the value was too large to inspect.
#[tokio::test]
async fn oversize_cache_hit_record_says_both() {
    let dir = tempfile::tempdir().unwrap();
    let mut cached = meta(Ok(oversize_reply_naming("cust-9")), &dir);
    cached.cache = Some(Arc::new(crate::cache::ResponseCache::new()));
    cached.default_cache_ttl = Duration::from_secs(300);
    let meta = attributing(cached);
    let who = api_key_caller();
    for _ in 0..2 {
        meta.invoke_tool(&args_for(None), None, &context(&AllowAll, &who))
            .await
            .expect("allowed call");
    }
    let all = records(&dir);
    assert_eq!(all.len(), 2, "{all:?}");
    assert_eq!(all[0]["attribution"], json!("uninspected"), "{}", all[0]);
    assert_eq!(
        all[1]["attribution"],
        json!("cached_delivery_uninspected"),
        "{}",
        all[1]
    );
}

/// A backend that answers every `tools/call` with its own JSON-RPC error,
/// counting the calls that reach it.
struct CountedPeerError(Arc<std::sync::atomic::AtomicUsize>);

#[async_trait::async_trait]
impl crate::transport::Transport for CountedPeerError {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/call" {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        super::PeerError(-32000).request(method, params).await
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A backend that answers every `tools/call` with `reply` (no chain), counting
/// the calls that reach it.
struct CountedReply(Arc<std::sync::atomic::AtomicUsize>, Value);

#[async_trait::async_trait]
impl crate::transport::Transport for CountedReply {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/call" {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        super::Scripted(Ok(self.1.clone()))
            .request(method, params)
            .await
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// `meta` with an idempotency cache, so a keyed repeat is served the stored
/// outcome of its first execution.
fn idempotent(mut meta: MetaMcp) -> MetaMcp {
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    meta
}

/// A retry key the caller sends on both calls.
fn keyed(key: &str) -> crate::protocol::mrtr::RetryFields {
    crate::protocol::mrtr::RetryFields {
        input_responses: None,
        request_state: None,
        idempotency_key: Some(key.to_string()),
        malformed: Vec::new(),
        attestation: None,
    }
}

/// MIK-7647 (in part). A keyed `gateway_invoke` whose backend answered with
/// its own error is settled as a stored `isError` result, so the repeat is
/// replayed from the idempotency cache (`CachedResult`, through
/// `GuardedValue::from_cache`): its record is a cached delivery, with the
/// request's tenants and no data classes, and the backend ran once. The
/// `CachedError` arm is reached only by a `reservation.fail` settlement
/// (a refused chain receipt or bridge challenge), which this harness cannot
/// script.
#[tokio::test]
async fn a_replayed_peer_error_result_is_recorded_as_a_cached_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let base = meta(Ok(reply_naming("cust-9", "")), &dir);
    base.backends
        .get("alpha")
        .expect("alpha")
        .set_transport_for_test(Arc::new(CountedPeerError(Arc::clone(&calls))));
    let meta = attributing(idempotent(base));
    let who = api_key_caller();
    let retry = keyed("peer-error-replay");
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        ..context(&AllowAll, &who)
    };
    for _ in 0..2 {
        let _ = meta
            .invoke_tool(&args_for(Some("cust-1")), None, &ctx)
            .await;
    }
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the replay reached the backend"
    );
    let all = records(&dir);
    assert_eq!(all.len(), 2, "{all:?}");
    let hit = &all[1];
    assert_eq!(hit["attribution"], json!("cached_delivery"), "{hit}");
    assert_eq!(hit["tenants"], sorted(&["cust-1"]), "{hit}");
    assert!(hit.get("data_classes").is_none(), "{hit}");
}

/// MIK-7649. The miss's response is refused by the inspection gate, so what
/// was delivered differs from what the backend returned. The miss records the
/// raw response's tenants; the replay records only what it delivered (the
/// refusal names no tenant), so the two are told apart. The response cache
/// stores no refusal, so the hit comes from the idempotency cache.
#[tokio::test]
async fn a_replayed_refusal_records_only_the_delivered_tenants() {
    let dir = tempfile::tempdir().unwrap();
    let note = format!("AWS_ACCESS_KEY_ID={}", example_access_key());
    let mut refusing = meta(Ok(reply_naming("cust-9", &note)), &dir);
    refusing.enable_response_inspection_action_mode();
    let meta = attributing(idempotent(refusing));
    let who = api_key_caller();
    let retry = keyed("refusal-replay");
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        ..context(&AllowAll, &who)
    };
    for _ in 0..2 {
        let _ = meta
            .invoke_tool(&args_for(Some("cust-1")), None, &ctx)
            .await;
    }
    let all = records(&dir);
    assert_eq!(all.len(), 2, "{all:?}");
    let (miss, hit) = (&all[0], &all[1]);
    let raw = miss["tenants"].as_array().cloned().unwrap_or_default();
    assert!(raw.contains(&json!(h("cust-9"))), "{miss}");
    assert_eq!(hit["attribution"], json!("cached_delivery"), "{hit}");
    assert_eq!(hit["tenants"], sorted(&["cust-1"]), "{hit}");
}

/// MIK-7647 AC1. The `CachedError` arm: a chained backend (`require`) whose
/// successful reply carries no chain is a refused receipt, so the first keyed call
/// settles its key as a terminal failure (`reservation.fail`, `invoke.rs`).
/// The repeat is served that stored error without reaching the backend, and
/// its record is a cached delivery with the request's tenants and no data
/// classes.
#[tokio::test]
async fn a_replayed_refused_receipt_is_recorded_as_a_cached_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig {
            signature_chain: crate::config::ChainMode::Require,
            ..crate::config::BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    backend.set_transport_for_test(Arc::new(CountedReply(
        Arc::clone(&calls),
        reply_naming("cust-9", ""),
    )));
    let _ = registry.register(Arc::clone(&backend));
    let logger = crate::security::TransparencyLogger::open(Arc::new(
        crate::security::transparency_log::TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "d1".to_string(),
            ..Default::default()
        },
    ))
    .expect("open log");
    let mut chained = MetaMcp::new(registry);
    chained.enable_transparency_log(Arc::new(logger));
    chained.set_chain_signer(
        crate::gateway::chain_test_support::signer(),
        crate::config::ChainEmit::OnRequest,
    );
    let meta = attributing(idempotent(chained));
    let who = api_key_caller();
    let retry = keyed("refused-receipt-replay");
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        ..context(&AllowAll, &who)
    };
    for _ in 0..2 {
        let _ = meta
            .invoke_tool(&args_for(Some("cust-1")), None, &ctx)
            .await;
    }
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the replay reached the backend"
    );
    let all = records(&dir);
    assert_eq!(all.len(), 2, "{all:?}");
    let hit = &all[1];
    assert_eq!(hit["attribution"], json!("cached_delivery"), "{hit}");
    assert_eq!(hit["tenants"], sorted(&["cust-1"]), "{hit}");
    assert!(hit.get("data_classes").is_none(), "{hit}");
}

/// MIK-7991 r4 (cleanup row): over HTTP and stdio the sync admission answers
/// every keyed re-issue before this invoke-path guard (`idempotency/admission.rs`
/// pins that its entry outlives this one), so only an in-process caller of
/// `invoke_tool` reaches the guard's replay arm. This pins what that arm does
/// today, so a production caller that starts reaching it shows up here: the
/// stored answer is served again without the backend running twice.
#[tokio::test]
async fn an_in_process_keyed_repeat_is_replayed_by_the_invoke_path_guard() {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    backend.set_transport_for_test(Arc::new(CountedReply(
        Arc::clone(&calls),
        reply_naming("cust-9", ""),
    )));
    let _ = registry.register(Arc::clone(&backend));
    let meta = idempotent(MetaMcp::new(registry));
    let who = api_key_caller();
    let retry = keyed("in-process-replay");
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        ..context(&AllowAll, &who)
    };
    let mut answers = Vec::new();
    for _ in 0..2 {
        answers.push(
            meta.invoke_tool(&args_for(Some("cust-1")), None, &ctx)
                .await
                .expect("answered"),
        );
    }
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the guard's replay reached the backend"
    );
    assert!(
        answers[1].to_string().contains("cust-9"),
        "the replay serves the stored answer: {}",
        answers[1]
    );
}

/// A backend whose every `tools/call` round is lost after the send, counting
/// the calls that reach it.
struct CountedLost(Arc<std::sync::atomic::AtomicUsize>);

#[async_trait::async_trait]
impl crate::transport::Transport for CountedLost {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/call" {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        super::Scripted(Err("stream lost".into()))
            .request(method, params)
            .await
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// MIK-7991 (F1): a keyed call whose round is lost settles its key with the
/// gateway's uncertainty notice. The sync admission's clock is wall time, so a
/// forward step can expire its entry before this guard's, and the re-issue
/// then reaches this guard, which replays the notice. That is the gateway's own
/// text, so the replay stages no receipt and another caller may send it.
#[tokio::test]
async fn a_replayed_lost_round_notice_puts_nothing_in_the_receipt() {
    use crate::security::firewall::{CollusionAction, CollusionConfig, RelayCaller};
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    backend.set_transport_for_test(Arc::new(CountedLost(Arc::clone(&calls))));
    let _ = registry.register(Arc::clone(&backend));
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            rules: serde_yaml::from_str("[{match: \"*\", action: allow}]").unwrap(),
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                sources: vec!["alpha:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    let meta = idempotent(meta);
    let who = api_key_caller();
    let retry = keyed("lost-round-notice");
    // Keyed for relay detection, which refuses an unkeyed caller under `block`.
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        caller_key: Some("lost-round-caller"),
        ..context(&AllowAll, &who)
    };
    let mut answers = Vec::new();
    for _ in 0..2 {
        let (answer, staged) = meta
            .collecting_staged(meta.invoke_tool(&args_for(None), None, &ctx))
            .await;
        staged.commit(true);
        answers.push(answer.expect("answered"));
    }
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the backend ran other than once (0: first round never sent; 2: the replay re-ran it)"
    );
    let notice = answers[1]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        notice.contains("may have reached the backend"),
        "base: the replay serves the notice: {}",
        answers[1]
    );
    let params = json!({"name": "read", "arguments": {"text": notice}});
    let verdict = firewall.check_relay(
        RelayCaller::Keyed("other-caller"),
        "alpha",
        "read",
        &params,
        ("s", "other"),
    );
    assert!(
        verdict.allowed,
        "the replayed notice is in a receipt: {}",
        answers[1]
    );
    // Control: receipted, the same notice is refused to the other caller, so
    // the allowed verdict above is not relay detection being idle.
    firewall.record_delivery(
        RelayCaller::Keyed("lost-round-caller"),
        "alpha",
        "read",
        &answers[1],
    );
    let verdict = firewall.check_relay(
        RelayCaller::Keyed("other-caller"),
        "alpha",
        "read",
        &params,
        ("s", "other"),
    );
    assert!(
        !verdict.allowed,
        "a receipted notice was allowed: {}",
        answers[1]
    );
}
