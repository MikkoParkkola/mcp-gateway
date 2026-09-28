// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F26: the response cache must not replay an error.
//!
//! A dispatch `Err` becomes an `isError: true` tool result, and a backend may
//! answer `isError: true` itself. Before F26 the response cache stored either
//! for its whole TTL, so a 10 ms rate-limit refusal became a 60 s refusal for
//! every call with the same key (seen as 960 cache hits in MRTR.7 row 7b under
//! load, GH #1158). R3 is the control: a success is still cached, so the rows
//! cannot pass by switching the cache off.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::MetaMcp;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::protocol::RequestId;
use crate::transport::Transport;

/// A backend transport that answers each call with the next scripted body
/// (the last one repeats) and counts the calls that reach it.
struct ScriptedTransport {
    calls: Arc<AtomicUsize>,
    script: Vec<Value>,
}

#[async_trait::async_trait]
impl Transport for ScriptedTransport {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        let body = self.script[n.min(self.script.len() - 1)].clone();
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            body,
        ))
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

fn ok_body() -> Value {
    json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
}

/// A `MetaMcp` with the response cache on (60 s, the shipped TTL) and one
/// backend `srv` answering from `script`. Returns the backend-call counter.
fn cached_meta(failsafe: &FailsafeConfig, script: Vec<Value>) -> (MetaMcp, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        "srv",
        BackendConfig::r2_off(),
        failsafe,
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(ScriptedTransport {
        calls: Arc::clone(&calls),
        script,
    }));
    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(backend);
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(60),
    );
    (meta, calls)
}

fn call(k: u32) -> Value {
    json!({"server": "srv", "tool": "read", "arguments": {"k": k}})
}

fn is_error(result: &crate::Result<Value>) -> bool {
    match result {
        Err(_) => true,
        Ok(v) => v.get("isError").and_then(Value::as_bool) == Some(true),
    }
}

/// F26 R1: a gateway rate-limit refusal is not replayed. One token (1 rps,
/// burst 1): A takes it, B is refused, and once a token has refilled B is asked
/// again and must reach the backend. Before F26 the second B was a cache hit
/// serving the stale refusal.
#[tokio::test]
async fn a_rate_limited_refusal_is_not_replayed_from_the_cache() {
    let mut failsafe = FailsafeConfig::default();
    failsafe.rate_limit.enabled = true;
    failsafe.rate_limit.requests_per_second = 1;
    failsafe.rate_limit.burst_size = 1;
    failsafe.retry.enabled = false;
    let (meta, calls) = cached_meta(&failsafe, vec![ok_body()]);
    let caller = ctx(&AllowAll);

    let a = meta.invoke_tool(&call(1), None, &caller).await;
    assert!(!is_error(&a), "A takes the only token: {a:?}");
    let b = meta.invoke_tool(&call(2), None, &caller).await;
    let refusal = b.expect("the refusal is a tool result");
    assert_eq!(
        refusal.get("isError"),
        Some(&json!(true)),
        "the refusal must be an error result, the shape the cache refuses: {refusal}"
    );
    assert_eq!(
        refusal.pointer("/recovery/error_code"),
        Some(&json!("RATE_LIMITED")),
        "and typed as a rate-limit refusal: {refusal}"
    );
    assert!(
        refusal
            .to_string()
            .contains("Rate limit exceeded for backend 'srv'"),
        "B must meet the empty bucket: {refusal}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "B never reached the backend"
    );

    // Poll rather than sleep a fixed refill: before the bucket refills the
    // limiter refuses afresh, and those refusals are not cached either after
    // F26. At base the first refusal is replayed for the whole 60 s TTL, so
    // the deadline passes with every attempt answered from the cache.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let again = loop {
        let attempt = meta.invoke_tool(&call(2), None, &caller).await;
        if !is_error(&attempt) || tokio::time::Instant::now() >= deadline {
            break attempt;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(
        !is_error(&again),
        "a refilled bucket must admit B; a cached refusal answered instead: {again:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the second B reached the backend"
    );
}

/// F26 R2: a backend's own `isError: true` is not replayed either. The backend
/// errs once and then answers; the same call made twice must reach it twice and
/// get the answer the second time.
#[tokio::test]
async fn a_backend_tool_error_is_not_replayed_from_the_cache() {
    let failed = json!({"content": [{"type": "text", "text": "upstream 503"}], "isError": true});
    let (meta, calls) = cached_meta(&FailsafeConfig::default(), vec![failed, ok_body()]);
    let caller = ctx(&AllowAll);

    let first = meta.invoke_tool(&call(7), None, &caller).await;
    assert!(is_error(&first), "the backend errs first: {first:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the first call reached the backend"
    );
    let second = meta.invoke_tool(&call(7), None, &caller).await;
    assert!(
        !is_error(&second),
        "the backend has recovered; a cached error answered instead: {second:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "both calls reached the backend"
    );
}

/// F26 R3, the control: a success is still cached, so R1 and R2 cannot pass by
/// switching the response cache off.
#[tokio::test]
async fn a_successful_result_is_still_cached() {
    let (meta, calls) = cached_meta(&FailsafeConfig::default(), vec![ok_body()]);
    let caller = ctx(&AllowAll);

    for _ in 0..2 {
        let r = meta.invoke_tool(&call(9), None, &caller).await;
        assert!(!is_error(&r), "{r:?}");
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the second identical success is served from the cache"
    );
}
