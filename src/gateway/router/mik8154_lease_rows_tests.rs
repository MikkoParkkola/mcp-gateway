// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8154.LEASE.1 rows (test plan r1.1): the direct route takes the shared
//! execution lease (matrix gap 11, Direct x Lease). Each row is red on the
//! release tip unless its doc says CONTROL.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::direct_guards_fixture::{
    Answer, Fx, fixture_built, fixture_built_on, post_direct, post_meta_invoke,
};

/// The store's mismatch refusal as both routes put it on the wire.
const MISMATCH: &str =
    "JSON-RPC error 409: Idempotency key belongs to another execution or representation";
fn calls(fx: &Fx) -> usize {
    fx.calls.load(Ordering::SeqCst)
}

fn message(body: &Value) -> &str {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// A backend whose `tools/call` signals `entered`, then waits for `gate`.
struct Held {
    entered: Arc<tokio::sync::Notify>,
    gate: Arc<tokio::sync::Notify>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Held {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]})
        } else {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            self.gate.notified().await;
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
        };
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
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

/// Which route sends a keyed `read` on `alpha`.
#[derive(Clone, Copy, Debug)]
enum Via {
    Invoke,
    Direct,
}

async fn keyed(fx: &Fx, via: Via, key: &str) -> Value {
    match via {
        Via::Invoke => {
            post_meta_invoke(fx, "k-std", "alpha", "read", json!({}), Some(key), None)
                .await
                .1
        }
        Via::Direct => {
            post_direct(fx, "alpha", "k-std", "read", json!({}), Some(key), None)
                .await
                .1
        }
    }
}

/// `first` under key K, held at the backend; then `second` under K. Returns
/// (the second's answer, the backend's `tools/call` count).
async fn cross_route(first: Via, second: Via) -> (Value, usize) {
    let (entered, gate) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    let count = Arc::new(AtomicUsize::new(0));
    let held = Held {
        entered: Arc::clone(&entered),
        gate: Arc::clone(&gate),
        calls: Arc::clone(&count),
    };
    let fx = Arc::new(fixture_built_on(Arc::new(held), |meta| meta).await);
    let shared = Arc::clone(&fx);
    let held_call = tokio::spawn(async move { keyed(&shared, first, "lease-k").await });
    tokio::time::timeout(std::time::Duration::from_secs(30), entered.notified())
        .await
        .expect("the first call reached the held backend");
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        keyed(&fx, second, "lease-k"),
    )
    .await;
    gate.notify_waiters();
    gate.notify_one();
    let answer = answer.expect("the second call was answered while the first was held");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), held_call).await;
    (answer, count.load(Ordering::SeqCst))
}

/// The 7a idempotency guard's in-flight refusal, shared by `/mcp` and the
/// direct route (keyed on the idempotency key plus the credential).
const DUPLICATE: &str = "Duplicate request in progress for key:";

/// L1 CONTROL: a direct call under K while `gateway_invoke` of the same
/// target under K is in flight is refused at 7a, which both routes share;
/// the backend runs once. Green on the tip (probe 8154-probeA) and unchanged
/// by the fix, which adds the lease after 7a.
#[tokio::test]
async fn l1_direct_call_meets_an_in_flight_invoke_of_the_same_target() {
    let (answer, runs) = cross_route(Via::Invoke, Via::Direct).await;
    assert!(message(&answer).contains(DUPLICATE), "l1: {answer}");
    assert_eq!(runs, 1, "l1: the backend ran {runs} times");
}

/// L2: the reverse of L1. On `/mcp` the execution lease (`admit_meta_sync`)
/// runs before the meta route's idempotency cache, so once the held direct
/// call holds a lease the store answers first, with its mismatch. On the tip
/// the direct call held no lease, and the cache refused it as a duplicate.
#[tokio::test]
async fn l2_invoke_meets_an_in_flight_direct_call() {
    let (answer, runs) = cross_route(Via::Direct, Via::Invoke).await;
    assert_eq!(message(&answer), MISMATCH, "l2: {answer}");
    assert_eq!(runs, 1, "l2: the backend ran {runs} times");
}

/// L3 CONTROL: a completed `/mcp` result retried on `/mcp/{name}` under the
/// same key is a hit in the idempotency cache the two routes share, which
/// answers before 7b (design L3: a cache hit skips the lease): replayed, and
/// the backend runs once. Green on the tip and unchanged by the fix.
#[tokio::test]
async fn l3_completed_invoke_then_direct_retry_replays_once() {
    let fx = fixture_built(Answer::Ok, |meta| meta).await;
    let first = keyed(&fx, Via::Invoke, "lease-k3").await;
    assert!(
        first.get("error").is_none(),
        "premise: the invoke failed: {first}"
    );
    let retry = keyed(&fx, Via::Direct, "lease-k3").await;
    // Each route shapes its own answer; the replay is proven by the count.
    assert!(retry.get("error").is_none(), "l3: {retry}");
    assert_eq!(calls(&fx), 1, "l3: the backend ran again");
}

/// U1 CONTROL: an unkeyed direct call is `Unprotected`: it dispatches once.
#[tokio::test]
async fn u1_an_unkeyed_direct_call_dispatches_once() {
    let fx = fixture_built(Answer::Ok, |meta| meta).await;
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", json!({}), None, None).await;
    assert!(body.get("error").is_none(), "u1: {body}");
    assert_eq!(calls(&fx), 1, "u1: dispatched {} times", calls(&fx));
}

/// A modern, keyed, task-augmented `gateway_invoke` of `alpha/read`.
fn task_submit(key: &str) -> Value {
    json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
        "task": {},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": {"io.modelcontextprotocol/tasks": {}}
            },
            crate::protocol::mrtr::IDEMPOTENCY_KEY_META: key
        }
    })
}

/// L9: a task submit under K whose worker is held at the backend, then a
/// direct call under K: refused with the shared store's mismatch, and the
/// backend runs once. RED: the direct call is outside the store.
#[tokio::test]
async fn l9_direct_call_meets_an_in_flight_task_of_the_same_target() {
    let (entered, gate) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    let count = Arc::new(AtomicUsize::new(0));
    let held = Held {
        entered: Arc::clone(&entered),
        gate: Arc::clone(&gate),
        calls: Arc::clone(&count),
    };
    let fx = fixture_built_on(Arc::new(held), |meta| meta).await;
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_invoke"),
    ];
    let (_, created) = super::direct_guards_fixture::send_with_headers(
        &fx,
        "/mcp",
        "k-std",
        "tools/call",
        task_submit("lease-k9"),
        None,
        &headers,
    )
    .await;
    assert!(
        created.pointer("/result/taskId").is_some(),
        "premise: the task submit was not admitted: {created}"
    );
    tokio::time::timeout(std::time::Duration::from_secs(30), entered.notified())
        .await
        .expect("the task's worker reached the held backend");
    // The held backend blocks every call, so a direct call that reaches it
    // never answers: a second entry is the red outcome, named as such.
    let answer = tokio::select! {
        answer = keyed(&fx, Via::Direct, "lease-k9") => Some(answer),
        () = entered.notified() => None,
        () = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
            panic!("l9: the direct call neither answered nor reached the backend")
        }
    };
    gate.notify_waiters();
    gate.notify_one();
    let answer = answer.unwrap_or_else(|| {
        panic!(
            "l9: the direct call reached the held backend (calls {})",
            count.load(Ordering::SeqCst)
        )
    });
    assert_eq!(message(&answer), MISMATCH, "l9: {answer}");
    assert_eq!(count.load(Ordering::SeqCst), 1, "l9: the backend ran twice");
}
