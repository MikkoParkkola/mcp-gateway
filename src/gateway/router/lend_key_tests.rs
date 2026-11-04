// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A per-user send refusal and the call's idempotency key. A refusal with
//! nothing sent releases the key, so a same-key retry is judged afresh; a
//! refusal after an earlier send keeps it, so a same-key retry is the stored
//! answer and sends nothing.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture_hardened_signed_built};
use super::playbook_key_tests::{call, reads};
use crate::protocol::RequestId;
use crate::transport::Transport;

/// Lists `read`; answers the first `sent` `tools/call`s, then refuses every
/// later one at its send as the per-user lender does, counting each call
/// that reached the send.
struct RefusesAfter {
    sent: usize,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Transport for RefusesAfter {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({"tools": [{"name": "read", "inputSchema": {"type": "object",
                "properties": {"cmd": {"type": "string"}}}}]})
        } else if self.calls.fetch_add(1, Ordering::SeqCst) < self.sent {
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
        } else {
            return Err(crate::Error::Forbidden {
                code: -32001,
                status: 403,
                message: "per-user send refused: this credential was refused".to_string(),
            });
        };
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

/// A signed, keyed fixture serving the two-step playbook `two` (both steps
/// `alpha/read`), whose `alpha` answers `sent` calls and refuses the rest.
async fn fixture(sent: usize) -> (Fx, Arc<AtomicUsize>) {
    let fx = fixture_hardened_signed_built(Answer::Ok, true, |meta| {
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(reads("two", &["one", "two"], json!({})));
        meta.set_playbook_engine(engine);
        meta
    })
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    fx.state
        .backends
        .get("alpha")
        .expect("the fixture registers alpha")
        .set_transport_for_test(Arc::new(RefusesAfter {
            sent,
            calls: Arc::clone(&calls),
        }));
    (fx, calls)
}

async fn invoke(fx: &Fx, key: &str, nonce: &str) -> Value {
    call(
        fx,
        ("/mcp", "gateway_invoke"),
        json!({"name": "gateway_invoke", "arguments":
            {"server": "alpha", "tool": "read", "arguments": {"cmd": "one"}}}),
        (Some(key), nonce),
        json!({}),
    )
    .await
}

/// Nothing was sent, so the key is released: the same-key retry reaches the
/// send again and is refused afresh, never served a stored answer.
#[tokio::test]
async fn a_refusal_with_nothing_sent_releases_its_key() {
    let (fx, calls) = fixture(0).await;
    let first = invoke(&fx, "lend-cold", "lend-cold-1").await;
    assert_eq!(first["error"]["code"], -32001, "premise: refused: {first}");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "premise: {first}");
    let again = invoke(&fx, "lend-cold", "lend-cold-2").await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the retry is judged afresh, the key released: {again}"
    );
    assert_eq!(again["error"]["code"], -32001, "{again}");
}

/// Step one was sent before step two was refused, so the run keeps its key:
/// the same-key retry is the stored answer and nothing is sent again.
#[tokio::test]
async fn a_refusal_after_an_earlier_send_keeps_its_key() {
    let (fx, calls) = fixture(1).await;
    let run = |nonce: &'static str| {
        call(
            &fx,
            ("/mcp", "gateway_run_playbook"),
            json!({"name": "gateway_run_playbook",
                   "arguments": {"name": "two", "arguments": {}}}),
            (Some("lend-warm"), nonce),
            json!({}),
        )
    };
    let first = run("lend-warm-1").await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "premise: step one sent, step two refused at its send: {first}"
    );
    assert!(first.get("error").is_some(), "premise: refused: {first}");
    let again = run("lend-warm-2").await;
    assert_eq!(again, first, "the retry is the stored answer");
    assert_eq!(calls.load(Ordering::SeqCst), 2, "the retry sent nothing");
}
