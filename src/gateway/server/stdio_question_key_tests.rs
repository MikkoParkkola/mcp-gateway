// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T4 over stdio: a keyed `gateway_invoke` whose backend asks a question the
//! client declared it can answer, then a fresh call under the same key. The
//! fresh call is answered without reaching the backend again.

use super::*;

#[tokio::test]
async fn t4_stdio_fresh_same_key_call_after_a_question_is_refused() {
    let calls = Arc::new(AtomicUsize::new(0));
    let question = json!({
        "resultType": "input_required",
        "inputRequests": { "k1": {
            "method": "elicitation/create",
            "params": { "message": "Which account?", "requestedSchema": { "type": "object" } }
        }},
        "requestState": "backend-state-1"
    });
    let gateway_meta = stdio_meta(
        |meta| {
            meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                crate::idempotency::CLEANUP_INTERVAL,
            );
        },
        Arc::new(Counting {
            calls: Arc::clone(&calls),
            answer: question,
        }),
    )
    .await;
    let mut params = invoke_read(&json!({}));
    params["_meta"] = json!({
        (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): "k-question",
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
    });
    let first = stdio_send(&gateway_meta, params.clone()).await;
    println!("stdio round 1: {first}");
    assert_eq!(first["result"]["resultType"], "input_required", "{first}");
    let again = stdio_send(&gateway_meta, params).await;
    println!("stdio fresh same-key call: {again}");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "stdio ran the tool again");
    assert_eq!(again["error"]["code"], 409, "{again}");
    assert!(
        again
            .to_string()
            .contains("Secured execution result is unavailable"),
        "{again}"
    );
}
