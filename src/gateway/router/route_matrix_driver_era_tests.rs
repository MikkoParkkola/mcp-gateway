// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8747 drivers: keyed `gateway_invoke` calls on `/mcp` sharing one
//! idempotency key, each declared in the era the caller picks. The tests
//! (`gateway::replay_era_tests`) own every assertion.

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::super::direct_guards_fixture::{
    self as fixture, Answer, post_meta_invoke, send_with_headers,
};
use crate::protocol::meta::Era;

/// What a sequence of keyed calls saw.
pub(crate) struct EraCalls {
    /// Each call's HTTP status and JSON-RPC body, in order.
    pub(crate) answers: Vec<(StatusCode, Value)>,
    /// Backend `tools/call` count after the last call.
    pub(crate) calls: usize,
}

/// One keyed `gateway_invoke alpha read` on `/mcp` in `era`.
async fn keyed_invoke(fx: &fixture::Fx, era: Era, key: &str) -> (StatusCode, Value) {
    match era {
        Era::Legacy => {
            post_meta_invoke(fx, "k-std", "alpha", "read", json!({}), Some(key), None).await
        }
        Era::Modern => {
            let params = json!({
                "name": "gateway_invoke",
                "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
                    (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key,
                },
            });
            let headers = [
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/call"),
                ("mcp-name", "gateway_invoke"),
            ];
            send_with_headers(fx, "/mcp", "k-std", "tools/call", params, None, &headers).await
        }
    }
}

/// One fixture, then a keyed call (`r1`) per entry of `eras`, in order.
pub(crate) async fn mcp_keyed_eras(eras: &[Era]) -> EraCalls {
    let fx = fixture::fixture_built(Answer::Ok, |meta| meta).await;
    let mut answers = Vec::new();
    for era in eras {
        answers.push(keyed_invoke(&fx, *era, "r1").await);
    }
    EraCalls {
        answers,
        calls: fx.calls.load(std::sync::atomic::Ordering::SeqCst),
    }
}
