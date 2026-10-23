// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8747 drivers: keyed stdio `gateway_invoke` calls sharing one
//! idempotency key, each declared in the era the caller picks, through the
//! real stdio dispatch. The tests (`gateway::replay_era_tests`) own every
//! assertion.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::{Counting, stdio_meta, stdio_send};
use crate::protocol::meta::Era;

/// The params of one keyed `gateway_invoke alpha read` in `era`.
fn keyed_invoke(era: Era, key: &str) -> Value {
    let mut meta = serde_json::Map::new();
    meta.insert(
        crate::protocol::mrtr::IDEMPOTENCY_KEY_META.to_string(),
        json!(key),
    );
    if era == Era::Modern {
        meta.insert(
            "io.modelcontextprotocol/protocolVersion".to_string(),
            json!("2026-07-28"),
        );
        meta.insert(
            "io.modelcontextprotocol/clientCapabilities".to_string(),
            json!({"elicitation": {"form": {}}}),
        );
    }
    json!({ "name": "gateway_invoke",
        "arguments": { "server": "alpha", "tool": "read", "arguments": {} },
        "_meta": meta })
}

/// One stdio Meta-MCP with idempotency on, then a keyed call (`r1`) per
/// entry of `eras`, in order. Returns the bodies and the backend sends.
pub(crate) async fn stdio_keyed_eras(eras: &[Era]) -> (Vec<Value>, usize) {
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(Counting {
        calls: Arc::clone(&calls),
        answer: json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
    });
    let meta = stdio_meta(
        |meta| {
            meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                crate::idempotency::CLEANUP_INTERVAL,
            );
        },
        transport,
    )
    .await;
    let mut bodies = Vec::new();
    for era in eras {
        bodies.push(stdio_send(&meta, keyed_invoke(*era, "r1")).await);
    }
    (bodies, calls.load(Ordering::SeqCst))
}
