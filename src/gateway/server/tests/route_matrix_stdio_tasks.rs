// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only stdio task driver for the route x check matrix (MIK-8137 family,
//! b3), on the stdio task fixture (`owner2_stdio_tasks`): one task-augmented
//! `tools/call` of a surfaced tool through the real stdio dispatch. The
//! matrix (`gateway::route_check_matrix_tests`) owns every assertion.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::owner2_stdio_tasks::{
    BACKEND, TOOL, backend, backend_listing, dispatch, fixture_on_with,
};
use crate::config::SurfacedToolConfig;

/// R5: a modern task-augmented `tools/call echo` by its surfaced name over
/// stdio, declaring the tasks extension and form elicitation, keyed. `echo`
/// is listed `destructiveHint: true`, so X14 has a destructive call to decide
/// (an unannotated tool reads as harmless once the catalogue is warm).
/// Returns the answer and the backend's `tools/call` count.
pub(crate) async fn stdio_task_surfaced() -> (Value, usize) {
    let served = backend_listing(json!([{
        "name": TOOL,
        "inputSchema": {"type": "object"},
        "annotations": {"destructiveHint": true, "readOnlyHint": false}
    }]))
    .await;
    let calls = std::sync::Arc::clone(&served.1);
    let fixture = Box::pin(fixture_on_with(served, None, |config| {
        config.meta_mcp.surfaced_tools = vec![SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: TOOL.to_string(),
        }];
    }))
    .await;
    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": TOOL,
            "arguments": {},
            "task": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {
                    "elicitation": {"form": {}},
                    "extensions": {"io.modelcontextprotocol/tasks": {}}
                },
                "io.modelcontextprotocol/clientInfo": {"name": "matrix", "version": "1"},
                "io.mcp-gateway/idempotency-key": "x14-stdio",
            },
        },
    });
    let body = dispatch(&fixture, request).await;
    (body, calls.load(Ordering::SeqCst))
}

/// R5: `tools/call gateway_invoke` of the fixture's `echo` over stdio with a
/// NUL in its arguments, on a gateway built from config with
/// `security.sanitize_input` = `on`. Returns the answer and the backend's
/// `tools/call` count.
pub(crate) async fn stdio_sanitizing(on: bool) -> (Value, usize) {
    let served = backend().await;
    let calls = std::sync::Arc::clone(&served.1);
    let fixture = Box::pin(fixture_on_with(served, None, |config| {
        config.security.sanitize_input = on;
    }))
    .await;
    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"cmd": "a\u{0}b"}},
        },
    });
    let body = dispatch(&fixture, request).await;
    (body, calls.load(Ordering::SeqCst))
}
