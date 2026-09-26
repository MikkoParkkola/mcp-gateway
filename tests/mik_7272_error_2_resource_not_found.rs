// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion test for MIK-7272.ERROR.2 — a resource that no backend
//! owns answers `-32602` (invalid params), not the legacy `-32002`.
//!
//! `-32002` is the pre-2026 MCP resource-not-found code, and it sits in the
//! `-32000..=-32019` band the specification leaves to implementations. A client
//! reading it there cannot tell our "no such resource" from an SDK's own
//! meaning for the same number, which is why the revision moves the condition
//! onto the standard JSON-RPC invalid-params code.
//!
//! `resources/read` is the one method that resolves a URI to its owning backend.
//! `resources/subscribe` and `resources/unsubscribe` used to, and are now refused
//! at dispatch (F24), so they no longer reach this mapping.

use std::sync::Arc;

use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::gateway::test_helpers::{CallerStanding, MetaMcp};
use mcp_gateway::protocol::{JsonRpcResponse, RequestId};
use serde_json::json;

/// A URI no backend can own: the registry below is empty, and this is not a
/// gateway-owned `gateway://` guide, so resolution must fail rather than be
/// short-circuited into a success by the inline-guide path.
const UNOWNED_URI: &str = "file:///no/backend/owns/this.txt";

fn meta_mcp() -> MetaMcp {
    MetaMcp::new(Arc::new(BackendRegistry::new()))
}

fn assert_invalid_params(response: &JsonRpcResponse, method: &str) {
    let error = response.error.as_ref().unwrap_or_else(|| {
        panic!("{method} on an unowned URI must be an error, got: {response:?}")
    });
    assert_ne!(
        error.code, -32002,
        "{method} still answers the legacy resource-not-found code"
    );
    assert_eq!(
        error.code, -32602,
        "{method} must map resource-not-found to invalid params"
    );
}

#[tokio::test]
async fn ac_error_2_resources_read_answers_invalid_params() {
    let params = json!({ "uri": UNOWNED_URI });
    let response = meta_mcp()
        .handle_resources_read(
            RequestId::Number(1),
            Some(&params),
            CallerStanding::Admin,
            None,
            None,
        )
        .await;
    assert_invalid_params(&response, "resources/read");
}
