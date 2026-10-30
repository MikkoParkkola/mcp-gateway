// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One attempt of `request_attempted`: the transport send a dispatch's retry
//! loop repeats, timed for the web UI's latency history.

use std::sync::Arc;

use serde_json::Value;

use super::Attempts;
use crate::Result;
use crate::gateway::meta_mcp::invoke::send_timer::SendTimer;
use crate::protocol::JsonRpcResponse;
use crate::transport::{ResendPermission, Transport};

/// Send `method` once on `transport`, as `attempts` allows. A `tools/call`
/// send is timed from here, after the slot, the start and every wait the
/// caller did, so the time is the backend's alone.
pub(super) async fn send_timed(
    transport: Arc<dyn Transport>,
    method: String,
    (params, extra_headers): (Option<Value>, Vec<(String, String)>),
    identity_key: Option<String>,
    perm: ResendPermission,
    attempts: Attempts,
) -> Result<JsonRpcResponse> {
    let timer = SendTimer::start_if(method == "tools/call");
    let result = match attempts {
        Attempts::WithRetry => {
            transport
                .request_with_headers(
                    &method,
                    params,
                    &extra_headers,
                    identity_key.as_deref(),
                    perm,
                )
                .await
        }
        Attempts::TaskCapabilityOnce => {
            transport
                .request_with_task_capability(
                    &method,
                    params,
                    &extra_headers,
                    identity_key.as_deref(),
                )
                .await
        }
    };
    timer.finish_with(result)
}
