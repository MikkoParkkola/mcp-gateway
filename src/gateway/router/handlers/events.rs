// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The HTTP arms of `events/list`, `events/subscribe` and
//! `events/unsubscribe` (MIK-7630). Never proxied to a backend: the gateway
//! answers these itself, from its own catalogue (design §7.8).

use serde_json::Value;

use crate::events::{Caller, EventsHub, RpcError};
use crate::protocol::{JsonRpcResponse, RequestId};

/// The events principal: the task owner key (`route_task_owner`), the one
/// stable caller identity both eras share, so a task-settled event can be
/// matched to its owner (I4). `None` when authentication is off or the
/// caller presented no credential: webhook mode needs a principal.
pub(super) fn principal(owner: &str, auth_enabled: bool) -> Option<String> {
    (auth_enabled && !owner.is_empty()).then(|| owner.to_owned())
}

/// Answer one `events/*` request.
pub(super) async fn answer(
    hub: &std::sync::Arc<EventsHub>,
    id: RequestId,
    method: &str,
    params: Option<&Value>,
    caller: &Caller,
) -> JsonRpcResponse {
    let result = match method {
        "events/list" => hub.list(caller, params),
        "events/subscribe" => hub.subscribe(caller, params).await,
        "events/unsubscribe" => hub.unsubscribe(caller, params).await,
        _ => Err(RpcError::method_not_found()),
    };
    match result {
        Ok(value) => JsonRpcResponse::success(id, value),
        Err(RpcError {
            code,
            message,
            data: Some(data),
        }) => JsonRpcResponse::error_with_data(Some(id), code, message, data),
        Err(RpcError { code, message, .. }) => JsonRpcResponse::error(Some(id), code, message),
    }
}
