// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's one send to a backend (MIK-8351, MIK-8154 SAN.3).
//!
//! Two doors and nothing else: a `tools/call` goes through
//! [`dispatch_tool_call`], which takes the [`DirectPermit`] the dispatch
//! chokepoint mints on the bytes about to be sent, and every other method
//! goes through [`dispatch_non_call`], which takes a [`NonToolMethod`] that
//! cannot name `tools/call`. The raw send is private to this module, so a
//! sibling cannot reach the backend without one of the two.

use crate::error::rpc_codes::METHOD_NOT_FOUND;
use serde_json::Value;

use crate::gateway::meta_mcp::invoke::DirectPermit;
use crate::protocol::{JsonRpcResponse, RequestId};

/// A method that is not `tools/call`, in any letter case.
#[derive(Clone, Copy)]
pub(super) struct NonToolMethod<'a>(&'a str);

impl<'a> NonToolMethod<'a> {
    /// `None` for `tools/call` in any letter case: that send needs a permit.
    pub(super) fn new(method: &'a str) -> Option<Self> {
        (!method.eq_ignore_ascii_case("tools/call")).then_some(Self(method))
    }
}

/// Send one `tools/call`, on the strength of the permit the chokepoint minted
/// for exactly these bytes.
pub(super) async fn dispatch_tool_call(
    _permit: DirectPermit,
    backend: &crate::backend::Backend,
    id: &RequestId,
    params: Option<Value>,
    (propagated_headers, identity_key): (crate::transport::LentCredential, Option<&str>),
) -> crate::Result<JsonRpcResponse> {
    send_in_scope(
        backend,
        "tools/call",
        id,
        params,
        propagated_headers,
        identity_key,
    )
    .await
}

/// Send any method but `tools/call`.
pub(super) async fn dispatch_non_call(
    method: NonToolMethod<'_>,
    backend: &crate::backend::Backend,
    id: &RequestId,
    params: Option<Value>,
    (propagated_headers, identity_key): (crate::transport::LentCredential, Option<&str>),
) -> crate::Result<JsonRpcResponse> {
    send_in_scope(
        backend,
        method.0,
        id,
        params,
        propagated_headers,
        identity_key,
    )
    .await
}

/// Dispatch a direct-route request to a backend inside a notification scope.
///
/// The scope is the only reason this wrapper exists: without one,
/// `mint_progress_token` returns `None` and `Backend::request*` hands the
/// backend the caller's own `_meta.progressToken` (MIK-7272.SUB.2b / ADR-014
/// section 2), which is precisely what the mint exists to prevent. This route
/// has no client-facing stream, so the drained notifications are discarded --
/// unscoped they were already dropped inside `publish`, so scoping changes
/// nothing about delivery and buys the substitution.
async fn send_in_scope(
    backend: &crate::backend::Backend,
    method: &str,
    id: &RequestId,
    params: Option<Value>,
    propagated_headers: crate::transport::LentCredential,
    identity_key: Option<&str>,
) -> crate::Result<JsonRpcResponse> {
    let credential = propagated_headers;
    // Collected and discarded unread: nothing reaches a client, so no screen.
    let (response, _discarded) = crate::transport::notification_sink::collect(None, async {
        if credential.headers.is_empty() && identity_key.is_none() {
            backend.request(method, params).await
        } else {
            backend
                .request_with_headers_lent(method, params, credential, identity_key)
                .await
        }
    })
    .await;
    // `method` is client-chosen. The backend refuses whatever the dispatched
    // slot's era removed, before the wire (MIK-7217 OUTBOUND.1, MIK-8186); the
    // refusal is answered here with the caller's own id, since an `id: null`
    // error cannot be correlated.
    if let Err(error) = &response
        && let Some(message) = crate::backend::removed_method_refusal_message(error)
    {
        return Ok(JsonRpcResponse::error(
            Some(id.clone()),
            METHOD_NOT_FOUND,
            message.to_string(),
        ));
    }
    // MIK-7116.MIN.2: what the backend sent counts as read here, before a
    // list drain, filter or normalisation drops fields. `tools/call` notes
    // its result at its gates instead, once they pass.
    if method != "tools/call"
        && let Ok(JsonRpcResponse {
            result: Some(raw), ..
        }) = &response
    {
        crate::security::tenant_reads::note_read(raw);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::NonToolMethod;

    /// MIK-8351: no letter case of `tools/call` can take the permit-free door.
    #[test]
    fn tools_call_in_any_case_is_not_a_non_tool_method() {
        for method in ["tools/call", "TOOLS/CALL", "Tools/Call"] {
            assert!(NonToolMethod::new(method).is_none(), "{method}");
        }
        for method in ["tools/list", "ping", "prompts/get", "resources/read"] {
            assert!(NonToolMethod::new(method).is_some(), "{method}");
        }
    }
}
