// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a dispatch or recovery error becomes the JSON-RPC error a caller
//! receives.

use crate::error::rpc_codes::INTERNAL_ERROR;

/// The error a recovered task result settles on when the gateway's own
/// processing refuses it: a firewall refusal as a native task and the
/// synchronous call report it (-32600), anything else as internal.
pub(crate) fn recovered_result_error(error: &crate::Error) -> crate::protocol::JsonRpcError {
    if matches!(error, crate::Error::ResponseFirewallRefused)
        && let Some(refusal) = crate::protocol::JsonRpcResponse::delivery_refusal_error(
            None,
            error.to_rpc_code(),
            &error.to_string(),
        )
        .error
    {
        return refusal;
    }
    crate::protocol::JsonRpcError {
        code: INTERNAL_ERROR,
        message: error.to_string(),
        data: None,
    }
}

/// Turn a dispatch error into a JSON-RPC error response, keeping the HTTP
/// status when the error is an authorization refusal.
///
/// The refusal already knows its status; every other error does not carry one
/// and gets the caller's default. The status rides in the error's optional
/// `data` because that is the only channel that survives this conversion —
/// `JsonRpcResponse` has no status of its own, and re-deriving one at the HTTP
/// boundary from the JSON-RPC code cannot work: eight of the nine refusal
/// branches emit the generic `-32600`, and `-32003` already means something
/// else elsewhere.
pub(crate) fn error_response_preserving_status(
    id: crate::protocol::RequestId,
    error: &crate::Error,
) -> crate::protocol::JsonRpcResponse {
    crate::gateway::delivery_facts::outlet(error);
    let mut response = match error {
        crate::Error::ResponseFirewallRefused => {
            crate::protocol::JsonRpcResponse::delivery_refusal_error(
                Some(id),
                error.to_rpc_code(),
                &error.to_string(),
            )
        }
        _ => crate::protocol::JsonRpcResponse::error(
            Some(id),
            error.to_rpc_code(),
            error.to_string(),
        ),
    };
    if let Some(ref mut rpc_error) = response.error {
        // Written unconditionally, so this function is the sole authority on
        // the field. `JsonRpcResponse::error` starts it at `None` and nothing
        // else in the gateway writes it today, but a future path that forwarded
        // a backend's error data could otherwise hand a backend the power to
        // choose the gateway's HTTP status. Assigning both arms closes that
        // without depending on the audit staying true.
        rpc_error.data = match error {
            crate::Error::Forbidden { status, .. } => Some(serde_json::json!({
                crate::gateway::authz::HTTP_STATUS_DATA_KEY: status,
            })),
            // D1-f: the log is down, not the caller wrong. 503 so an operator
            // and a load balancer read it as unavailability.
            crate::Error::AuditUnavailable => Some(serde_json::json!({
                crate::gateway::authz::HTTP_STATUS_DATA_KEY: 503,
            })),
            // Gateway-authored, so its fixed fields go out whole.
            crate::Error::AmbiguousBackend { .. } => error.ambiguous_backend_data(),
            // A gateway-authored refusal may carry a recovery payload the
            // client needs: MRTR.9 names the capability an input request would
            // have required and MRTR.9a the mode, which is the difference
            // between a client that can fix its declaration and retry and one
            // that only sees prose. Named keys only, never the whole object:
            // `invoke_tool` puts a *backend's* error data into this variant, and
            // forwarding it wholesale would hand a backend the status field.
            crate::Error::JsonRpc {
                data: Some(data), ..
            } => {
                let forwarded: serde_json::Map<String, serde_json::Value> = [
                    crate::gateway::meta_mcp::invoke::REQUIRED_CAPABILITIES_DATA_KEY,
                    crate::gateway::meta_mcp::invoke::UNSUPPORTED_ELICITATION_MODE_DATA_KEY,
                ]
                .into_iter()
                .filter_map(|key| Some((key.to_string(), data.get(key)?.clone())))
                .chain(capped_tool_text(data))
                .collect();
                // `None` rather than `{}`: a backend error carrying none of these
                // keys leaves `data` absent exactly as when one key was forwarded.
                (!forwarded.is_empty()).then_some(serde_json::Value::Object(forwarded))
            }
            _ => None,
        };
        // A connect offer only under the gateway's own seal (ADR-008).
        // An offer's text is the gateway's own, so it goes out without the
        // JSON-RPC prefix Display adds. Gated on the offer keys, not the seal:
        // a sealed upstream rejection forwards `{}` and keeps its text, as does
        // any unsealed error.
        let offer = crate::personal_accounts::refusal::offer_data(error);
        let is_offer = offer
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .is_some_and(|keys| !keys.is_empty());
        if let (true, crate::Error::JsonRpc { message, .. }) = (is_offer, error) {
            rpc_error.message.clone_from(message);
        }
        // A sealed transient answer likewise goes out with its own text and
        // its retryable data (Busy parity), never a backend's.
        let transient = crate::personal_accounts::refusal::transient_data(error);
        if let (true, crate::Error::JsonRpc { message, .. }) = (transient.is_some(), error) {
            rpc_error.message.clone_from(message);
        }
        rpc_error.data = transient.or(offer).or(rpc_error.data.take());
    }
    response
}

/// A playbook step failure's tool text, forwarded so an
/// aborted plan still tells its caller why. Only a string within the
/// playbook's cap: the key is named, not the whole object, and a backend's
/// error data carrying the same key cannot push more text through it.
fn capped_tool_text(data: &serde_json::Value) -> Option<(String, serde_json::Value)> {
    let text = data.get(crate::playbook::TOOL_TEXT_DATA_KEY)?.as_str()?;
    // One more than the cap: the cut marker the playbook appends.
    (text.chars().count() <= crate::playbook::TOOL_TEXT_CAP + 1).then(|| {
        (
            crate::playbook::TOOL_TEXT_DATA_KEY.to_string(),
            serde_json::Value::from(text),
        )
    })
}
