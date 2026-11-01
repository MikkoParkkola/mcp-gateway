// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's own health metrics (decision D10): which kind of error a
//! client received, and how much time the gateway itself added to a call.

pub(crate) mod clock;
pub(crate) mod layers;
#[cfg(feature = "metrics")]
pub(crate) mod process;

#[cfg(test)]
mod classify_tests;
#[cfg(all(test, feature = "metrics"))]
mod latency_tests;
#[cfg(all(test, feature = "metrics"))]
mod process_tests;

/// Help text for every health metric a recorder holds.
#[cfg(feature = "metrics")]
pub(crate) fn register() {
    layers::register();
    process::register();
}

pub(crate) use crate::protocol::Origin;

/// The JSON-RPC error an answer carries, set where the frame becomes the
/// response, so the error count never reads a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RpcError {
    pub(crate) code: i32,
    pub(crate) origin: Origin,
}

impl RpcError {
    /// The error `frame` carries, with the origin its off-wire marker names.
    pub(crate) fn of_frame(frame: &crate::protocol::JsonRpcResponse) -> Option<Self> {
        let error = frame.error.as_ref()?;
        Some(Self {
            code: error.code,
            origin: frame.wire_meta.origin,
        })
    }

    /// The error in an answer rendered as a JSON value, written by `origin`.
    pub(crate) fn of_value(answer: &serde_json::Value, origin: Origin) -> Option<Self> {
        let code = answer.get("error")?.get("code")?.as_i64()?;
        Some(Self {
            code: i32::try_from(code).ok()?,
            origin,
        })
    }
}

/// The `kind` label of `mcp_gateway_errors_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorKind {
    Auth,
    Request,
    Internal,
    Backend,
}

/// The kind of error an answer with HTTP `status` and error `marker` gave
/// its client, or `None` when it was not an error.
pub(crate) fn error_kind(status: u16, marker: Option<RpcError>) -> Option<ErrorKind> {
    let code = marker.map(|m| m.code);
    if marker.is_some_and(|m| m.origin != Origin::Gateway) {
        return Some(ErrorKind::Backend);
    }
    match (status, code) {
        (401 | 403, _) => Some(ErrorKind::Auth),
        (500..=599, _) | (_, Some(-32603)) => Some(ErrorKind::Internal),
        (_, Some(_)) | (400..=499, None) => Some(ErrorKind::Request),
        _ => None,
    }
}
