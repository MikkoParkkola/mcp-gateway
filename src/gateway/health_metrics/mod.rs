// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's own health metrics (decision D10): which kind of error a
//! client received, and how much time the gateway itself added to a call.

#[cfg(test)]
mod classify_tests;

/// Who wrote a JSON-RPC error frame: the gateway, or a backend whose answer
/// the gateway forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    Gateway,
    Backend,
}

/// The JSON-RPC error an answer carries, set where the frame becomes the
/// response, so the error count never reads a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RpcError {
    pub(crate) code: i32,
    pub(crate) origin: Origin,
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
    let _ = (status, marker);
    None
}
