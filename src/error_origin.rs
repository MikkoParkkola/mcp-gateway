// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whose failure an [`Error`] is, for the gateway's error count.

use super::Error;

impl Error {
    /// Whose failure this error is, for the error count. Exhaustive on
    /// purpose: a new variant fails to compile until it is classified, and
    /// the `BackendFailure` arms are exactly the ones `to_rpc_code` groups as
    /// a backend-side failure with the gateway healthy. The gateway's own
    /// throttles (`is_gateway_throttle`) are the gateway's, though they share
    /// that code.
    #[must_use]
    pub(crate) fn origin(&self) -> crate::protocol::Origin {
        use crate::protocol::Origin;
        match self {
            Self::BackendUnavailable(_)
            | Self::CircuitOpen { .. }
            | Self::BackendTimeout(_)
            | Self::Transport(_)
            | Self::TransportConnect(_)
            | Self::TransportPermanent(_) => Origin::BackendFailure,
            Self::Http(e) if http_is_backend_refusal(e) => Origin::BackendFailure,
            // Built in production only by the HTTP transport, from a peer's
            // JSON-RPC body on a 429/503: the backend's own answer.
            Self::JsonRpcRetryable { .. } => Origin::Backend,
            Self::Config(_)
            | Self::Forbidden { .. }
            | Self::ResponseFirewallRefused
            | Self::AuditUnavailable
            | Self::ConfigValidation(_)
            | Self::ConfigWatcher(_)
            | Self::CapabilityHashMismatch { .. }
            | Self::BackendNotFound(_)
            | Self::RateLimited(_)
            | Self::IdentitySlotsExhausted { .. }
            | Self::ToolNotFound(_)
            | Self::Protocol(_)
            | Self::ProtocolVersionRejected { .. }
            | Self::OAuth(_)
            | Self::AuthorizationIncomplete { .. }
            | Self::AuthorizationCancelled { .. }
            | Self::AuthorizationRequired { .. }
            | Self::AuthorizationPending { .. }
            | Self::Tls(_)
            | Self::JsonRpc { .. }
            // Built only by `gateway_refused`: a gateway decision.
            | Self::GatewayRefused { .. }
            | Self::CliCredentialRefused { .. }
            | Self::Io(_)
            | Self::Json(_)
            | Self::Http(_)
            | Self::Shutdown
            | Self::Internal(_) => Origin::Gateway,
        }
    }
}

/// An `Http` error that is a backend refusing, not a gateway fault: a 429 (the
/// backend refused, the gateway is healthy) or a typed credential refusal
/// (A11-b: 401/403 were `Transport`, -32000, until typed, and keep that code).
/// Every other `Http` status stays the internal error it has always reported.
pub(super) fn http_is_backend_refusal(e: &reqwest::Error) -> bool {
    e.status().is_some_and(|status| {
        status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || crate::security::http_diagnostics::is_deterministic_refusal(status)
    })
}
