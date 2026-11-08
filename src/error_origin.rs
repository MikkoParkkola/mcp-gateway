// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whose failure an [`Error`] is, for the gateway's error count, and the
//! JSON-RPC code it answers with: the two maps group the backend's failures
//! alike.

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
            // Built in production by two sites. The HTTP transport builds it
            // from a peer's JSON-RPC body on a 429/503: the backend's own
            // answer. The injected-value scrub builds it when it replaces such
            // an answer with its refusal, keeping it retryable: the gateway's
            // decision. The two are told apart by the refusal's own code and
            // text; a backend sending that exact refusal on a 429/503 is
            // counted as the gateway's (a metric skew only, register row 375).
            Self::JsonRpcRetryable { .. } if crate::security::needles::is_echo_refusal(self) => {
                Origin::Gateway
            }
            // The backend's own answer: a peer's JSON-RPC body on a 429/503,
            // and any error member a backend sent (built only by
            // `backend_json_rpc`; the scrub's refusal of one is the gateway's
            // `JsonRpc`, never this variant).
            Self::JsonRpcRetryable { .. } | Self::BackendJsonRpc { .. } => Origin::Backend,
            Self::Config(_)
            | Self::Forbidden { .. }
            | Self::ResponseFirewallRefused
            | Self::AuditUnavailable
            | Self::ConfigValidation(_)
            | Self::ConfigWatcher(_)
            | Self::CapabilityHashMismatch { .. }
            | Self::BackendNotFound(_)
            // Built only by the gateway when a name is both a backend and the
            // capability backend: its own refusal.
            | Self::AmbiguousBackend { .. }
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

    /// Convert to JSON-RPC error code
    #[must_use]
    pub fn to_rpc_code(&self) -> i32 {
        match self {
            Self::JsonRpc { code, .. }
            | Self::BackendJsonRpc { code, .. }
            | Self::GatewayRefused { code, .. }
            | Self::JsonRpcRetryable { code, .. }
            | Self::Forbidden { code, .. } => *code,
            Self::Json(_) => super::rpc_codes::PARSE_ERROR, // Parse error
            Self::Protocol(_) | Self::ResponseFirewallRefused => super::rpc_codes::INVALID_REQUEST, // Invalid request
            Self::BackendNotFound(_) | Self::ToolNotFound(_) | Self::AmbiguousBackend { .. } => {
                -32001
            }
            Self::AuditUnavailable => -32005,
            Self::CliCredentialRefused { .. } => {
                crate::security::http_diagnostics::CLI_UNAUTHORIZED
            }
            Self::BackendUnavailable(_)
            | Self::CircuitOpen { .. }
            | Self::RateLimited(_)
            | Self::IdentitySlotsExhausted { .. }
            | Self::BackendTimeout(_)
            | Self::Transport(_)
            // A connect failure is the same class on the wire; the variant
            // exists for settlement, not for the caller.
            | Self::TransportConnect(_)
            // Same class as `Transport` to a JSON-RPC caller: a backend-side
            // failure, not a gateway fault. Omitting it reported a missing
            // backend command as an internal error.
            | Self::TransportPermanent(_) => -32000,
            Self::Http(e) if http_is_backend_refusal(e) => -32000,
            _ => super::rpc_codes::INTERNAL_ERROR, // Internal error
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
