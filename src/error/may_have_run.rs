// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A failed step's error with the may-have-run sentence appended.

use super::{Error, MAY_HAVE_RUN, reports_may_have_run};

impl Error {
    /// This error with [`MAY_HAVE_RUN`] appended to its message when
    /// [`reports_may_have_run`] holds and the variant carries text of its own.
    /// Variant, code, status and data are unchanged; a variant with no text of
    /// ours (`Io`, `Http`, a firewall refusal) is returned as it is, and a
    /// caller reads it through `!is_pre_dispatch()`.
    #[must_use]
    pub(crate) fn with_may_have_run(self) -> Self {
        if !reports_may_have_run(&self) {
            return self;
        }
        let note = |text: String| format!("{text}; {MAY_HAVE_RUN}");
        match self {
            Self::Config(m) => Self::Config(note(m)),
            Self::ConfigValidation(m) => Self::ConfigValidation(note(m)),
            Self::ConfigWatcher(m) => Self::ConfigWatcher(note(m)),
            Self::CliCredentialRefused { message } => Self::CliCredentialRefused {
                message: note(message),
            },
            Self::BackendTimeout(m) => Self::BackendTimeout(note(m)),
            Self::Transport(m) => Self::Transport(note(m)),
            Self::TransportPermanent(m) => Self::TransportPermanent(note(m)),
            Self::Protocol(m) => Self::Protocol(note(m)),
            Self::OAuth(m) => Self::OAuth(note(m)),
            Self::Tls(m) => Self::Tls(note(m)),
            Self::Internal(m) => Self::Internal(note(m)),
            Self::JsonRpc {
                code,
                message,
                data,
            } => Self::JsonRpc {
                code,
                message: note(message),
                data,
            },
            Self::JsonRpcRetryable {
                code,
                message,
                status,
                data,
            } => Self::JsonRpcRetryable {
                code,
                message: note(message),
                status,
                data,
            },
            // No text of ours to append to (or never reported, by
            // `reports_may_have_run`). Listed, not `_`, so a new variant is a
            // compile-time decision here.
            other @ (Self::Forbidden { .. }
            | Self::GatewayRefused { .. }
            | Self::ResponseFirewallRefused
            | Self::AuditUnavailable
            | Self::CapabilityHashMismatch { .. }
            | Self::BackendNotFound(_)
            | Self::AmbiguousBackend { .. }
            | Self::BackendUnavailable(_)
            | Self::CircuitOpen { .. }
            | Self::RateLimited(_)
            | Self::IdentitySlotsExhausted { .. }
            | Self::ToolNotFound(_)
            | Self::TransportConnect(_)
            | Self::ProtocolVersionRejected { .. }
            | Self::AuthorizationIncomplete { .. }
            | Self::AuthorizationCancelled { .. }
            | Self::AuthorizationRequired { .. }
            | Self::AuthorizationPending { .. }
            | Self::Io(_)
            | Self::Json(_)
            | Self::Http(_)
            | Self::Shutdown) => other,
        }
    }
}
