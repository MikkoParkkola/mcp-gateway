// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which dispatch-time refusals a playbook step records as the gateway's:
//! every error variant is classified here, so a new one cannot widen the
//! raise unnoticed.

use super::is_authorization_refusal;
use crate::Error;

/// The expected answer, by variant. No wildcard arm: a new variant fails to
/// compile here until someone decides whether it is a decision.
fn decides(error: &Error) -> bool {
    match error {
        Error::Forbidden { .. } => true,
        Error::Config(_)
        | Error::ResponseFirewallRefused
        | Error::AuditUnavailable
        | Error::ConfigValidation(_)
        | Error::ConfigWatcher(_)
        | Error::CapabilityHashMismatch { .. }
        | Error::BackendNotFound(_)
        | Error::BackendUnavailable(_)
        | Error::CircuitOpen { .. }
        | Error::RateLimited(_)
        | Error::IdentitySlotsExhausted { .. }
        | Error::ToolNotFound(_)
        | Error::BackendTimeout(_)
        | Error::Transport(_)
        | Error::TransportPermanent(_)
        | Error::TransportConnect(_)
        | Error::Protocol(_)
        | Error::ProtocolVersionRejected { .. }
        | Error::OAuth(_)
        | Error::AuthorizationIncomplete { .. }
        | Error::AuthorizationCancelled { .. }
        | Error::AuthorizationRequired { .. }
        | Error::AuthorizationPending { .. }
        | Error::Tls(_)
        | Error::JsonRpc { .. }
        | Error::GatewayRefused { .. }
        | Error::CliCredentialRefused { .. }
        | Error::JsonRpcRetryable { .. }
        | Error::Io(_)
        | Error::Json(_)
        | Error::Http(_)
        | Error::Shutdown
        | Error::Internal(_) => false,
    }
}

/// One value of every variant.
fn every_variant() -> Vec<Error> {
    let s = || "x".to_owned();
    vec![
        Error::Config(s()),
        Error::Forbidden {
            code: -32003,
            status: 403,
            message: s(),
        },
        Error::ResponseFirewallRefused,
        Error::AuditUnavailable,
        Error::ConfigValidation(s()),
        Error::ConfigWatcher(s()),
        Error::CapabilityHashMismatch {
            expected: s(),
            actual: s(),
            file: s(),
        },
        Error::BackendNotFound(s()),
        Error::BackendUnavailable(s()),
        Error::CircuitOpen {
            backend: s(),
            last_failure: None,
        },
        Error::RateLimited(s()),
        Error::IdentitySlotsExhausted {
            backend: s(),
            limit: "x",
        },
        Error::ToolNotFound(s()),
        Error::BackendTimeout(s()),
        Error::Transport(s()),
        Error::TransportPermanent(s()),
        Error::TransportConnect(s()),
        Error::Protocol(s()),
        Error::ProtocolVersionRejected {
            supported: Vec::new(),
        },
        Error::OAuth(s()),
        Error::AuthorizationIncomplete {
            backend: s(),
            window_secs: 1,
        },
        Error::AuthorizationCancelled { backend: s() },
        Error::AuthorizationRequired { backend: s() },
        Error::AuthorizationPending { backend: s() },
        Error::Tls(s()),
        Error::JsonRpc {
            code: -32003,
            message: s(),
            data: None,
        },
        Error::GatewayRefused {
            code: -32003,
            message: s(),
        },
        Error::CliCredentialRefused { message: s() },
        Error::JsonRpcRetryable {
            code: -32003,
            message: s(),
            status: 429,
            data: None,
        },
        Error::Io(std::io::Error::other("x")),
        Error::Json(serde_json::from_str::<serde_json::Value>("{").unwrap_err()),
        Error::Http(
            reqwest::Client::new()
                .get("http://[::1")
                .build()
                .unwrap_err(),
        ),
        Error::Shutdown,
        Error::Internal(s()),
    ]
}

#[test]
fn only_an_authorization_refusal_is_recorded_at_dispatch() {
    let all = every_variant();
    for error in &all {
        assert_eq!(is_authorization_refusal(error), decides(error), "{error:?}");
    }
    assert_eq!(
        all.iter().filter(|e| decides(e)).count(),
        1,
        "only Forbidden"
    );
}
