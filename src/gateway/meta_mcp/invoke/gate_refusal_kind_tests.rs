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
        | Error::AmbiguousBackend { .. }
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
        | Error::BackendJsonRpc { .. }
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
        Error::AmbiguousBackend {
            server: s(),
            rule: None,
        },
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

/// A caller with no signing, nonce or task: the backstop's settle is a no-op.
fn caller() -> crate::gateway::meta_mcp::MetaMcpCallerContext<'static> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        signing: None,
        execution: None,
        credential_principal: None,
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: None,
        authorizer: &crate::gateway::authz::AllowAll,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        task: None,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    }
}

/// The delivery effect a playbook step's dispatch-time `refusal` leaves when
/// the backstop is the only site that sees it: no composite, no outlet.
async fn backstop_effect(refusal: Error) -> serde_json::Value {
    use crate::gateway::delivery_facts::{record_fields, scope, snapshot};
    let meta = crate::gateway::meta_mcp::MetaMcp::new(std::sync::Arc::new(
        crate::backend::BackendRegistry::new(),
    ));
    scope(async {
        let answer = Box::pin(crate::playbook::in_step(
            0,
            meta.backstop(("alpha", "read"), &caller(), None, refusal),
        ))
        .await;
        assert!(answer.is_err(), "premise: the refusal stands");
        let mut fields = serde_json::Map::new();
        record_fields(snapshot().as_ref(), false, &mut fields);
        fields["response_effect"].clone()
    })
    .await
}

/// The backstop exists for a refusal site that records nothing itself: here
/// it is the only recorder, so an authorization refusal records refused.
#[tokio::test]
async fn the_backstop_alone_records_a_steps_authorization_refusal() {
    let refused = Box::pin(backstop_effect(Error::Forbidden {
        code: -32003,
        status: 403,
        message: "refused".to_owned(),
    }))
    .await;
    assert_eq!(refused, "refused");
}

/// Any other error at the same point records nothing.
#[tokio::test]
async fn the_backstop_records_nothing_for_a_non_authorization_error() {
    let effect = Box::pin(backstop_effect(Error::AuditUnavailable)).await;
    assert_eq!(effect, "delivered");
}

/// A merge-time decision, pinned: a name that is both a backend and the
/// capability backend is refused for the gateway's configuration clash, not
/// as a decision about the caller, so the backstop records no refusal for it.
#[tokio::test]
async fn an_ambiguous_backend_is_not_recorded_as_a_refusal() {
    let effect = Box::pin(backstop_effect(Error::AmbiguousBackend {
        server: "alpha".to_owned(),
        rule: None,
    }))
    .await;
    assert_eq!(effect, "delivered");
}
