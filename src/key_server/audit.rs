//! Audit logging for key server token lifecycle events.
//!
//! Every event is emitted via `tracing::info!` with structured fields, making
//! the audit trail queryable by any log aggregator (Loki, CloudWatch, Datadog).
//!
//! # Events
//!
//! | Event | When |
//! |-------|------|
//! | `token.issued` | A new temporary token is successfully issued |
//! | `token.used` | A temporary token is validated for a request |
//! | `token.expired` | A token is rejected because its `exp` has passed |
//! | `token.revoked` | A token is explicitly revoked via `DELETE /auth/token/{jti}` |
//! | `token.denied` | OIDC verification or policy matching failed |
//! | `token.invalid` | The token string is structurally invalid |

use std::net::IpAddr;

use serde::Serialize;

use super::{oidc::VerifiedIdentity, store::TemporaryToken};

/// Structured audit event emitted for every token lifecycle transition.
#[derive(Debug, Serialize)]
pub struct AuditEvent {
    /// Event type string (e.g., `"token.issued"`).
    pub event: &'static str,
    /// Identity associated with the event (present for most events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<VerifiedIdentity>,
    /// JTI of the affected token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_jti: Option<String>,
    /// Allowed backends (for `token.issued`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backends: Option<Vec<String>>,
    /// Allowed tools (for `token.issued`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<String>>,
    /// Rate limit in requests/minute (for `token.issued`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<u32>,
    /// Client IP address (when available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<IpAddr>,
    /// Human-readable reason for denial or error events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AuditEvent {
    /// Construct a `token.issued` event.
    #[must_use]
    pub fn issued(token: &TemporaryToken) -> Self {
        Self {
            event: "token.issued",
            identity: Some(token.identity.clone()),
            token_jti: Some(token.jti.clone()),
            backends: Some(token.scopes.backends.clone()),
            tools: Some(token.scopes.tools.clone()),
            rate_limit: Some(token.scopes.rate_limit),
            client_ip: token.client_ip,
            reason: None,
        }
    }

    /// Construct a `token.used` event.
    #[must_use]
    pub fn used(token: &TemporaryToken, client_ip: Option<IpAddr>) -> Self {
        Self {
            event: "token.used",
            identity: Some(token.identity.clone()),
            token_jti: Some(token.jti.clone()),
            backends: None,
            tools: None,
            rate_limit: None,
            client_ip,
            reason: None,
        }
    }

    /// Construct a `token.expired` event.
    #[must_use]
    pub fn expired(jti: &str, identity: VerifiedIdentity) -> Self {
        Self {
            event: "token.expired",
            identity: Some(identity),
            token_jti: Some(jti.to_string()),
            backends: None,
            tools: None,
            rate_limit: None,
            client_ip: None,
            reason: None,
        }
    }

    /// Construct a `token.revoked` event.
    #[must_use]
    pub fn revoked(jti: &str, identity: Option<VerifiedIdentity>) -> Self {
        Self {
            event: "token.revoked",
            identity,
            token_jti: Some(jti.to_string()),
            backends: None,
            tools: None,
            rate_limit: None,
            client_ip: None,
            reason: None,
        }
    }

    /// Construct a `token.denied` event (OIDC verification or policy failure).
    #[must_use]
    pub fn denied(reason: impl Into<String>, client_ip: Option<IpAddr>) -> Self {
        Self {
            event: "token.denied",
            identity: None,
            token_jti: None,
            backends: None,
            tools: None,
            rate_limit: None,
            client_ip,
            reason: Some(reason.into()),
        }
    }

    /// Construct a `token.invalid` event.
    #[must_use]
    pub fn invalid(reason: impl Into<String>, client_ip: Option<IpAddr>) -> Self {
        Self {
            event: "token.invalid",
            identity: None,
            token_jti: None,
            backends: None,
            tools: None,
            rate_limit: None,
            client_ip,
            reason: Some(reason.into()),
        }
    }
}

/// Emit an audit event via `tracing::info!` with structured fields.
///
/// The event is serialized as a JSON blob in the `audit` field, making it
/// easy to extract in log aggregators:
///
/// ```text
/// INFO key_server::audit audit={"event":"token.issued","identity":...}
/// ```
pub fn emit(event: &AuditEvent) {
    match serde_json::to_string(event) {
        Ok(ref json) => tracing::info!(audit = %json, "key_server audit"),
        Err(ref e) => tracing::warn!(error = %e, "Failed to serialize audit event"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_server::{oidc::VerifiedIdentity, store::{InMemoryTokenStore, TemporaryToken, TokenScopes}};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn make_identity() -> VerifiedIdentity {
        VerifiedIdentity {
            subject: "sub123".to_string(),
            email: "alice@company.com".to_string(),
            name: Some("Alice".to_string()),
            groups: Vec::new(),
            issuer: "https://accounts.google.com".to_string(),
        }
    }

    fn make_token() -> TemporaryToken {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        TemporaryToken {
            jti: InMemoryTokenStore::generate_jti(),
            token: InMemoryTokenStore::generate_bearer(),
            identity: make_identity(),
            scopes: TokenScopes {
                backends: vec!["tavily".to_string()],
                tools: Vec::new(),
                rate_limit: 100,
            },
            iat: now,
            exp: now + 3600,
            client_ip: None,
        }
    }

    #[test]
    fn issued_event_has_correct_type() {
        // GIVEN: a token
        let token = make_token();

        // WHEN: build issued event
        let event = AuditEvent::issued(&token);

        // THEN: event type is "token.issued" and fields are populated
        assert_eq!(event.event, "token.issued");
        assert!(event.identity.is_some());
        assert!(event.token_jti.is_some());
        assert!(event.backends.is_some());
    }

    #[test]
    fn used_event_has_correct_type() {
        // GIVEN: a token
        let token = make_token();

        // WHEN: build used event
        let event = AuditEvent::used(&token, None);

        // THEN: event type is "token.used", no scope fields
        assert_eq!(event.event, "token.used");
        assert!(event.backends.is_none());
    }

    #[test]
    fn denied_event_contains_reason() {
        // GIVEN/WHEN: build denied event with a reason
        let event = AuditEvent::denied("Policy not matched", None);

        // THEN: event type and reason are set
        assert_eq!(event.event, "token.denied");
        assert_eq!(event.reason.as_deref(), Some("Policy not matched"));
        assert!(event.identity.is_none());
    }

    #[test]
    fn revoked_event_has_jti() {
        // GIVEN/WHEN: build revoked event
        let event = AuditEvent::revoked("some-jti", Some(make_identity()));

        // THEN: event type and JTI set
        assert_eq!(event.event, "token.revoked");
        assert_eq!(event.token_jti.as_deref(), Some("some-jti"));
    }

    #[test]
    fn events_serialize_to_json() {
        // GIVEN: various event types
        let token = make_token();
        let events = vec![
            AuditEvent::issued(&token),
            AuditEvent::used(&token, None),
            AuditEvent::denied("test", None),
            AuditEvent::revoked("jti", None),
            AuditEvent::invalid("bad token", None),
        ];

        // WHEN/THEN: all serialize without error
        for event in events {
            let result = serde_json::to_string(&event);
            assert!(result.is_ok(), "Serialization failed: {:?}", result);
        }
    }

    #[test]
    fn emit_does_not_panic() {
        // GIVEN: any audit event
        let token = make_token();
        let event = AuditEvent::issued(&token);

        // WHEN: emit (just check it doesn't panic)
        emit(&event);
    }
}
