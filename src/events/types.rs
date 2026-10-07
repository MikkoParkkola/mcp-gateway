// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Wire errors and descriptor types of the events extension (draft at
//! `28ec35e9`; design §6).

use serde_json::{Value, json};

/// A JSON-RPC error answer of an `events/*` method.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RpcError {
    pub code: i32,
    pub message: &'static str,
    pub data: Option<Value>,
}

impl RpcError {
    fn new(code: i32, message: &'static str, data: Option<Value>) -> Self {
        Self {
            code,
            message,
            data,
        }
    }

    /// `-32601`: events are off, or the transport does not serve them.
    pub(crate) fn method_not_found() -> Self {
        Self::new(-32601, "Method not found", None)
    }

    /// `-32602` naming the offending field, never its value.
    pub(crate) fn invalid(field: &str) -> Self {
        Self::new(-32602, "Invalid params", Some(json!({ "field": field })))
    }

    /// `-32011`: unknown, or invisible to this caller (indistinguishable).
    pub(crate) fn not_found() -> Self {
        Self::new(-32011, "NotFound", Some(json!({ "kind": "event" })))
    }

    /// `-32012`: no authenticated principal, or the source refuses.
    pub(crate) fn forbidden() -> Self {
        Self::new(-32012, "Forbidden", None)
    }

    /// `-32013` naming the exhausted limit.
    pub(crate) fn exhausted(limit: &str, max: Option<usize>) -> Self {
        let mut data = json!({ "limit": limit });
        if let Some(max) = max {
            data["max"] = json!(max);
        }
        Self::new(-32013, "ResourceExhausted", Some(data))
    }

    /// `-32014`: a delivery mode other than `webhook`.
    pub(crate) fn unsupported_mode(mode: &Value) -> Self {
        Self::new(
            -32014,
            "Unsupported",
            Some(json!({ "feature": "deliveryMode", "value": mode })),
        )
    }

    /// `-32000`: the backend could not be started to learn its transport, the
    /// code `tools/call` answers a backend failure with (MIK-7969).
    pub(crate) fn backend_unavailable() -> Self {
        Self::new(-32000, "BackendUnavailable", None)
    }

    /// `-32014` for an upstream-notification event `name` its backend cannot
    /// offer, naming why (I5 design §11 D2/D3).
    pub(crate) fn unsupported_backend_events(name: &str, reason: &'static str) -> Self {
        Self::new(
            -32014,
            "Unsupported",
            Some(json!({ "feature": "backendEvents", "value": name, "reason": reason })),
        )
    }

    /// `-32015` with one of the [`CallbackFailure`] categories.
    pub(crate) fn callback(reason: CallbackFailure) -> Self {
        Self::new(
            -32015,
            "CallbackEndpointError",
            Some(json!({ "reason": reason.as_str() })),
        )
    }

    /// `-32603`: the store could not commit.
    pub(crate) fn internal() -> Self {
        Self::new(-32603, "Internal error", None)
    }
}

/// Why a callback endpoint failed. Only this category ever reaches a caller:
/// never the endpoint's body, headers or status line (design §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallbackFailure {
    /// Refused by the destination policy, or the TCP connect failed.
    ConnectionRefused,
    /// No answer inside the timeout.
    Timeout,
    /// The TLS handshake or certificate check failed.
    TlsError,
    /// A 4xx answer.
    Http4xx,
    /// A 5xx answer.
    Http5xx,
    /// A 2xx or 3xx answer that did not echo the challenge.
    ChallengeFailed,
}

impl CallbackFailure {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionRefused => "connection_refused",
            Self::Timeout => "timeout",
            Self::TlsError => "tls_error",
            Self::Http4xx => "http_4xx",
            Self::Http5xx => "http_5xx",
            Self::ChallengeFailed => "challenge_failed",
        }
    }
}

/// What produced an event. 4.0.1 kinds are reserved so records written now
/// parse later (design §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code, reason = "the 4.0.1 sources are reserved kinds")]
pub(crate) enum SourceKind {
    Webhook,
    BackendNotification,
    TaskSettled,
    RestWatch,
    GatewayOperational,
    Schedule,
}

impl SourceKind {
    /// The stable name mixed into event ids; never changes for a kind.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::BackendNotification => "backend_notification",
            Self::TaskSettled => "task_settled",
            Self::RestWatch => "rest_watch",
            Self::GatewayOperational => "gateway_operational",
            Self::Schedule => "schedule",
        }
    }
}

/// Who may see an event type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code, reason = "the Operator scope lands with 4.0.1")]
pub(crate) enum Visibility {
    /// Callers admitted to this backend.
    Backend(String),
    /// The owner of the underlying record (task events).
    Owner,
    /// Operator standing.
    Operator,
}

impl Visibility {
    /// The backend a credential must be granted to receive this scope, if
    /// any: owner-scoped events need only a live credential.
    pub(crate) fn grant_backend(&self) -> Option<&str> {
        match self {
            Self::Backend(backend) => Some(backend),
            Self::Owner | Self::Operator => None,
        }
    }
}

/// One event type in the catalogue.
#[derive(Debug, Clone)]
pub(crate) struct EventDescriptor {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub payload_schema: Value,
    pub scope: Visibility,
    #[allow(dead_code, reason = "read by the I1 kind check and I2 audit")]
    pub kind: SourceKind,
}

impl EventDescriptor {
    /// The `events/list` entry.
    pub(crate) fn to_wire(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "delivery": ["webhook"],
            "inputSchema": self.input_schema,
            "payloadSchema": self.payload_schema,
        })
    }
}
