// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The audit envelope every transparency-log entry carries (4.0.0 item D1).
//!
//! `schema_version`, `trace_id`, `outcome`, `error_code` and `who` are written
//! by the logger, not by each writer, so no writer can leave them out.

use serde::Serialize;

/// How the caller's credential was presented. Never any part of the secret.
///
/// No `Default`: a mint site that forgets to say which kind it minted does not
/// compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// Nothing was presented (auth off, or a public path).
    None,
    /// The stdio transport: the client spawned the process.
    LocalTransport,
    /// The configured static bearer token.
    StaticBearer,
    /// A configured API key.
    ApiKey,
    /// The dashboard session cookie.
    DashboardSession,
    /// A key-server temporary token.
    KeyServerToken,
    /// A delegated OIDC bearer verified by the key server.
    OidcBearer,
}

impl CredentialKind {
    /// The kind a request's client presented; `None` when there is no client.
    #[must_use]
    pub fn of(client: Option<&crate::gateway::auth::AuthenticatedClient>) -> Self {
        client.map_or(Self::None, |client| client.credential_kind)
    }
}

/// What an audited call came to (D1-d.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// The call returned a result that is not a tool error.
    Ok,
    /// The call returned a result with `isError: true`. No JSON-RPC error.
    ToolError,
    /// A refusal, with its JSON-RPC code.
    Denied(i32),
    /// The request itself was malformed or named nothing, with its code.
    Invalid(i32),
    /// Any other failure, with its code.
    Error(i32),
}

impl AuditOutcome {
    /// The outcome for a call's result. `None` means no record is written:
    /// `AuditUnavailable` is the log itself being down.
    ///
    /// Matched on the variant, never on the code alone: `-32001` is both a
    /// refusal and `BackendNotFound`.
    #[must_use]
    pub fn from_result(result: &crate::Result<serde_json::Value>) -> Option<Self> {
        use crate::Error;
        Some(match result {
            Ok(value) => {
                if value.get("isError").and_then(serde_json::Value::as_bool) == Some(true) {
                    Self::ToolError
                } else {
                    Self::Ok
                }
            }
            Err(Error::AuditUnavailable) => return None,
            Err(Error::Forbidden { code, .. }) => Self::Denied(*code),
            Err(Error::JsonRpc { code, .. }) if matches!(*code, -32004 | -32001) => {
                Self::Denied(*code)
            }
            Err(e @ Error::ResponseFirewallRefused) => Self::Denied(e.to_rpc_code()),
            Err(
                e @ (Error::Json(_)
                | Error::Protocol(_)
                | Error::BackendNotFound(_)
                | Error::ToolNotFound(_)),
            ) => Self::Invalid(e.to_rpc_code()),
            Err(Error::JsonRpc { code: -32602, .. }) => Self::Invalid(-32602),
            Err(e) => Self::Error(e.to_rpc_code()),
        })
    }

    /// The `outcome` field value.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::ToolError => "tool_error",
            Self::Denied(_) => "denied",
            Self::Invalid(_) => "invalid",
            Self::Error(_) => "error",
        }
    }

    /// The outcome of an HTTP route that audits by status: the admin UI
    /// (E1-f) and the direct route (D2). `code` is the JSON-RPC code the route
    /// answered with, when it answered with one; otherwise the kind's
    /// [`Self::default_code`]. One table, so every such route maps a status
    /// the same way.
    ///
    /// | status | outcome |
    /// |---|---|
    /// | 2xx | `ok` |
    /// | 401, 403 | `denied` |
    /// | 400, 404 | `invalid` |
    /// | any other (409 included) | `error` |
    #[must_use]
    pub fn from_http_status(status: axum::http::StatusCode, code: Option<i32>) -> Self {
        use crate::error::rpc_codes;
        let (kind, default): (fn(i32) -> Self, i32) = match status.as_u16() {
            200..=299 => return Self::Ok,
            401 | 403 => (Self::Denied, rpc_codes::INVALID_REQUEST),
            400 | 404 => (Self::Invalid, rpc_codes::INVALID_PARAMS),
            _ => (Self::Error, rpc_codes::INTERNAL_ERROR),
        };
        kind(code.unwrap_or(default))
    }

    /// The JSON-RPC code an outcome of this kind carries when the answer had
    /// none: -32600 denied, -32602 invalid, -32603 error; none for `ok` and
    /// `tool_error`.
    #[must_use]
    pub fn default_code(self) -> Option<i32> {
        let status = match self {
            Self::Ok | Self::ToolError => return None,
            Self::Denied(_) => axum::http::StatusCode::FORBIDDEN,
            Self::Invalid(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::Error(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self::from_http_status(status, None).error_code()
    }

    /// The `error_code` field value; absent for `ok` and `tool_error`.
    #[must_use]
    pub const fn error_code(self) -> Option<i32> {
        match self {
            Self::Ok | Self::ToolError => None,
            Self::Denied(code) | Self::Invalid(code) | Self::Error(code) => Some(code),
        }
    }
}

/// What a failed append does to the gateway (D1-f).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFailurePolicy {
    /// Auth off: a failed append is logged and the call continues.
    BestEffort,
    /// Auth on: a failed append withholds the result and degrades the logger.
    FailClosed,
}

/// Who made an audited call: the credential and the verified
/// `(authority, subject)`, never an email or a display label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditWho {
    /// How the credential was presented; absent when the writer cannot know.
    #[serde(skip_serializing_if = "Option::is_none")]
    // ci-allow-secret-debug: an enum naming how a credential was presented; it holds no secret bytes.
    pub(crate) credential_kind: Option<CredentialKind>,
    /// 12 hex characters of `sha256(secret)`; empty when none was presented.
    pub(crate) principal: String,
    /// The configured key name, `bearer`, or the OIDC stable actor id.
    pub(crate) account: String,
    /// Identity authority (the OIDC issuer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) authority: Option<String>,
    /// Subject inside `authority`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) subject: Option<String>,
}

impl AuditWho {
    /// A governance actor. An OIDC actor id is the length-prefixed
    /// `oidc:<len>:<issuer>:<len>:<sub>`, so `(issuer, sub)` is recovered from it.
    #[must_use]
    pub fn from_actor_id(actor_id: &str) -> Self {
        let (authority, subject) = parse_oidc_actor(actor_id).unzip();
        Self {
            credential_kind: None,
            principal: String::new(),
            account: actor_id.to_string(),
            authority,
            subject,
        }
    }

    /// An identity-propagation subject: the user the credential is minted for.
    #[must_use]
    pub fn from_subject(subject: &str) -> Self {
        Self {
            credential_kind: None,
            principal: String::new(),
            account: subject.to_string(),
            authority: None,
            subject: Some(subject.to_string()),
        }
    }

    /// The gateway itself, for records no caller caused (`audit_probe`).
    #[must_use]
    pub fn gateway() -> Self {
        Self {
            credential_kind: None,
            principal: String::new(),
            account: "gateway".to_string(),
            authority: None,
            subject: None,
        }
    }

    /// The account, for the legacy `caller` field kept for one major version.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The caller of a direct-route request (D2-d): its credential and
    /// verified subject, never a label or an email.
    #[must_use]
    pub fn from_request(
        client: Option<&crate::gateway::auth::AuthenticatedClient>,
        grant_subject: Option<&crate::identity_grants::GrantSubject>,
    ) -> Self {
        Self::from_parts(
            CredentialKind::of(client),
            client.map(|c| c.principal.as_str()),
            client.map(|c| c.name.as_str()),
            grant_subject,
        )
    }

    /// The one invocation-caller constructor both routes delegate to.
    /// `authority` and `subject` come only from the verified grant subject.
    pub(crate) fn from_parts(
        credential_kind: CredentialKind,
        principal: Option<&str>,
        account: Option<&str>,
        grant_subject: Option<&crate::identity_grants::GrantSubject>,
    ) -> Self {
        Self {
            credential_kind: Some(credential_kind),
            principal: principal.unwrap_or_default().to_string(),
            account: account.unwrap_or("anonymous").to_string(),
            authority: grant_subject.map(|g| g.authority.clone()),
            subject: grant_subject.map(|g| g.subject.clone()),
        }
    }
}

/// Which route served an invocation (D2-f).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationRoute {
    /// `gateway_invoke` on the meta route.
    Meta,
    /// `tools/call` on `POST /mcp/{name}`.
    Direct,
}

impl InvocationRoute {
    /// The `route` field value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Meta => "meta",
            Self::Direct => "direct",
        }
    }
}

/// What an invocation record is about. `tool` is `None` when a malformed
/// call named none; the record then has no `tool` key.
#[derive(Debug, Clone, Copy)]
pub struct InvocationTarget<'a> {
    /// The route that served the call.
    pub route: InvocationRoute,
    /// The backend.
    pub server: &'a str,
    /// The tool, when the call named one.
    pub tool: Option<&'a str>,
}

impl<'a> InvocationTarget<'a> {
    /// A `gateway_invoke` of `tool` on `server`.
    #[must_use]
    pub const fn meta(server: &'a str, tool: &'a str) -> Self {
        Self {
            route: InvocationRoute::Meta,
            server,
            tool: Some(tool),
        }
    }
}

fn parse_oidc_actor(actor: &str) -> Option<(String, String)> {
    let rest = actor.strip_prefix("oidc:")?;
    let (len, rest) = rest.split_once(':')?;
    let issuer = rest.get(..len.parse::<usize>().ok()?)?;
    let rest = rest.get(issuer.len()..)?.strip_prefix(':')?;
    let (len, subject) = rest.split_once(':')?;
    (subject.len() == len.parse::<usize>().ok()?).then(|| (issuer.to_string(), subject.to_string()))
}

/// The fields the logger writes into every entry (D1-b). A writer passes one
/// next to its domain fields and cannot supply these keys itself.
#[derive(Debug, Clone)]
pub struct AuditEnvelope {
    /// The gateway trace id. `None` takes the current trace scope's, or mints one.
    pub trace_id: Option<String>,
    /// The W3C trace id the caller sent, when it sent one.
    pub otel_trace_id: Option<String>,
    /// What the call came to.
    pub outcome: AuditOutcome,
    /// Who made it.
    pub who: AuditWho,
}

impl AuditEnvelope {
    /// Entries without `schema_version` are v1.
    pub const SCHEMA_VERSION: u64 = 2;

    /// Keys only the logger writes.
    pub const RESERVED: [&'static str; 7] = [
        "schema_version",
        "trace_id",
        "otel_trace_id",
        "outcome",
        "error_code",
        "who",
        "type",
    ];

    /// A successful event by `who`, traced from the current scope.
    #[must_use]
    pub fn ok(who: AuditWho) -> Self {
        Self {
            trace_id: None,
            otel_trace_id: None,
            outcome: AuditOutcome::Ok,
            who,
        }
    }

    /// A record the gateway itself writes (`audit_probe`), traced from the
    /// current scope.
    #[must_use]
    pub fn gateway() -> Self {
        Self::ok(AuditWho::gateway())
    }

    /// A governance mutation by `actor_id` (a control-plane actor).
    #[must_use]
    pub fn governance(actor_id: &str) -> Self {
        Self::ok(AuditWho::from_actor_id(actor_id))
    }

    /// An identity-propagation mint or refusal for `subject`. A refusal is
    /// `denied` with the code its caller receives (`Error::Config`, -32603).
    #[must_use]
    pub fn identity_propagation(action: &str, subject: &str) -> Self {
        let outcome = if action == "idp_refuse" {
            AuditOutcome::Denied(crate::error::rpc_codes::INTERNAL_ERROR)
        } else {
            AuditOutcome::Ok
        };
        Self {
            outcome,
            ..Self::ok(AuditWho::from_subject(subject))
        }
    }

    pub(crate) fn write_into(&self, fields: &mut serde_json::Map<String, serde_json::Value>) {
        use crate::gateway::trace;
        let trace_id = self
            .trace_id
            .clone()
            .or_else(trace::current)
            .unwrap_or_else(trace::generate);
        fields.insert("schema_version".into(), Self::SCHEMA_VERSION.into());
        fields.insert("trace_id".into(), trace_id.into());
        if let Some(otel) = &self.otel_trace_id {
            fields.insert("otel_trace_id".into(), otel.clone().into());
        }
        fields.insert("outcome".into(), self.outcome.label().into());
        if let Some(code) = self.outcome.error_code() {
            fields.insert("error_code".into(), code.into());
        }
        fields.insert(
            "who".into(),
            serde_json::to_value(&self.who).unwrap_or(serde_json::Value::Null),
        );
    }
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
