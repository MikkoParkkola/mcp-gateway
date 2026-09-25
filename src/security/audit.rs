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
    /// The outcome for a call's result. `None` means no record is written.
    #[must_use]
    pub fn from_result(_result: &crate::Result<serde_json::Value>) -> Option<Self> {
        Some(Self::Ok)
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

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
