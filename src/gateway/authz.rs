// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The authorization port shared by the router and the meta layer.
//!
//! Authorization decisions are made in `router::authorization`, which owns the
//! policy. This module owns only the *vocabulary* the two layers need in
//! common: the target of a call, the refusal, and the trait through which the
//! meta layer asks without depending on `AppState`.
//!
//! That indirection exists for one structural reason: `AppState` owns
//! `meta_mcp`, so an `Arc<AppState>` stored inside `MetaMcp` is a reference
//! cycle that never frees. A [`ToolAuthorizer`] is therefore **borrowed per
//! request and never stored** — see `MetaMcpCallerContext`.
//!
//! Design: `docs/design/authorize-at-dispatch.md` (MIK-7252).

use axum::http::StatusCode;
use serde_json::Value;
use tracing::warn;

/// A backend tool invocation, owned.
pub(crate) struct OwnedToolTarget {
    pub server: String,
    pub tool: String,
    pub arguments: Value,
}

/// A backend tool invocation, borrowed.
///
/// Carries `arguments` even though no policy reads them today: the router's
/// pre-check already passes them, and a port with a narrower shape would drift
/// from `authorize_tool_target` the moment a policy does read them.
#[derive(Clone, Copy)]
pub struct ToolTarget<'a> {
    pub server: &'a str,
    pub tool: &'a str,
    pub arguments: &'a Value,
}

impl OwnedToolTarget {
    pub(crate) fn as_target(&self) -> ToolTarget<'_> {
        ToolTarget {
            server: &self.server,
            tool: &self.tool,
            arguments: &self.arguments,
        }
    }
}

/// A refusal, carrying the code and status the client-facing envelope needs.
#[derive(Debug, Clone)]
pub struct AuthorizationError {
    pub code: i32,
    pub status: StatusCode,
    pub message: String,
}

impl AuthorizationError {
    pub(crate) fn forbidden(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }
}

/// Which transport the caller arrived on.
///
/// Reported by the authorizer rather than carried beside it: a field set next
/// to the authorizer can disagree with the authorizer that actually decided,
/// and an audit line naming the wrong transport is worse than none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Http,
    Stdio,
    #[cfg(test)]
    Test,
}

impl Transport {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Stdio => "stdio",
            #[cfg(test)]
            Self::Test => "test",
        }
    }
}

/// Asks whether a caller may invoke a backend tool.
///
/// Implemented once per transport, because the transports carry different
/// identity: HTTP has a client, a certificate and an agent identity; stdio has
/// none of them and only a global tool policy to apply.
pub trait ToolAuthorizer {
    /// # Errors
    /// Returns the refusal when the caller may not invoke this target.
    fn authorize(&self, target: ToolTarget<'_>) -> Result<(), AuthorizationError>;

    /// The transport this authorizer speaks for, used only for audit.
    fn transport(&self) -> Transport;

    /// A stable name for the caller, for audit. `None` when unauthenticated.
    fn caller_name(&self) -> Option<&str>;
}

/// Emits the audit line for a refusal.
///
/// Owned here, and called by **both** gates — the router's pre-check and the
/// dispatch chokepoint — because the router returns its error response without
/// entering the meta layer, so a chokepoint-only emitter would never fire for
/// any router-covered shape. One emitter also means one format.
///
/// Never called by a `ToolAuthorizer` implementation: an authorizer that stayed
/// silent would otherwise be able to suppress the record of its own refusal.
pub(crate) fn audit_refusal(
    transport: Transport,
    caller: Option<&str>,
    server: &str,
    tool: &str,
    reason: &str,
) {
    warn!(
        transport = transport.as_str(),
        caller = caller.unwrap_or("<unauthenticated>"),
        server,
        tool,
        reason,
        "Tool invocation refused by authorization"
    );
}

/// Permits everything. Test-only, so a release build cannot reach it and the
/// guard cannot be defeated by satisfying the type permissively.
#[cfg(test)]
pub(crate) struct AllowAll;

#[cfg(test)]
impl ToolAuthorizer for AllowAll {
    fn authorize(&self, _target: ToolTarget<'_>) -> Result<(), AuthorizationError> {
        Ok(())
    }
    fn transport(&self) -> Transport {
        Transport::Test
    }
    fn caller_name(&self) -> Option<&str> {
        None
    }
}

/// Refuses everything. Test-only, and the instrument for the chokepoint
/// coverage cases: every dispatch shape must be refused when it denies.
#[cfg(test)]
pub(crate) struct DenyAll;

#[cfg(test)]
impl ToolAuthorizer for DenyAll {
    fn authorize(&self, target: ToolTarget<'_>) -> Result<(), AuthorizationError> {
        Err(AuthorizationError::forbidden(
            -32003,
            format!(
                "denied by test authorizer: '{}' on '{}'",
                target.tool, target.server
            ),
        ))
    }
    fn transport(&self) -> Transport {
        Transport::Test
    }
    fn caller_name(&self) -> Option<&str> {
        None
    }
}

/// Counts consultations, delegating the verdict. Test-only.
///
/// Counts per `(server, tool)` rather than in total: a whole-run count is
/// satisfied by a terminal refusal, and cannot distinguish "consulted once for
/// this step" from "consulted once for the whole playbook".
#[cfg(test)]
pub(crate) struct CountingAuthorizer<A: ToolAuthorizer> {
    inner: A,
    counts: std::sync::Mutex<std::collections::BTreeMap<String, usize>>,
}

#[cfg(test)]
impl<A: ToolAuthorizer> CountingAuthorizer<A> {
    pub(crate) fn new(inner: A) -> Self {
        Self {
            inner,
            counts: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    /// Consultations recorded for one target.
    pub(crate) fn count_for(&self, server: &str, tool: &str) -> usize {
        self.counts
            .lock()
            .expect("counting authorizer mutex poisoned")
            .get(&format!("{server}:{tool}"))
            .copied()
            .unwrap_or(0)
    }
}

#[cfg(test)]
impl<A: ToolAuthorizer> ToolAuthorizer for CountingAuthorizer<A> {
    fn authorize(&self, target: ToolTarget<'_>) -> Result<(), AuthorizationError> {
        *self
            .counts
            .lock()
            .expect("counting authorizer mutex poisoned")
            .entry(format!("{}:{}", target.server, target.tool))
            .or_insert(0) += 1;
        self.inner.authorize(target)
    }
    fn transport(&self) -> Transport {
        self.inner.transport()
    }
    fn caller_name(&self) -> Option<&str> {
        self.inner.caller_name()
    }
}

/// The stdio authorizer: the global tool policy, and nothing else.
///
/// stdio has no client, no certificate and no agent identity to scope against,
/// so the checks that need one are not merely skipped — they are inapplicable.
/// mTLS in particular must NOT be evaluated here: `MtlsPolicy::evaluate`
/// returns `Deny` for a `None` identity once the policy is enabled, so an
/// operator who configured any certificate rule would find every stdio call
/// refused. mTLS is a property of a network transport stdio does not use.
///
/// This replaces the inline check that ran for `gateway_invoke` alone, so a
/// stdio playbook or code-mode step is now covered where it was not.
pub(crate) struct ToolPolicyAuthorizer<'a> {
    pub(crate) tool_policy: &'a crate::security::ToolPolicy,
}

impl ToolAuthorizer for ToolPolicyAuthorizer<'_> {
    fn authorize(&self, target: ToolTarget<'_>) -> Result<(), AuthorizationError> {
        if target.server.is_empty() || target.tool.is_empty() {
            return Ok(());
        }
        crate::security::validate_tool_name(target.tool)
            .map_err(|e| AuthorizationError::forbidden(-32600, e.clone()))?;
        self.tool_policy
            .check(target.server, target.tool)
            .map_err(|e| AuthorizationError::forbidden(-32600, e.to_string()))
    }

    fn transport(&self) -> Transport {
        Transport::Stdio
    }

    fn caller_name(&self) -> Option<&str> {
        // The client spawned this process, so it holds whatever the operator
        // holds. There is no separate principal to name.
        None
    }
}
