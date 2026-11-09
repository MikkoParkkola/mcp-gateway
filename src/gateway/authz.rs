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

use crate::error::rpc_codes::INVALID_REQUEST;
use axum::http::StatusCode;
use serde_json::Value;
use tracing::warn;

use super::auth::QuotaPrincipal;

/// The key under which a refusal carries its HTTP status in the JSON-RPC
/// error's `data`.
///
/// Carried, not inferred. An earlier repair mapped 403 by matching the
/// JSON-RPC code, which was wrong twice over: eight of the nine refusal
/// branches emit the generic `-32600`, so most refusals would still have
/// answered 200, and `-32003` is already used elsewhere for budget exhaustion,
/// so that one would have been reclassified as forbidden. A code is not an
/// identity. The status is stamped by the one place that mints a refusal and
/// read by the one place that answers HTTP, and nothing else is touched —
/// changing the eight existing codes would be a client-visible break for no
/// gain here.
pub const HTTP_STATUS_DATA_KEY: &str = "gateway_http_status";

/// A backend tool invocation: owned names, and the arguments borrowed from
/// the request whenever they already exist there (MIK-8014: no per-call copy).
pub(crate) struct CallTarget<'a> {
    pub server: String,
    pub tool: String,
    pub arguments: std::borrow::Cow<'a, Value>,
}

/// The `arguments` a call dispatches, as every gate judges them: the
/// JSON-string form parsed to the object it is sent as (MIK-8137 b1: a string
/// once skipped the request scan, which reads objects), otherwise the value as
/// given (`{}` when absent). A string that does not parse to an object is kept
/// as given; [`crate::gateway::meta_mcp_helpers::parse_tool_arguments`] refuses that call before any dispatch.
pub(crate) fn judged_arguments(holder: &Value) -> std::borrow::Cow<'_, Value> {
    use std::borrow::Cow;
    match holder.get("arguments") {
        // Owned only here, where a string had to be parsed (MIK-8014 keeps
        // the object form borrowed).
        Some(raw @ Value::String(_)) => {
            crate::gateway::meta_mcp_helpers::parse_tool_arguments_cow(holder)
                .unwrap_or(Cow::Borrowed(raw))
        }
        Some(value) => Cow::Borrowed(value),
        None => Cow::Owned(serde_json::json!({})),
    }
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

impl CallTarget<'_> {
    pub(crate) fn as_target(&self) -> ToolTarget<'_> {
        ToolTarget {
            server: &self.server,
            tool: &self.tool,
            arguments: self.arguments.as_ref(),
        }
    }
}

/// A refusal, carrying the code and status the client-facing envelope needs.
///
/// `kind` names the check that refused, for the decision record only: it is
/// crate-private, never serialized, and left out of `Debug`, so no response
/// body or log line can carry it and the wire stays exactly as it was.
#[derive(Clone)]
pub struct AuthorizationError {
    pub code: i32,
    pub status: StatusCode,
    pub message: String,
    pub(crate) kind: crate::security::decision_record::DecisionKind,
    /// The configured rule that refused, for the decision record only, never
    /// delivered: a refused caller cannot learn which rule blocked it.
    pub(crate) rule_id: Option<crate::security::rule_id::RuleId>,
}

#[expect(
    clippy::missing_fields_in_debug,
    reason = "kind and rule_id are deliberately left out so no log line can carry them"
)]
impl std::fmt::Debug for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationError")
            .field("code", &self.code)
            .field("status", &self.status)
            .field("message", &self.message)
            .finish()
    }
}

impl AuthorizationError {
    pub(crate) fn forbidden(
        kind: crate::security::decision_record::DecisionKind,
        code: i32,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            status: StatusCode::FORBIDDEN,
            message: message.into(),
            kind,
            rule_id: None,
        }
    }

    /// This refusal, naming the configured rule that made it.
    #[must_use]
    pub(crate) fn with_rule(mut self, rule_id: Option<crate::security::rule_id::RuleId>) -> Self {
        self.rule_id = rule_id;
        self
    }
}

/// The tool policy on `target`, as every transport's authorizer judges it: a
/// refusal is `-32600` and names the policy entry that made it, for the
/// decision record only. An allow keeps the allow-list entry that admitted
/// the call (D6): `Ok(None)` when no entry did (the policy is off, or its
/// default action allowed, which names no entry).
pub(crate) fn tool_policy_refusal(
    policy: &crate::security::ToolPolicy,
    target: ToolTarget<'_>,
) -> Result<Option<crate::security::rule_id::RuleId>, AuthorizationError> {
    policy
        .check_explained(target.server, target.tool)
        .map(Option::<&crate::security::rule_id::RuleId>::cloned)
        .map_err(|(e, rule)| {
            AuthorizationError::forbidden(
                crate::security::decision_record::DecisionKind::ToolPolicy,
                INVALID_REQUEST,
                e.to_string(),
            )
            .with_rule(rule.cloned())
        })
}

/// The caller's backend scope: whether an API key or key-server token may
/// reach `server` at all.
///
/// The one backend-level check. `tools/call` reaches it through
/// `router::authorization::authorize_tool_target`, and the resource and prompt
/// methods — which carry no tool name for the rest of that policy to key on —
/// call it directly, so the two cannot drift. `None` is stdio or a caller the
/// auth layer attached no client to, which holds no backend scope.
pub(crate) fn authorize_backend(
    client: Option<&super::auth::AuthenticatedClient>,
    server: &str,
) -> Result<(), AuthorizationError> {
    match client {
        Some(client) if !client.can_access_backend(server) => Err(AuthorizationError::forbidden(
            crate::security::decision_record::DecisionKind::BackendScope,
            -32003,
            client.backend_refusal(server),
        )),
        _ => Ok(()),
    }
}

/// A caller's backend grant, as [`authorize_backend`] reads it (MIK-8387):
/// the one input the scoped absence predicate judges a name against. `pub`
/// like the trait's other return types (`Transport`, `Decision`): the module
/// is crate-private, so this reaches no further than the crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendGrant<'a> {
    /// No client (stdio, key-less), or a list holding `*`: no scope to hide.
    Unscoped,
    /// A non-empty list without `*`.
    Scoped(&'a [String]),
    /// `backends: []`: reaches nothing, and keeps its named grant message.
    Empty,
}

impl<'a> BackendGrant<'a> {
    pub(crate) fn of(client: Option<&'a super::auth::AuthenticatedClient>) -> Self {
        client.map_or(Self::Unscoped, |client| Self::of_list(&client.backends))
    }

    /// The grant a `backends` list makes, for a caller holding the list
    /// apart from its client (an Activity read outlives the request).
    pub(crate) fn of_list(backends: &'a [String]) -> Self {
        if backends.iter().any(|b| b == "*") {
            Self::Unscoped
        } else if backends.is_empty() {
            Self::Empty
        } else {
            Self::Scoped(backends)
        }
    }

    /// The grant the web UI reads and administers by. An admin key with an
    /// empty backend list is a UI-wide admin that calls no backend; a
    /// non-empty list without `*` narrows the UI to those backends, admin or
    /// not. Every other case is [`Self::of`].
    #[cfg(feature = "webui")]
    pub(crate) fn for_ui(client: Option<&'a super::auth::AuthenticatedClient>) -> Self {
        client.map_or(Self::Unscoped, |client| {
            Self::for_ui_list(client.admin, &client.backends)
        })
    }

    /// `for_ui` for a key held apart from its client (the web UI's rule, used
    /// also where a session is checked against the key that minted it).
    pub(crate) fn for_ui_list(admin: bool, backends: &'a [String]) -> Self {
        match Self::of_list(backends) {
            Self::Empty if admin => Self::Unscoped,
            grant => grant,
        }
    }

    /// Whether this grant reaches backend `name`: the one membership test the
    /// UI's scoped reads share, so no surface judges a scope its own way. It
    /// agrees with `AuthenticatedClient::can_access_backend` for every grant
    /// shape, a pinned row (MCP dispatch still reads that one).
    #[cfg(feature = "webui")]
    pub(crate) fn admits(self, name: &str) -> bool {
        match self {
            Self::Unscoped => true,
            Self::Scoped(backends) => backends.iter().any(|b| b == name),
            Self::Empty => false,
        }
    }
}

/// How far a caller's admin flag reaches. Declared lowest first,
/// so the derived order is the rank: a step down is `fresh < captured`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdminStanding {
    /// Not an admin.
    None,
    /// An admin scoped to some backends: admin breadth inside the scope
    /// (Activity, admin-only capabilities on its backends), never past it.
    InScope,
    /// An admin whose scope is every backend (`*`, or an admin key with no
    /// backends): the gateway-wide admin powers.
    Gateway,
}

impl AdminStanding {
    /// Whether this standing holds the gateway-wide admin powers.
    #[must_use]
    pub(crate) const fn is_gateway(self) -> bool {
        matches!(self, Self::Gateway)
    }
}

/// The one rule from an admin flag and a backend list to a standing, on the
/// web UI's reading of the list ([`BackendGrant::for_ui_list`]), so an admin
/// key with no backends stays a gateway-wide admin.
pub(crate) fn admin_standing(admin: bool, backends: &[String]) -> AdminStanding {
    if !admin {
        AdminStanding::None
    } else if BackendGrant::for_ui_list(true, backends) == BackendGrant::Unscoped {
        AdminStanding::Gateway
    } else {
        AdminStanding::InScope
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
    /// The verdict for `target`, with any audit record deferred.
    ///
    /// Side-effect free: a decision records nothing until [`Authorize`]
    /// emits it. Discovery asks this and discards the record, so listing a
    /// catalogue writes no invocation audit trail.
    fn decide<'a>(&'a self, target: ToolTarget<'a>) -> Decision<'a>;

    /// Whether the backend itself is reachable for this caller: the
    /// backend-level half of `decide`, asked where a backend name is disclosed
    /// with no tool in hand (a server list, a cold cache).
    fn admits_backend(&self, server: &str) -> bool;

    /// The transport this authorizer speaks for, used only for audit.
    fn transport(&self) -> Transport;

    /// A stable name for the caller, for audit. `None` when unauthenticated.
    fn caller_name(&self) -> Option<&str>;

    /// Validated quota authority, never a client-selected name or session ID.
    /// Each transport and wrapper must explicitly preserve or omit authority.
    fn quota_principal(&self) -> Option<&QuotaPrincipal>;

    /// The caller's backend grant (MIK-8387). Required, like
    /// `quota_principal`: a wrapper delegates, and only a transport with no
    /// client scope answers [`BackendGrant::Unscoped`].
    fn backend_grant(&self) -> BackendGrant<'_>;

    /// The generation this caller is judged under: the request's pinned one,
    /// or the one current at a queued dispatch. `None` only for an authorizer
    /// built from no request (the unscoped operator, a test's), which is
    /// judged under the generation published at the check, never the startup
    /// policy. Required, with no default: an authorizer that forgot it would
    /// judge with stale rules and nothing would fail.
    fn generation(&self) -> Option<&crate::config_reload::Generation>;
}

/// Whether a decision writes its audit record. An enum rather than a `bool`
/// because it selects behaviour, and the silent direction must be explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emit {
    /// The invocation path: write the record, as every call always has.
    Audit,
    /// Discovery: the same verdict, no record.
    Silent,
}

/// A verdict and the audit record [`Authorize::authorize`] writes for it.
pub struct Decision<'a> {
    pub verdict: Result<(), AuthorizationError>,
    record: Option<Box<dyn FnOnce() + 'a>>,
    /// The check that allowed, noted for the call's record when the
    /// decision is emitted under [`Emit::Audit`] and the verdict allows.
    allow: Option<crate::security::decision_record::Allow>,
}

impl<'a> Decision<'a> {
    /// A verdict that records nothing.
    pub(crate) fn of(verdict: Result<(), AuthorizationError>) -> Self {
        Self {
            verdict,
            record: None,
            allow: None,
        }
    }

    /// A verdict whose audit record runs only when emitted.
    pub(crate) fn recorded(
        verdict: Result<(), AuthorizationError>,
        record: impl FnOnce() + 'a,
    ) -> Self {
        Self {
            verdict,
            record: Some(Box::new(record)),
            allow: None,
        }
    }

    /// This decision, naming the check that allowed it; a lower rank already
    /// held is kept.
    #[must_use]
    pub(crate) fn allowing(
        mut self,
        allow: Option<crate::security::decision_record::Allow>,
    ) -> Self {
        self.allow = match (self.allow, allow) {
            (Some(held), Some(next)) if held.rank <= next.rank => Some(held),
            (held, next) => next.or(held),
        };
        self
    }

    /// The verdict, writing the record first under [`Emit::Audit`].
    ///
    /// # Errors
    /// Returns the refusal when the verdict is one.
    pub(crate) fn emit(self, emit: Emit) -> Result<(), AuthorizationError> {
        if emit == Emit::Audit
            && let Some(record) = self.record
        {
            record();
        }
        // Only an audited allow names its check: a listing or a silent
        // recheck must never write into a call's notes.
        if emit == Emit::Audit
            && self.verdict.is_ok()
            && let Some(allow) = self.allow
        {
            crate::gateway::meta_mcp::invoke::audit::note_allowed_by(allow);
        }
        self.verdict
    }
}

/// `decide` plus its audit record. A blanket implementation, so no authorizer
/// can override it and skip the record.
pub trait Authorize {
    /// # Errors
    /// Returns the refusal when the caller may not invoke this target.
    fn authorize(&self, target: ToolTarget<'_>) -> Result<(), AuthorizationError>;
}

impl<T: ToolAuthorizer + ?Sized> Authorize for T {
    fn authorize(&self, target: ToolTarget<'_>) -> Result<(), AuthorizationError> {
        self.decide(target).emit(Emit::Audit)
    }
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
    fn generation(&self) -> Option<&crate::config_reload::Generation> {
        None
    }
    fn quota_principal(&self) -> Option<&QuotaPrincipal> {
        None
    }
    fn backend_grant(&self) -> BackendGrant<'_> {
        BackendGrant::Unscoped
    }
    fn decide<'a>(&'a self, _target: ToolTarget<'a>) -> Decision<'a> {
        Decision::of(Ok(()))
    }
    fn admits_backend(&self, _server: &str) -> bool {
        true
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
    fn generation(&self) -> Option<&crate::config_reload::Generation> {
        None
    }
    fn quota_principal(&self) -> Option<&QuotaPrincipal> {
        None
    }
    fn backend_grant(&self) -> BackendGrant<'_> {
        BackendGrant::Unscoped
    }
    fn decide<'a>(&'a self, target: ToolTarget<'a>) -> Decision<'a> {
        Decision::of(Err(AuthorizationError::forbidden(
            crate::security::decision_record::DecisionKind::ToolPolicy,
            -32003,
            format!(
                "denied by test authorizer: '{}' on '{}'",
                target.tool, target.server
            ),
        )))
    }
    fn admits_backend(&self, _server: &str) -> bool {
        false
    }
    fn transport(&self) -> Transport {
        Transport::Test
    }
    fn caller_name(&self) -> Option<&str> {
        None
    }
}

/// Denies one named tool and permits everything else. Test-only.
///
/// `DenyAll` cannot express "the run carried on to a step it WAS allowed to
/// take", because it denies that step too — so a case asserting a successor
/// executes needs a selective verdict or it asserts nothing about success.
#[cfg(test)]
pub(crate) struct DenyOne {
    pub(crate) tool: &'static str,
}

#[cfg(test)]
impl ToolAuthorizer for DenyOne {
    fn generation(&self) -> Option<&crate::config_reload::Generation> {
        None
    }
    fn quota_principal(&self) -> Option<&QuotaPrincipal> {
        None
    }
    fn backend_grant(&self) -> BackendGrant<'_> {
        BackendGrant::Unscoped
    }
    fn decide<'a>(&'a self, target: ToolTarget<'a>) -> Decision<'a> {
        if target.tool == self.tool {
            return Decision::of(Err(AuthorizationError::forbidden(
                crate::security::decision_record::DecisionKind::ToolPolicy,
                -32003,
                format!("denied by test authorizer: '{}'", target.tool),
            )));
        }
        Decision::of(Ok(()))
    }
    fn admits_backend(&self, _server: &str) -> bool {
        true
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
    fn generation(&self) -> Option<&crate::config_reload::Generation> {
        self.inner.generation()
    }
    fn quota_principal(&self) -> Option<&QuotaPrincipal> {
        self.inner.quota_principal()
    }
    fn backend_grant(&self) -> BackendGrant<'_> {
        self.inner.backend_grant()
    }
    fn decide<'a>(&'a self, target: ToolTarget<'a>) -> Decision<'a> {
        *self
            .counts
            .lock()
            .expect("counting authorizer mutex poisoned")
            .entry(format!("{}:{}", target.server, target.tool))
            .or_insert(0) += 1;
        self.inner.decide(target)
    }
    fn admits_backend(&self, server: &str) -> bool {
        self.inner.admits_backend(server)
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
/// What a stdio line is judged with: its generation, taken as the line is
/// read (ADR-029, amended, item 5). Tests pass a real generation too
/// (`test_line`), so no line is judged under an invented config.
pub(crate) trait StdioLine: Sync {
    /// The tool policy that decides the line's calls.
    fn tool_policy(&self) -> &crate::security::ToolPolicy;
    /// The generation the line is judged under: always the one pinned as the
    /// line was read, never a later read of the live config.
    fn generation(&self) -> &crate::config_reload::Generation;
    /// The generation a reader that outlives the borrow judges the line
    /// under. Never absent: a catalogue read has no fallback to the config
    /// published later.
    fn pinned(&self) -> std::sync::Arc<crate::config_reload::Generation>;
}

impl StdioLine for std::sync::Arc<crate::config_reload::Generation> {
    fn tool_policy(&self) -> &crate::security::ToolPolicy {
        crate::config_reload::Generation::tool_policy(self)
    }
    fn generation(&self) -> &crate::config_reload::Generation {
        self
    }
    fn pinned(&self) -> std::sync::Arc<crate::config_reload::Generation> {
        std::sync::Arc::clone(self)
    }
}

/// A test's stdio line, pinned as the serve loop pins one when it reads it:
/// the generation `meta` publishes now with `policy` as its tool policy (its
/// keys kept), or, for a gateway that publishes none, the default config
/// with it. Never a bare policy judged under no generation.
#[cfg(test)]
pub(crate) fn test_line(
    meta: &crate::gateway::meta_mcp::MetaMcp,
    policy: &crate::security::ToolPolicyConfig,
) -> std::sync::Arc<crate::config_reload::Generation> {
    use crate::config_reload::LiveConfig;
    let Some(published) = meta.current_generation() else {
        let mut config = crate::config::Config::default();
        config.security.tool_policy = policy.clone();
        return LiveConfig::new(config).generation();
    };
    let mut config = (**published.config()).clone();
    config.security.tool_policy = policy.clone();
    LiveConfig::with_auth(config, std::sync::Arc::clone(published.auth())).generation()
}

/// [`test_line`] under the default tool policy.
#[cfg(test)]
pub(crate) fn default_line(
    meta: &crate::gateway::meta_mcp::MetaMcp,
) -> std::sync::Arc<crate::config_reload::Generation> {
    test_line(meta, &crate::security::ToolPolicyConfig::default())
}

/// The generation a published test gateway serves a stdio line under.
#[cfg(test)]
pub(crate) fn published_line(
    meta: &crate::gateway::meta_mcp::MetaMcp,
) -> std::sync::Arc<crate::config_reload::Generation> {
    meta.current_generation()
        .expect("the fixture publishes a generation")
}

pub(crate) struct ToolPolicyAuthorizer<'a> {
    pub(crate) tool_policy: &'a crate::security::ToolPolicy,
    /// The generation the call is judged under; `tool_policy` is its policy.
    /// `None` only for a test's own policy.
    pub(crate) generation: Option<&'a crate::config_reload::Generation>,
}

impl ToolAuthorizer for ToolPolicyAuthorizer<'_> {
    fn generation(&self) -> Option<&crate::config_reload::Generation> {
        self.generation
    }
    fn quota_principal(&self) -> Option<&QuotaPrincipal> {
        None
    }
    fn backend_grant(&self) -> BackendGrant<'_> {
        BackendGrant::Unscoped
    }
    fn decide<'a>(&'a self, target: ToolTarget<'a>) -> Decision<'a> {
        if target.server.is_empty() || target.tool.is_empty() {
            return Decision::of(Ok(()));
        }
        let verdict = crate::security::validate_tool_name(target.tool)
            .map_err(|e| {
                AuthorizationError::forbidden(
                    crate::security::decision_record::DecisionKind::Syntax,
                    INVALID_REQUEST,
                    e.clone(),
                )
            })
            .and_then(|()| tool_policy_refusal(self.tool_policy, target));
        // D6: the allow-list entry that admitted the call is its allow.
        let entry = verdict.as_ref().ok().cloned().flatten();
        Decision::of(verdict.map(|_| ())).allowing(entry.map(|id| {
            crate::security::decision_record::Allow::by(
                crate::security::decision_record::AllowRank::ToolPolicy,
                Some(id),
            )
        }))
    }

    /// stdio carries no per-caller backend scope.
    fn admits_backend(&self, _server: &str) -> bool {
        true
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

#[cfg(test)]
#[path = "authz_rule_id_tests.rs"]
mod rule_id_tests;

#[cfg(test)]
#[path = "authz_allow_emit_tests.rs"]
mod allow_emit_tests;
#[cfg(test)]
#[path = "authz_standing_tests.rs"]
mod standing_tests;
