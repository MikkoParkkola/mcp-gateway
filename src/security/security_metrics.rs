// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D4 (MIK-7570.METRICS.2): security events as Prometheus counters.
//!
//! `mcp_auth_failures_total{kind}` counts refused credentials and
//! `mcp_authz_denials_total{route, reason}` counts refused calls. Every label
//! is an `&'static str` from a closed enum: `/metrics` is read by whoever holds
//! the scrape token, so no label may carry a key name, subject, backend, tool
//! or path. Per-principal breakdowns stay in the audit log.

use serde_json::Value;

use crate::Error;
use crate::security::audit::AuditOutcome;

/// Why a presented credential was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthFailureKind {
    MissingCredential,
    InvalidCredential,
    ExpiredApiKey,
    SessionExpired,
    BootstrapRefused,
    TokenExchangeDenied,
    TokenExchangeInvalid,
}

impl AuthFailureKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::MissingCredential => "missing_credential",
            Self::InvalidCredential => "invalid_credential",
            Self::ExpiredApiKey => "expired_api_key",
            Self::SessionExpired => "session_expired",
            Self::BootstrapRefused => "bootstrap_refused",
            Self::TokenExchangeDenied => "token_exchange_denied",
            Self::TokenExchangeInvalid => "token_exchange_invalid",
        }
    }
}

/// Where a call was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DenialRoute {
    Meta,
    Direct,
    Admin,
    /// The admin UI exists only with the `webui` feature.
    #[cfg(feature = "webui")]
    Ui,
    /// The control-plane pages of the admin UI, refused by their RBAC.
    #[cfg(feature = "webui")]
    ControlPlane,
}

impl DenialRoute {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Meta => "meta",
            Self::Direct => "direct",
            Self::Admin => "admin",
            #[cfg(feature = "webui")]
            Self::Ui => "ui",
            #[cfg(feature = "webui")]
            Self::ControlPlane => "control_plane",
        }
    }
}

/// Why a call was refused. One set for every route, so the same refusal
/// reads the same on the meta and the direct route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DenialReason {
    BackendScope,
    AccountNotUsable,
    IdentityGrant,
    GatewayRefusal,
    ResponseFirewall,
    RequestPolicy,
    AdminRequired,
    #[cfg(feature = "webui")]
    Rbac,
    Other,
}

impl DenialReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BackendScope => "backend_scope",
            Self::AccountNotUsable => "account_not_usable",
            Self::IdentityGrant => "identity_grant",
            Self::GatewayRefusal => "gateway_refusal",
            Self::ResponseFirewall => "response_firewall",
            Self::RequestPolicy => "request_policy",
            Self::AdminRequired => "admin_required",
            #[cfg(feature = "webui")]
            Self::Rbac => "rbac",
            Self::Other => "other",
        }
    }

    /// The one classifier for a refusal's JSON-RPC code. The response
    /// firewall answers with -32600 and an account offer rides -32001 on the
    /// meta route and -32003 on the direct one, so both are decided before
    /// the code.
    pub(crate) const fn of(code: i32, account_offer: bool, firewall: bool) -> Self {
        if firewall {
            return Self::ResponseFirewall;
        }
        if account_offer {
            return Self::AccountNotUsable;
        }
        match code {
            -32003 => Self::BackendScope,
            -32004 => Self::IdentityGrant,
            -32001 => Self::GatewayRefusal,
            -32600 => Self::RequestPolicy,
            _ => Self::Other,
        }
    }
}

pub(crate) fn auth_failure(kind: AuthFailureKind) {
    telemetry_metrics::counter!("mcp_auth_failures_total", "kind" => kind.as_str()).increment(1);
}

pub(crate) fn denied(route: DenialRoute, reason: DenialReason) {
    telemetry_metrics::counter!(
        "mcp_authz_denials_total",
        "route" => route.as_str(),
        "reason" => reason.as_str()
    )
    .increment(1);
}

/// Count a meta-route refusal the router answers before the meta layer runs,
/// and hand its code on to the answer.
pub(crate) fn meta_refused(code: i32) -> i32 {
    denied(DenialRoute::Meta, DenialReason::of(code, false, false));
    code
}

/// The meta route's reason for `result`, when D1 records it as `denied`.
pub(crate) fn meta_denial(result: &crate::Result<Value>) -> Option<DenialReason> {
    let Some(AuditOutcome::Denied(code)) = AuditOutcome::from_result(result) else {
        return None;
    };
    let error = result.as_ref().err()?;
    Some(DenialReason::of(
        code,
        crate::personal_accounts::refusal::offer_data(error).is_some(),
        matches!(error, Error::ResponseFirewallRefused),
    ))
}

/// The direct route's reason for an answer whose outcome is `denied`, read
/// from the answer the caller receives. `firewall`: the answer is the
/// response firewall's refusal.
pub(crate) fn direct_denial(
    outcome: AuditOutcome,
    body: &Value,
    firewall: bool,
) -> Option<DenialReason> {
    let AuditOutcome::Denied(code) = outcome else {
        return None;
    };
    let error = body.get("error").unwrap_or(&Value::Null);
    let offer = ["account_id", "connect_url"]
        .iter()
        .any(|key| error.pointer(&format!("/data/{key}")).is_some());
    Some(DenialReason::of(code, offer, firewall))
}

#[cfg(test)]
#[path = "security_metrics_unit_tests.rs"]
mod tests;
