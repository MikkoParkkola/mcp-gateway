// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's caller identity for per-caller firewall controls, and
//! its relay check and delivery recording (COLLUDE.1, design
//! `2026-09-28-asi10-verbatim-relay.md` §13.1).

use axum::http::StatusCode;
use serde_json::Value;
use tracing::warn;

use super::{AppState, BackendAuthContext, BackendRejection, backend_security_error_with_status};
use crate::protocol::RequestId;
use crate::security::firewall::{Firewall, FirewallAction, RelayCaller};

/// The key the direct route's per-caller firewall controls score on: the
/// caller's `CallerKey`, as on the meta route, so one caller has one budget on
/// both. With no key (authentication off) it is the shared per-backend bucket,
/// never tracked; a keyed caller's reclaim deadline is renewed (CONTROL.4).
pub(super) fn direct_control_identity(
    state: &AppState,
    auth: BackendAuthContext<'_>,
    per_backend: &str,
) -> String {
    let (key, keyed) = direct_caller(auth, per_backend);
    if !keyed {
        return key;
    }
    if let Some(ref lifecycle) = state.session_lifecycle {
        use crate::gateway::session_lifecycle::{IDLE_TTL, now_unix};
        lifecycle.track(key.clone(), now_unix() + IDLE_TTL.as_secs());
    }
    key
}

/// The direct caller's key and whether it is a real identity (`true`) or the
/// shared `per_backend` fallback. The one rule for every per-caller control
/// on this route, relay detection included.
fn direct_caller(auth: BackendAuthContext<'_>, per_backend: &str) -> (String, bool) {
    let key = crate::gateway::router::identity::caller_key(
        auth.grant_subject,
        auth.cert_identity,
        auth.client,
    );
    if key.is_empty() {
        (per_backend.to_string(), false)
    } else {
        (key, true)
    }
}

/// The relay check on everything the backend will receive, `_meta`
/// included. Runs before idempotency admission, so a refusal reserves
/// nothing. `Some` is the refusal to answer with.
pub(super) fn relay_refusal(
    fw: &Firewall,
    auth: BackendAuthContext<'_>,
    id: &RequestId,
    (backend, tool): (&str, &str),
    params: &Value,
    (session_id, caller_name): (&str, &str),
) -> Option<BackendRejection> {
    let (key, keyed) = direct_caller(auth, session_id);
    let caller = RelayCaller::new(&key, keyed);
    let verdict = fw.check_relay(caller, backend, tool, params, (session_id, caller_name));
    if verdict.action == FirewallAction::Warn {
        warn!(backend = %backend, tool = %tool, "Firewall: relay observed");
    }
    if verdict.allowed {
        return None;
    }
    let desc = verdict
        .findings
        .first()
        .map_or("", |f| f.description.as_str());
    Some(backend_security_error_with_status(
        id,
        -32002,
        &format!("Relay detection blocked: {desc}"),
        StatusCode::FORBIDDEN,
    ))
}

/// Record what the direct caller was actually delivered, after every gate,
/// redaction and the provenance stamp.
pub(super) fn record_direct_delivery(
    state: &AppState,
    auth: BackendAuthContext<'_>,
    server: &str,
    tool: &str,
    result: Option<&Value>,
) {
    let (Some(fw), Some(result)) = (state.firewall.as_ref(), result) else {
        return;
    };
    let (key, keyed) = direct_caller(auth, &format!("direct:{server}"));
    fw.record_delivery(RelayCaller::new(&key, keyed), server, tool, result);
}
