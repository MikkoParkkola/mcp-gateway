// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's caller identity for per-caller firewall controls, and
//! its relay check and delivery recording (COLLUDE.1, design
//! `2026-09-28-asi10-verbatim-relay.md` §13.1).

use axum::http::StatusCode;
use serde_json::Value;

use super::{AppState, BackendAuthContext, BackendRejection, backend_security_error_with_status};
use crate::gateway::meta_mcp::invoke::relay::GatewayStamps;
use crate::protocol::RequestId;
use crate::security::firewall::{Firewall, RelayCaller};

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
        lifecycle.renew(key.clone());
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
    // The progress token is the gateway's own, substituted for the client's:
    // it is not content the caller sent, so it is not scanned (MIK-7832).
    let scanned = without_progress_token(params);
    let message = fw.relay_block_message(
        caller,
        (backend, tool),
        scanned.as_ref().unwrap_or(params),
        (session_id, caller_name),
    )?;
    Some(backend_security_error_with_status(
        id,
        -32002,
        &message,
        StatusCode::FORBIDDEN,
    ))
}

/// `params` without `_meta.progressToken`; `None` when it carries none.
fn without_progress_token(params: &Value) -> Option<Value> {
    params.pointer("/_meta/progressToken")?;
    let mut copy = params.clone();
    copy.get_mut("_meta")?
        .as_object_mut()?
        .remove("progressToken");
    Some(copy)
}

/// The relay check on a catalogue read's forwarded params (`prompts/get`
/// arguments, a `resources/read` URI), as a `tools/call`'s are (MIK-7765).
/// `Some` is the refusal to answer with.
pub(super) fn catalogue_refusal(
    state: &AppState,
    auth: BackendAuthContext<'_>,
    id: &RequestId,
    (backend, method): (&str, &str),
    params: Option<&Value>,
) -> Option<BackendRejection> {
    let (fw, params) = (state.firewall.as_ref()?, params?);
    let caller_name = auth.client.map_or("anonymous", |c| c.name.as_str());
    let session_id = format!("direct:{backend}");
    relay_refusal(
        fw,
        auth,
        id,
        (backend, method),
        params,
        (&session_id, caller_name),
    )
}

/// Stage what the direct caller is delivered, after every gate, redaction and
/// the provenance stamp. The receipt is recorded only once the answer has
/// passed the read judge and the audit write ([`commit_direct_receipts`]).
#[cfg(feature = "firewall")]
pub(super) fn stage_direct_delivery(
    state: &AppState,
    auth: BackendAuthContext<'_>,
    (server, tool): (&str, &str),
    result: Option<&Value>,
    stamps: GatewayStamps,
) {
    let (Some(fw), Some(result)) = (state.firewall.as_ref(), result) else {
        return;
    };
    // No collector without relay detection: skip the copy (MIK-7832).
    if !fw.relay_active() {
        return;
    }
    let (key, keyed) = direct_caller(auth, &format!("direct:{server}"));
    let who = crate::gateway::meta_mcp::invoke::relay::RelayKey::new(&key, keyed);
    // The gateway's own stamps, its signature and its chain link are not
    // backend text (MIK-8022, MIK-7939, MIK-8025); `stage_with` leaves out
    // its value-layer notes (cost warnings, provenance).
    let mut staged = result.clone();
    crate::gateway::meta_mcp::invoke::relay::strip_gateway_stamps(&mut staged, stamps);
    crate::gateway::gateway_writes::strip_noted(&mut staged);
    crate::security::signature_chain::strip_chain(&mut staged);
    crate::gateway::meta_mcp::invoke::relay::stage_with(fw, who, (server, tool), &staged);
}

/// [`stage_direct_delivery`] for a catalogue result, which no response gate
/// classifies: the staged copy carries the context-integrity verdict of the
/// text, so content the gateway reads as sensitive needs no `sources` glob.
#[cfg(feature = "firewall")]
pub(super) fn stage_direct_catalogue(
    state: &AppState,
    auth: BackendAuthContext<'_>,
    (server, method): (&str, &str),
    result: Option<&Value>,
    stamps: GatewayStamps,
) {
    let Some(result) = result else {
        return;
    };
    // Classifying the text is the cost; with relay detection off nothing is
    // staged, so skip it (MIK-7832).
    if !state.firewall.as_ref().is_some_and(|fw| fw.relay_active()) {
        return;
    }
    // The gateway's stamps are left out before the text is classified, not
    // only before it is digested (MIK-8022).
    let mut result = result.clone();
    crate::gateway::meta_mcp::invoke::relay::strip_gateway_stamps(&mut result, stamps);
    let result = &result;
    let caller_name = auth.client.map(|c| c.name.as_str());
    let recorded =
        state
            .meta_mcp
            .recorded_prompt((server, method), caller_name, "catalogue", result);
    stage_direct_delivery(state, auth, (server, method), Some(&recorded), stamps);
}

/// Record the staged receipts when the answer that was written delivers a
/// result: a read the judge withheld, or a fail-closed audit write replaced,
/// leaves none.
#[cfg(feature = "firewall")]
pub(super) fn commit_direct_receipts(state: &AppState, delivered: bool) {
    if let Some(fw) = state.firewall.as_ref() {
        crate::gateway::meta_mcp::invoke::relay::commit_with(fw, delivered);
    }
}

#[cfg(test)]
#[path = "relay_tests.rs"]
mod tests;
