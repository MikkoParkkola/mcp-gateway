// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The session a legacy `/mcp` POST runs under, opened before anything runs.

use serde_json::Value;

use super::{AppState, IntoResponse, SessionId};
use crate::gateway::router::hardened_elicitation;
use crate::gateway::router::helpers::session_capacity_refusal;
use crate::gateway::session_id::SessionOwner;
use crate::gateway::streaming::{MintKind, SessionCapacity, SessionHold};

/// Open or resume the request's session, held while the request runs. A
/// 2026-era request by header opens none. `initialize` mints an ordinary
/// session; any other request mints a provisional one, refused at the cap
/// (MIK-8504). `Err` is a finished answer: nothing was minted.
pub(super) fn open_request_session(
    state: &AppState,
    request: &Value,
    headers: &axum::http::HeaderMap,
    existing: Option<&str>,
    caller_owner: &SessionOwner,
    (declared_version, declares_modern_by_header): (Option<&str>, bool),
) -> Result<(Option<SessionId>, Option<SessionHold>), Box<axum::response::Response>> {
    if declares_modern_by_header {
        // No session, and none minted. Minting one per request grew a table of
        // sessions nothing could reach, and handed the sequence-anomaly
        // detector a fresh identity every call — a detector that sees a first
        // request every time keeps running and stops protecting.
        return Ok((None, None));
    }
    // The identity that owns the session. A caller with neither a subject
    // nor a credential is "anonymous", so a single-user gateway behaves
    // exactly as before.
    let held = crate::gateway::auth::live::held_credential(headers);
    let initialize = hardened_elicitation::is_initialize(request);
    if hardened_elicitation::is_hardened(state) && !initialize {
        // Hardened: only a declaring `initialize` opens a legacy session.
        return match state
            .multiplexer
            .resume_session_id_scoped(existing, caller_owner, held)
        {
            Some(id) => Ok((Some(id), None)),
            None => Err(Box::new(hardened_elicitation::refuse(
                request,
                declared_version,
            ))),
        };
    }
    if hardened_elicitation::is_hardened(state)
        && !hardened_elicitation::declares_elicitation(request)
    {
        // Hardened (row 10): refused before anything is minted.
        return Err(Box::new(hardened_elicitation::refusal().into_response()));
    }
    let kind = if initialize {
        MintKind::Ordinary
    } else {
        MintKind::Provisional
    };
    match state
        .multiplexer
        .open_request_session_scoped(existing, caller_owner, held, kind)
    {
        Ok((id, request_hold)) => Ok((Some(id), Some(request_hold))),
        Err(SessionCapacity) => Err(Box::new(session_capacity_refusal(
            crate::protocol::mrtr::raw_request_id(request),
        ))),
    }
}
