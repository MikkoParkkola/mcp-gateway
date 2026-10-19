// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The session a legacy `/mcp` POST runs under, opened before anything runs.

use serde_json::Value;

use super::{AppState, IntoResponse, SessionId};
use crate::gateway::session_id::SessionOwner;

/// Open or resume the request's session. `None` for a request of the 2026
/// era by header, which opens none. `Err` is a finished answer.
pub(super) fn open_request_session(
    state: &AppState,
    request: &Value,
    headers: &axum::http::HeaderMap,
    existing: Option<&str>,
    caller_owner: &SessionOwner,
    (declared_version, declares_modern_by_header): (Option<&str>, bool),
) -> Result<Option<SessionId>, Box<axum::response::Response>> {
    let opened = if declares_modern_by_header {
        // No session, and none minted. Minting one per request grew a table of
        // sessions nothing could reach, and handed the sequence-anomaly
        // detector a fresh identity every call — a detector that sees a first
        // request every time keeps running and stops protecting.
        None
    } else {
        // The identity that owns the session. A caller with neither a subject
        // nor a credential is "anonymous", so a single-user gateway behaves
        // exactly as before.
        let held = crate::gateway::auth::live::held_credential(headers);
        Some(
            if !crate::gateway::router::hardened_elicitation::is_hardened(state) {
                state
                    .multiplexer
                    .get_or_create_session_id_scoped(existing, caller_owner, held)
            } else if crate::gateway::router::hardened_elicitation::is_initialize(request) {
                // Hardened (row 10): refused before anything is minted.
                if !crate::gateway::router::hardened_elicitation::declares_elicitation(request) {
                    return Err(Box::new(
                        crate::gateway::router::hardened_elicitation::refusal().into_response(),
                    ));
                }
                state
                    .multiplexer
                    .get_or_create_session_id_scoped(existing, caller_owner, held)
            } else {
                // Hardened: only a declaring `initialize` opens a legacy session.
                match state
                    .multiplexer
                    .resume_session_id_scoped(existing, caller_owner, held)
                {
                    Some(id) => id,
                    None => {
                        return Err(Box::new(
                            crate::gateway::router::hardened_elicitation::refuse(
                                request,
                                declared_version,
                            ),
                        ));
                    }
                }
            },
        )
    };
    Ok(opened)
}
