// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Terminal states a dropped idempotency reservation stores once the backend
//! has been reached.
//!
//! One marker per epistemic state. Both settle the key — an effect that might
//! have run must not be run a second time — and they differ only in what the
//! retry is told, because the difference decides whether a caller reconciles.

use serde_json::{Value, json};

use crate::Error;
use crate::idempotency::IdempotencyReservation;

/// The terminal state a dropped reservation stores once the backend has acted.
///
/// Committed rather than completed: the call may still fail a post-dispatch
/// gate, and a retry of the same key must be told the side effect ran rather
/// than be readmitted to run it again or served a success the caller's own
/// request never produced.
pub(super) fn withheld_side_effect() -> Value {
    json!({
        "resultType": "complete",
        "isError": true,
        "content": [{
            "type": "text",
            "text": "Side effect executed; the response was withheld by a \
                     post-dispatch gate. Retrying with the same idempotency \
                     key will not re-execute it."
        }],
    })
}

/// What a same-key retry is told when the backend *may* have acted and nothing
/// can establish whether it did. One sentence for both routes, so a client
/// hears the same thing however it called (MIK-7979). "May have reached": a
/// lost round is classified conservatively, and where the send cannot be
/// proven either way the notice must not claim it happened.
pub(crate) const UNCERTAIN_TEXT: &str = "The call may have reached the backend; its \
     outcome is unknown: it may have executed. Retrying with the same idempotency key \
     will not re-execute it and will return this same notice. Reconcile at the backend \
     before assuming the effect either ran or did not.";

/// The terminal state a dropped reservation stores when the backend *may* have
/// acted and nothing can establish whether it did.
///
/// Distinct from [`withheld_side_effect`], which is written only where the
/// round demonstrably completed. A round lost after dispatch — the request left
/// the gateway, the answer never came back — leaves the effect genuinely
/// undetermined, and telling the caller it executed is a claim the gateway
/// cannot make. It reads as certainty, so a client that would otherwise
/// reconcile at the backend stops looking.
pub(super) fn uncertain_side_effect() -> Value {
    json!({
        "resultType": "complete",
        "isError": true,
        "content": [{ "type": "text", "text": UNCERTAIN_TEXT }],
    })
}

/// Whether a stored result is one of the notices above: the gateway's own
/// text, which a replay serving it receipts as no read (MIK-7991). A backend
/// answer equal to one carries nothing a relay could leak.
pub(super) fn is_gateway_notice(value: &Value) -> bool {
    *value == withheld_side_effect() || *value == uncertain_side_effect()
}

/// How a route stores a lost round under its key.
#[derive(Clone, Copy, Debug)]
pub(crate) enum LostRoundRoute {
    /// `gateway_invoke` replays a stored tool result.
    Meta,
    /// `POST /mcp/{backend}` replays a stored JSON-RPC error object; `code` is
    /// the one its first caller was answered with.
    Direct {
        /// The first caller's JSON-RPC error code.
        code: i32,
    },
}

/// MIK-7979: settle a lost round (the request may have left the gateway and no
/// answer came back) with the uncertainty notice, so a same-key retry is told
/// the outcome is undetermined instead of being served this error as if the
/// work had failed. The first caller's answer is not touched; the work still
/// never runs twice. Shared by both settle points so they cannot drift.
///
/// Returns whether it settled the key. A reservation another path already
/// settled is left alone, and logged, so a re-entry shows instead of
/// overwriting what that path stored.
pub(crate) fn settle_lost_round(
    error: &Error,
    reservation: Option<&mut IdempotencyReservation>,
    route: LostRoundRoute,
) -> bool {
    if !error.is_lost_round() {
        return false;
    }
    let Some(reservation) = reservation else {
        return false;
    };
    if reservation.is_settled() {
        tracing::debug!(
            key = reservation.key(),
            "lost round found its idempotency reservation already settled"
        );
        return false;
    }
    match route {
        LostRoundRoute::Meta => {
            reservation.complete(&uncertain_side_effect());
        }
        LostRoundRoute::Direct { code } => {
            reservation.fail(&json!({ "code": code, "message": UNCERTAIN_TEXT }));
        }
    }
    true
}
