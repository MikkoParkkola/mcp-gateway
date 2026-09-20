// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Terminal states a dropped idempotency reservation stores once the backend
//! has been reached.
//!
//! One marker per epistemic state. Both settle the key — an effect that might
//! have run must not be run a second time — and they differ only in what the
//! retry is told, because the difference decides whether a caller reconciles.

use serde_json::{Value, json};

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
        "content": [{
            "type": "text",
            "text": "The call reached the backend and its outcome is unknown: \
                     it may have executed. Retrying with the same idempotency \
                     key will not re-execute it and will return this same \
                     notice. Reconcile at the backend before assuming the \
                     effect either ran or did not."
        }],
    })
}
