// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `Debug` for [`BridgeError`], by hand.
//!
//! `RoundsExhausted` carries the backend's last interim result whole, and that
//! holds the backend's raw `requestState`: opaque, possibly an authorization,
//! and never shown to the caller (MRTR.2). A derived `Debug` would print it
//! into any log or panic that formats the error, so the body is shown only by
//! its presence, as the continuation `Payload` shows its state.

use super::BridgeError;

impl std::fmt::Debug for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused { key, reason } => f
                .debug_struct("Refused")
                .field("key", key)
                .field("reason", reason)
                .finish(),
            Self::Delivery { key, error } => f
                .debug_struct("Delivery")
                .field("key", key)
                .field("error", error)
                .finish(),
            Self::RoundsExhausted { last } => f
                .debug_struct("RoundsExhausted")
                .field("last", &last.as_ref().map(|_| "<redacted>"))
                .finish(),
            Self::Undeclared {
                key,
                method,
                reason,
            } => f
                .debug_struct("Undeclared")
                .field("key", key)
                .field("method", method)
                .field("reason", reason)
                .finish(),
            Self::MalformedInterim => f.write_str("MalformedInterim"),
            Self::RequestBudgetExhausted => f.write_str("RequestBudgetExhausted"),
            Self::Deadline => f.write_str("Deadline"),
            Self::NotAdmitted { message } => f
                .debug_struct("NotAdmitted")
                .field("message", message)
                .finish(),
            Self::ChallengeRefused { dispatched } => f
                .debug_struct("ChallengeRefused")
                .field("dispatched", dispatched)
                .finish(),
            Self::BackendFailed { message, dispatch } => f
                .debug_struct("BackendFailed")
                .field("message", message)
                .field("dispatch", dispatch)
                .finish(),
        }
    }
}
