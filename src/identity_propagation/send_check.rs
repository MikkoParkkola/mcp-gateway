// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The per-send check a non-managed credential carries (ADR-007 IDP.7): a
//! lent-only per-user slot runs it before every send of the credential.

use std::sync::Arc;

use crate::transport::{Refusal, SendCheck};

/// When a non-managed credential stops being sendable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Expiry {
    /// The strategy published this expiry (unix seconds): past it, the
    /// credential is refused definitively.
    At(i64),
    /// No expiry was published; the credential is valid for the dispatch
    /// that lent it.
    Unpublished,
}

/// The `exp` claim of `token` if it is a JWT, read WITHOUT verifying its
/// signature. Never trusted to extend a lifetime, only to shorten one.
pub(crate) fn unverified_jwt_exp(_token: &str) -> Option<i64> {
    None
}

/// The check for a non-managed credential with `expiry` and `headers`,
/// judged against `now` (unix seconds) at each send.
pub(crate) fn expiry_check(
    expiry: Expiry,
    headers: &[(String, String)],
    now: fn() -> Option<i64>,
) -> SendCheck {
    let _ = (expiry, headers, now);
    Arc::new(|| Box::pin(async { Ok::<(), Refusal>(()) }))
}

#[cfg(test)]
#[path = "send_check_tests.rs"]
mod tests;
