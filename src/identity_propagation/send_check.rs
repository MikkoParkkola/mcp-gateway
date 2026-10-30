// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The per-send check a non-managed credential carries (ADR-007 IDP.7): a
//! lent-only per-user slot runs it before every send of the credential.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::transport::{LentCredential, Refusal, SendCheck};

/// When a non-managed credential stops being sendable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Expiry {
    /// The strategy published this expiry (unix seconds): past it, the
    /// credential is refused definitively.
    At(i64),
    /// The expiry is a cache entry's default, not one the strategy
    /// published (an exchange that omitted `expires_in`): past it the send is
    /// refused for this loan only, because the issuer never said the token
    /// stops working then.
    AtSynthetic(i64),
    /// No expiry was published; the credential is valid for the dispatch
    /// that lent it.
    Unpublished,
}

/// The clock as unix seconds, for the expiry check; `None` when unreadable.
pub(crate) fn unix_now() -> Option<i64> {
    crate::clock::unix_secs()
        .ok()
        .and_then(|secs| i64::try_from(secs).ok())
}

/// A credential that is valid for the dispatch that carries it and no longer
/// (a caller's own forwarded bearer): checked only against its own JWT `exp`.
pub(crate) fn dispatch_scoped(headers: Vec<(String, String)>) -> LentCredential {
    LentCredential {
        check: Some(expiry_check(Expiry::Unpublished, &headers, unix_now)),
        headers: headers.into(),
    }
}

/// The `exp` claim of `token` if it is a JWT, read WITHOUT verifying its
/// signature. A token counts as a JWT only when it has three segments and
/// its header decodes to a JSON object naming an `alg`, so an opaque token
/// that happens to contain dots is not misread.
pub(crate) fn unverified_jwt_exp(token: &str) -> Option<i64> {
    let mut segments = token.split('.');
    let (header, claims) = (segments.next()?, segments.next()?);
    segments.next()?;
    if segments.next().is_some() {
        return None;
    }
    let decode = |segment: &str| {
        URL_SAFE_NO_PAD
            .decode(segment)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    };
    decode(header)?.as_object()?.get("alg")?.as_str()?;
    decode(claims)?.get("exp")?.as_i64()
}

/// The check for a non-managed credential with `expiry` and `headers`,
/// judged against `now` (unix seconds) at each send.
///
/// The `exp` of a JWT among the headers is read unverified, so it may only
/// TIGHTEN: one already past refuses this loan, and it is never read to keep
/// a credential past a published expiry. With no published expiry and no
/// readable `exp`, the credential is valid for the dispatch that lent it,
/// which holds because its loan ends with that dispatch. An unverified `exp`
/// never evicts the slot: only a published expiry is definitive.
pub(crate) fn expiry_check(
    expiry: Expiry,
    headers: &[(String, String)],
    now: fn() -> Option<i64>,
) -> SendCheck {
    let jwt_exp = headers
        .iter()
        .filter_map(|(_, value)| {
            // The auth scheme is case-insensitive (RFC 9110 11.1), and one or
            // more spaces may follow it.
            let token = value
                .as_str()
                .split_once(' ')
                .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
                .map_or(value.as_str(), |(_, rest)| rest.trim_start_matches(' '));
            unverified_jwt_exp(token)
        })
        .min();
    Arc::new(move || {
        Box::pin(async move {
            // A clock that cannot be read judges nothing about the credential.
            let now = now().ok_or(Refusal::Transient)?;
            if matches!(expiry, Expiry::At(at) if now >= at) {
                return Err(Refusal::Definitive);
            }
            if matches!(expiry, Expiry::AtSynthetic(at) if now >= at)
                || jwt_exp.is_some_and(|exp| now >= exp)
            {
                return Err(Refusal::ThisLoan);
            }
            Ok(())
        })
    })
}

#[cfg(test)]
#[path = "send_check_tests.rs"]
mod tests;
