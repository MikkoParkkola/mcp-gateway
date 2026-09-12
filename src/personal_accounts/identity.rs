// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Account key construction from a verified principal and a configured descriptor.
//!
//! P2 TEST slice: refusing scaffold. The signature and refusal vocabulary are
//! the contract; nothing here constructs a key yet.
//!
//! WHAT MAY BECOME AN ACCOUNT KEY, and nothing else:
//!
//! * `principal_authority` <- `VerifiedIdentity::issuer` (`key_server::oidc`)
//! * `principal_subject`   <- `VerifiedIdentity::subject`
//! * `backend_id`          <- the `accounts.descriptors` MAP KEY (approved table
//!   row 422: "this ID is the logical `backend_id` in the account key"). NOT the
//!   backend registry id, and NOT `identity_propagation::BackendDescriptor::id`
//!   -- that type is the propagation descriptor, it carries `audience`/token
//!   -exchange fields and has no `resource` or `issuer` to take.
//! * `resource`, `oauth_issuer` <- the configured descriptor's explicit
//!   `resource` and `issuer` (row 425), immutable within a configuration revision.
//!
//! `email`, `name` and `groups` are display fields and are excluded: they are
//! mutable, and a mutable label inside the isolation boundary means one user's
//! rename silently re-points custody. No request body, query, header or state
//! possession contributes. A caller with no verified principal gets a refusal,
//! never an inferred identity.
//!
//! No new encoding: `AccountKey::digest` is already approved and is the only
//! hash. Nothing here re-implements length-prefixing.

use super::{AccountError, AccountKey};
use crate::key_server::oidc::VerifiedIdentity;

/// The configured account descriptor, addressed by its map key.
///
/// Deliberately NOT `identity_propagation::BackendDescriptor`: that type is the
/// propagation strategy's descriptor and has no resource or issuer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccountDescriptor {
    /// The `accounts.descriptors` map key. This is the account key's `backend_id`.
    pub(crate) descriptor_id: String,
    /// Logical OAuth provider id, e.g. `google`. Does not itself select a token.
    pub(crate) provider: String,
    /// Explicit absolute resource (approved table row 425).
    pub(crate) resource: String,
    /// Exact trusted downstream OAuth issuer. Distinct from the inbound `IdP`.
    pub(crate) issuer: String,
}

/// Typed refusals when a key cannot be constructed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum IdentityBindingError {
    #[error("account identity binding is not implemented")]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
        )
    )]
    RuntimeNotImplemented,
    /// No verified principal reached this call. Never downgraded to a guess.
    #[error("request carries no verified principal")]
    MissingVerifiedPrincipal,
    /// The caller named a descriptor that is not configured.
    #[error("account descriptor is not configured")]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
        )
    )]
    UnknownDescriptor,
    #[error(transparent)]
    Account(#[from] AccountError),
}

/// Bind a verified principal to a configured descriptor.
///
/// Five fields, five sources, nothing else. `email`, `name` and `groups` are
/// never read — not by omission but by construction: they are not mentioned
/// below, so no future edit can quietly admit one without appearing in a diff.
pub(crate) fn account_key(
    identity: Option<&VerifiedIdentity>,
    descriptor: &AccountDescriptor,
) -> Result<AccountKey, IdentityBindingError> {
    // No verified principal, no account. Nothing is inferred from the request,
    // and there is no anonymous or operator-token fallback for personal mode.
    let identity = identity.ok_or(IdentityBindingError::MissingVerifiedPrincipal)?;

    let key = AccountKey {
        principal_authority: identity.issuer.clone(),
        principal_subject: identity.subject.clone(),
        backend_id: descriptor.descriptor_id.clone(),
        resource: descriptor.resource.clone(),
        oauth_issuer: descriptor.issuer.clone(),
    };
    // The approved digest is the only hash, and it is also the validator: it
    // refuses an empty or oversized field. Calling it here means a key that
    // cannot be stored is refused at construction rather than at first use.
    key.digest()?;
    Ok(key)
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
