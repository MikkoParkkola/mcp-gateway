// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Account key construction from a verified principal and a configured descriptor.
//!
//! P2 TEST slice: refusing scaffold. The signature and refusal vocabulary are
//! the contract; nothing here constructs a key yet.
//!
//! WHAT MAY BECOME AN ACCOUNT KEY, and nothing else:
//!
//! * `principal_authority` <- [`Principal::parts`], which is either a
//!   `VerifiedIdentity::issuer` (`key_server::oidc`) or the sole-operator
//!   authority a single-user deployment asserts
//! * `principal_subject`   <- [`Principal::parts`], likewise
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
//! possession contributes. A caller with no principal gets a refusal, never an
//! inferred identity.
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
    #[expect(
        dead_code,
        reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
    )]
    RuntimeNotImplemented,
    /// No verified principal reached this call. Never downgraded to a guess.
    #[error("request carries no verified principal")]
    MissingVerifiedPrincipal,
    /// The caller named a descriptor that is not configured.
    #[error("account descriptor is not configured")]
    #[expect(
        dead_code,
        reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
    )]
    UnknownDescriptor,
    #[error(transparent)]
    Account(#[from] AccountError),
}

/// The authority a sole-operator deployment's accounts are recorded under.
///
/// Namespaced rather than a bare word, for the reason
/// `openwebui_adapter::namespaced_issuer` is: an authority plus a subject IS a
/// principal, so a value that could pass for another producer's would let one
/// producer's accounts be addressed as another's. An OIDC issuer is a URL and
/// this is not one — but that is a consequence of the configuration, not a rule
/// the code enforces (nothing validates `principal_authority`, design doc §3).
/// What makes the two namespaces disjoint is
/// [`AuthConfig::grants_single_user_principal`](crate::config::features::auth::AuthConfig::grants_single_user_principal),
/// which is false whenever any OIDC issuer is configured, so no deployment ever
/// holds both.
///
/// NOT `"local"`, which the design doc's tier table originally proposed. That
/// string is already four unrelated things in this tree — `cli::mod` maps a
/// `Local` variant to it and uses it as a `default_value`, `gateway::ui`
/// emits it, and `identity_grants_tests` builds `GrantSubject::new("local", …)`
/// — so a bare word here would collide with values that have nothing to do with
/// account custody. Every other `principal_authority` in the tree is either
/// URL-shaped or namespaced; a short literal would be the only one of its kind.
/// Do not shorten it.
const SOLE_OPERATOR_AUTHORITY: &str = "mcp-gateway-single-user";

/// The one subject a sole-operator deployment has. Fixed: a deployment that
/// asserted it serves one human has nothing to distinguish a second one by.
const SOLE_OPERATOR_SUBJECT: &str = "sole-operator";

/// Who an account belongs to, and what stands behind the claim.
///
/// THE TWO ARMS ARE NOT EQUIVALENT, and the type exists to keep that visible at
/// every call site rather than collapsing both into a synthesised
/// `VerifiedIdentity` nothing downstream could tell apart.
///
/// * [`Self::Verified`] is a PROOF: an identity provider validated a token and
///   the issuer and subject are its answer.
/// * [`Self::SoleOperator`] is an ASSERTION: the operator configured
///   `auth.single_user` on an authenticated gateway with no second credential
///   and no `IdP`, and the gateway takes their word for it. If two humans share
///   that machine's credential they share the stored OAuth grants, because the
///   gateway cannot tell them apart. That is already true of `single_user` for
///   request authorisation; this extends its reach to stored OAuth grants,
///   which is a larger blast radius, and it is not a proof of anything.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Principal<'a> {
    /// An identity provider verified this caller.
    Verified(&'a VerifiedIdentity),
    /// The deployment asserted that exactly one human reaches it.
    SoleOperator,
}

/// Two principals are the same iff they name the same authority and subject.
///
/// Through [`Principal::parts`], not derived: a derive would compare a
/// `VerifiedIdentity` whole, which means `email`, `name` and `groups` would
/// decide whether two requests are the same principal. Those are mutable
/// display labels, and the whole point of the five-field account key is that
/// they never reach the isolation boundary.
impl PartialEq for Principal<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.parts() == other.parts()
    }
}

impl Eq for Principal<'_> {}

impl<'a> Principal<'a> {
    /// The authority and subject, and NOTHING else.
    ///
    /// The ONE place an arm's fields are read. [`account_key`] and
    /// [`Self::stable_actor_id`] both come through here, so the two can never
    /// disagree about who a principal is, and a future arm has exactly one site
    /// to add itself to.
    fn parts(self) -> (&'a str, &'a str) {
        match self {
            Self::Verified(identity) => (&identity.issuer, &identity.subject),
            Self::SoleOperator => (SOLE_OPERATOR_AUTHORITY, SOLE_OPERATOR_SUBJECT),
        }
    }

    /// The verified identity behind this principal, when one proved it.
    ///
    /// For a consumer that genuinely needs the PROOF rather than the principal
    /// — an external propagation strategy exchanges the caller's own token, so
    /// an assertion is not something it can mint from. Returning `None` lets
    /// such a consumer refuse, instead of having the assertion silently widened
    /// into a proof on its behalf.
    pub(crate) fn verified(self) -> Option<&'a VerifiedIdentity> {
        match self {
            Self::Verified(identity) => Some(identity),
            Self::SoleOperator => None,
        }
    }

    /// Stable actor id for the audit trail.
    ///
    /// Length-prefixed for the collision reason `VerifiedIdentity::stable_actor_id`
    /// documents, and tagged with the arm so a reader of the log can see which
    /// tier of proof released a credential. A sole-operator mint is audited AS
    /// the sole operator: logging it as `"unauthenticated"` would record a
    /// credential release against nobody.
    pub(crate) fn stable_actor_id(self) -> String {
        match self {
            Self::Verified(identity) => identity.stable_actor_id(),
            Self::SoleOperator => {
                let (authority, subject) = self.parts();
                format!(
                    "single-user:{}:{authority}:{}:{subject}",
                    authority.len(),
                    subject.len()
                )
            }
        }
    }
}

/// Bind a principal to a configured descriptor.
///
/// Five fields, five sources, nothing else. `email`, `name` and `groups` are
/// never read — not by omission but by construction: they are not mentioned
/// below, and the only place a `VerifiedIdentity` field is read at all is
/// [`Principal::parts`], whose two-string return type cannot carry a third
/// field without appearing in a diff.
pub(crate) fn account_key(
    principal: Option<Principal<'_>>,
    descriptor: &AccountDescriptor,
) -> Result<AccountKey, IdentityBindingError> {
    // No principal, no account. Nothing is inferred from the request, and there
    // is no anonymous or operator-token fallback for personal mode. The
    // sole-operator arm is NOT such a fallback: it is reached only when the
    // deployment's own configuration already asserted it, decided once at
    // startup and never per request.
    let principal = principal.ok_or(IdentityBindingError::MissingVerifiedPrincipal)?;
    let (authority, subject) = principal.parts();

    let key = AccountKey {
        principal_authority: authority.to_string(),
        principal_subject: subject.to_string(),
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
