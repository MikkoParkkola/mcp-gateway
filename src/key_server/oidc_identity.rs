// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a `VerifiedIdentity` is made and keyed: the checked constructor every
//! production source goes through (MIK-8286) and the stable actor id.

use super::{OidcError, VerifiedIdentity};

/// A token this verifier has fully verified, kept as the exact string that
/// was verified together with the window that verification judged: the two
/// cannot be split or recomposed, and no other module can mint one.
#[derive(Clone)]
pub(crate) struct VerifiedAssertion {
    assertion: String,
    exp: u64,
    leeway: u64,
}

impl VerifiedAssertion {
    pub(super) fn verified(assertion: String, exp: u64, leeway: u64) -> Self {
        Self {
            assertion,
            exp,
            leeway,
        }
    }

    /// The verified string, for the re-verification that needs it.
    pub(crate) fn expose(&self) -> &str {
        &self.assertion
    }

    /// Whether the verified window is still live, judged exactly as
    /// verification judged it: `exp` with the same leeway, no `nbf`.
    pub(crate) fn live(&self) -> bool {
        crate::clock::jwt_window(
            crate::clock::JwtClaimTime::At(self.exp),
            crate::clock::JwtClaimTime::Absent,
            self.leeway,
        ) == crate::clock::Validity::Live
    }

    #[cfg(test)]
    pub(crate) fn for_test(assertion: &str) -> Self {
        Self {
            assertion: assertion.to_owned(),
            exp: u64::MAX,
            leeway: 0,
        }
    }
}

impl std::fmt::Debug for VerifiedAssertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedAssertion(<redacted>)")
    }
}

impl VerifiedIdentity {
    /// The only way production code builds a caller's verified identity
    /// (MIK-8286): `None` when the issuer or the subject is empty, since such
    /// an identity names nobody and its actor id would merge every such
    /// caller at the issuer.
    pub(crate) fn checked(
        issuer: String,
        subject: String,
        email: String,
        name: Option<String>,
        groups: Vec<String>,
    ) -> Option<Self> {
        crate::identity_grants::names_someone(&issuer, &subject).then_some(Self {
            subject,
            email,
            name,
            groups,
            issuer,
        })
    }

    /// Stable, collision-safe actor identifier derived from `issuer` + `subject`.
    ///
    /// A naive `format!("oidc:{issuer}:{subject}")` collides when an issuer
    /// contains `:` — e.g. issuer `https://idp/a` + subject `b:c` vs issuer
    /// `https://idp/a:b` + subject `c` both render `oidc:https://idp/a:b:c`
    /// (MIK-6702 CP.ID.1). Length-prefixing each component makes the boundary
    /// unambiguous, so distinct (issuer, subject) pairs always map to distinct
    /// ids. Not a role-escalation path (roles come from the verified identity,
    /// not the id), but it prevents audit / user-identity row collisions.
    #[must_use]
    pub fn stable_actor_id(&self) -> String {
        format!(
            "oidc:{}:{}:{}:{}",
            self.issuer.len(),
            self.issuer,
            self.subject.len(),
            self.subject
        )
    }
}

/// The refusal for a token whose identity names no one: an existing variant,
/// so the public error type is unchanged (MIK-8287).
pub(super) fn missing_subject() -> OidcError {
    OidcError::JwtError(jsonwebtoken::errors::Error::from(
        jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("sub".to_owned()),
    ))
}
