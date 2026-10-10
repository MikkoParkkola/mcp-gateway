// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a `VerifiedIdentity` is made and keyed: the checked constructor every
//! production source goes through (MIK-8286) and the stable actor id.

use super::VerifiedIdentity;

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
