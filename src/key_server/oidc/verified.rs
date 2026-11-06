// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The verified identity a valid OIDC token yields, and everything that
//! touches its fields: the checked constructor every production source goes
//! through, the stable actor id, and the read-only accessors.
//! Re-exported as `crate::key_server::oidc::VerifiedIdentity`.

use serde::Serialize;

/// Verified identity extracted from a valid OIDC ID token.
///
/// Output only: it is written to audit records, but nothing can read one back
/// from bytes, since bytes are not a verification:
///
/// ```compile_fail,E0277
/// fn read(bytes: &str) -> mcp_gateway::key_server::oidc::VerifiedIdentity {
///     serde_json::from_str(bytes).expect("an identity")
/// }
/// ```
///
/// Writing one out compiles:
///
/// ```
/// fn write(identity: &mcp_gateway::key_server::oidc::VerifiedIdentity) -> String {
///     serde_json::to_string(identity).expect("an identity")
/// }
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedIdentity {
    /// OIDC `sub` claim (opaque user ID).
    pub subject: String,
    /// Email address from the token claims.
    pub email: String,
    /// Display name (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Group memberships (from custom claims).
    #[serde(default)]
    pub groups: Vec<String>,
    /// Issuer URL.
    pub issuer: String,
}

impl VerifiedIdentity {
    /// The only way production code builds a caller's verified identity:
    /// `None` when the issuer or the subject is empty, since such
    /// an identity names nobody and its actor id would merge every such
    /// caller at the issuer. It checks only that the identity names someone
    /// (a non-empty, non-blank issuer and subject): verifying the token the
    /// values came from is the caller's job.
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
    /// `https://idp/a:b` + subject `c` both render `oidc:https://idp/a:b:c`.
    /// Length-prefixing each component makes the boundary
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

    /// The OIDC `sub` claim (opaque user id).
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The email address from the token claims.
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }

    /// The display name, when the token carried one.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Group memberships, from custom claims.
    #[must_use]
    pub fn groups(&self) -> &[String] {
        &self.groups
    }

    /// The issuer URL.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

#[cfg(test)]
#[path = "verified_tests.rs"]
mod tests;
