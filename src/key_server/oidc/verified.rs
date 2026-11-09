// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The verified identity a valid OIDC token yields, and everything that
//! touches its fields: the checked constructor every production source goes
//! through, the stable actor id, and the read-only accessors.
//! Re-exported as `crate::key_server::oidc::VerifiedIdentity`.

/// Verified identity extracted from a valid OIDC ID token.
///
/// Nothing can read one back from bytes, since bytes are not a verification,
/// and nothing writes one out: audit records carry its keyed hash form
/// instead (`SafeIdentity`), never the raw identity:
///
/// ```compile_fail,E0277
/// fn read(bytes: &str) -> mcp_gateway::key_server::oidc::VerifiedIdentity {
///     serde_json::from_str(bytes).expect("an identity")
/// }
/// ```
///
/// nor write one out:
///
/// ```compile_fail,E0277
/// fn write(identity: &mcp_gateway::key_server::oidc::VerifiedIdentity) -> String {
///     serde_json::to_string(identity).expect("an identity")
/// }
/// ```
///
/// Reading it through its accessors compiles:
///
/// ```
/// fn subject(identity: &mcp_gateway::key_server::oidc::VerifiedIdentity) -> &str {
///     identity.subject()
/// }
/// ```
///
/// Nor can code outside this module build one without the checked
/// constructor, by a struct literal:
///
/// ```compile_fail,E0451
/// fn mint() -> mcp_gateway::key_server::oidc::VerifiedIdentity {
///     mcp_gateway::key_server::oidc::VerifiedIdentity {
///         subject: String::new(),
///         email: String::new(),
///         name: None,
///         groups: Vec::new(),
///         issuer: String::new(),
///     }
/// }
/// ```
///
/// or by copying another identity with one field changed:
///
/// ```compile_fail,E0451
/// use mcp_gateway::key_server::oidc::VerifiedIdentity;
///
/// fn relabel(other: VerifiedIdentity) -> VerifiedIdentity {
///     VerifiedIdentity {
///         subject: String::new(),
///         ..other
///     }
/// }
/// ```
///
/// Its fields are read through the accessors only:
///
/// ```compile_fail,E0616
/// fn subject(identity: &mcp_gateway::key_server::oidc::VerifiedIdentity) -> &str {
///     &identity.subject
/// }
/// ```
///
/// and never changed after it was built:
///
/// ```compile_fail,E0616
/// fn rename(identity: &mut mcp_gateway::key_server::oidc::VerifiedIdentity) {
///     identity.subject = String::new();
/// }
/// ```
#[derive(Clone)]
pub struct VerifiedIdentity {
    /// OIDC `sub` claim (opaque user ID).
    subject: String,
    /// Email address from the token claims.
    email: String,
    /// Display name (optional).
    name: Option<String>,
    /// Group memberships (from custom claims).
    groups: Vec<String>,
    /// Issuer URL.
    issuer: String,
}

/// Names the email, name and groups only by presence, as `IdTokenClaims`
/// does: a stray `?identity` cannot log them.
impl std::fmt::Debug for VerifiedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let shown = |present: bool| if present { "<present>" } else { "<absent>" };
        f.debug_struct("VerifiedIdentity")
            .field("subject", &self.subject)
            .field("email", &shown(!self.email.is_empty()))
            .field("name", &shown(self.name.is_some()))
            .field("groups", &shown(!self.groups.is_empty()))
            .field("issuer", &self.issuer)
            .finish()
    }
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

    /// The actor id an identity with this `issuer` and `subject` would have,
    /// without building one: `None` when the pair names no one.
    pub(crate) fn stable_actor_id_for(issuer: &str, subject: &str) -> Option<String> {
        crate::identity_grants::names_someone(issuer, subject).then(|| actor_id(issuer, subject))
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
        actor_id(&self.issuer, &self.subject)
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

/// Test construction, which bypasses [`VerifiedIdentity::checked`] so a row
/// can hold an identity that names nobody. Compiled only into the crate's own
/// tests and visible only inside the crate: no build and no other crate can
/// make an identity this way.
#[cfg(test)]
impl VerifiedIdentity {
    /// An identity from its five parts, in field order.
    pub(crate) fn for_test(
        subject: impl Into<String>,
        email: impl Into<String>,
        name: Option<String>,
        groups: Vec<String>,
        issuer: impl Into<String>,
    ) -> Self {
        Self {
            subject: subject.into(),
            email: email.into(),
            name,
            groups,
            issuer: issuer.into(),
        }
    }

    /// This identity with another subject.
    #[must_use]
    pub(crate) fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }

    /// This identity with another email.
    #[must_use]
    pub(crate) fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = email.into();
        self
    }

    /// This identity with another issuer.
    #[must_use]
    pub(crate) fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// This identity with another display name.
    #[must_use]
    pub(crate) fn with_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    /// This identity with other groups.
    #[must_use]
    pub(crate) fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.groups = groups;
        self
    }
}

/// The one formula behind both actor-id functions, so they cannot drift.
fn actor_id(issuer: &str, subject: &str) -> String {
    format!("oidc:{}:{issuer}:{}:{subject}", issuer.len(), subject.len())
}

#[cfg(test)]
#[path = "verified_tests.rs"]
mod tests;
