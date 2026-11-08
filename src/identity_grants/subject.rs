// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who a grant names. A leaf module, so its private fields are private to
//! this file alone: every subject is built through [`GrantSubject::new`] or
//! read through its checked deserializer.

use serde::{Deserialize, Serialize};

/// Which part of an identity names no one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EmptyIdentity {
    /// The authority is empty.
    #[error("the identity's authority is empty")]
    Authority,
    /// The subject is empty.
    #[error("the identity's subject is empty")]
    Subject,
}

/// Stable subject identity used by grant evaluation.
///
/// Equality is `(authority, subject)` only; see its `PartialEq` impl.
/// Read from bytes only through [`RawGrantSubject`], so a subject that names
/// no one is refused wherever it is deserialized, whatever holds it.
///
/// Built only through the checked constructor and read through its accessors:
///
/// ```
/// use mcp_gateway::identity_grants::GrantSubject;
///
/// let subject = GrantSubject::new("https://idp.test", "alice", None).expect("names someone");
/// assert_eq!(subject.authority(), "https://idp.test");
/// assert_eq!(subject.subject(), "alice");
/// assert!(GrantSubject::new("https://idp.test", " ", None).is_err());
/// ```
///
/// Code outside this module cannot build one by a struct literal:
///
/// ```compile_fail,E0451
/// use mcp_gateway::identity_grants::GrantSubject;
///
/// fn mint() -> GrantSubject {
///     GrantSubject {
///         authority: String::new(),
///         subject: String::new(),
///         label: None,
///     }
/// }
/// ```
///
/// or by copying another with one field changed:
///
/// ```compile_fail,E0451
/// use mcp_gateway::identity_grants::GrantSubject;
///
/// fn relabel(other: GrantSubject) -> GrantSubject {
///     GrantSubject {
///         subject: String::new(),
///         ..other
///     }
/// }
/// ```
///
/// and cannot change one after it was built:
///
/// ```compile_fail,E0616
/// use mcp_gateway::identity_grants::GrantSubject;
///
/// fn rename(identity: &mut GrantSubject) {
///     identity.subject = String::new();
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "RawGrantSubject")]
pub struct GrantSubject {
    /// Identity authority, such as an issuer URL or local authority name.
    authority: String,
    /// Stable subject identifier inside the authority namespace.
    subject: String,
    /// Optional operator-facing label. Display only: never part of identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

/// A grant subject as written, before its check.
#[derive(Deserialize)]
pub(super) struct RawGrantSubject {
    authority: String,
    subject: String,
    label: Option<String>,
}

impl TryFrom<RawGrantSubject> for GrantSubject {
    type Error = EmptyIdentity;

    fn try_from(raw: RawGrantSubject) -> Result<Self, Self::Error> {
        Self::new(raw.authority, raw.subject, raw.label)
    }
}

impl GrantSubject {
    /// The identity authority, such as an issuer URL or local authority name.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The stable subject identifier inside the authority namespace.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The operator-facing label. Display only: never part of identity.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// The one way to build a grant subject, a caller's or a grant rule's:
    /// refused when the authority or the subject is empty, since such a
    /// subject names nobody and every key built from it would merge all such
    /// callers, and a rule naming it grants nothing. The error names the part
    /// that is empty.
    ///
    /// # Errors
    ///
    /// [`EmptyIdentity`] when the authority or the subject is empty.
    pub fn new(
        authority: impl Into<String>,
        subject: impl Into<String>,
        label: Option<String>,
    ) -> Result<Self, EmptyIdentity> {
        let (authority, subject) = (authority.into(), subject.into());
        // The one predicate every identity source applies.
        if !names_someone(&authority, &subject) {
            return Err(if authority.trim().is_empty() {
                EmptyIdentity::Authority
            } else {
                EmptyIdentity::Subject
            });
        }
        Ok(Self {
            authority,
            subject,
            label,
        })
    }
}

#[cfg(test)]
impl GrantSubject {
    /// A test's fixed subject; panics on an empty authority or subject.
    pub(crate) fn for_test(
        authority: impl Into<String>,
        subject: impl Into<String>,
        label: Option<String>,
    ) -> Self {
        Self::new(authority, subject, label).expect("a test subject names someone")
    }
}

/// Whether an (authority, subject) pair names someone: neither is empty or
/// only whitespace. The one predicate every caller-identity source applies.
/// Only this test looks past whitespace: a value that names someone is kept
/// and compared exactly as written, so `" admin "` stays a different
/// principal from `admin`. It does not judge names: a subject literally
/// spelled like a placeholder still names someone, so the certificate
/// refusal is its own check (`CertIdentity::subject_id`).
pub(crate) fn names_someone(authority: &str, subject: &str) -> bool {
    !authority.trim().is_empty() && !subject.trim().is_empty()
}

// Identity is `(authority, subject)`. The label is whatever each side had to
// hand — an API key's name at runtime, a person's name in a grant file — so
// comparing it made correctly written grants deny. Every owner and grant
// comparison routes through this impl, which is why it lives on the type.
impl PartialEq for GrantSubject {
    fn eq(&self, other: &Self) -> bool {
        self.authority == other.authority && self.subject == other.subject
    }
}

impl Eq for GrantSubject {}

// Must hash exactly what `eq` compares, or a set or map keyed by subject
// would hold one identity twice.
impl std::hash::Hash for GrantSubject {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.authority.hash(state);
        self.subject.hash(state);
    }
}
