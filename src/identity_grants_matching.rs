// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What matches what when a grant is evaluated.

use serde::{Deserialize, Serialize};

use super::{GrantAgent, GrantScope, GrantSubject};
use crate::capability::CapabilityDefinition;
use crate::security::{OwnedProvenAgentId, ProofSource};

/// The proven agent an exact grant names: `{source: mtls|jwt, id}`.
///
/// The source is part of the key because an mTLS subject and a JWT `sub` that
/// stringify the same are two principals. [`ProofSource`] has no `declared`
/// value, so a grant keyed to a self-declared label cannot be written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantAgentKey {
    /// The namespace `id` belongs to.
    pub source: ProofSource,
    /// The proven id: SAN URI or bare CN for mTLS, `sub` for JWT.
    pub id: String,
}

impl std::fmt::Display for GrantAgentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.source, self.id)
    }
}

impl GrantAgent {
    pub(super) fn matches(&self, agent: Option<&OwnedProvenAgentId>) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(key) => agent.is_some_and(|a| a.as_str() == key.id),
        }
    }
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

impl GrantScope {
    /// The scope a dispatch of `capability` requests: `Read` when its author
    /// declared it read-only, `Execute` otherwise. The declaration is the only
    /// read/write signal dispatch has, which is why there is no `Write`.
    pub(crate) fn requested_by(capability: &CapabilityDefinition) -> Self {
        if capability.metadata.read_only {
            Self::Read
        } else {
            Self::Execute
        }
    }

    pub(super) fn grants(&self, requested: &Self) -> bool {
        self == requested
            || matches!(
                (self, requested),
                (Self::Any, _) | (Self::Execute, Self::Read)
            )
    }
}
