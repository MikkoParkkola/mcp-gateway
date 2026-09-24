// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What matches what when a grant is evaluated.

use super::{GrantScope, GrantSubject};
use crate::capability::CapabilityDefinition;

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
