// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which upstream listener a subscription is served by, and how many per-user
//! listeners a backend runs (MIK-8833 §2.2, A5).

/// Which listener: a backend, and on a per-user backend the observation it
/// listens as (MIK-8833 §2.2). One task per key, so two subscribers on one
/// per-user backend never share a session, snapshot, ledger or debt.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct ListenerKey {
    pub backend: String,
    pub obs: Option<String>,
}

impl ListenerKey {
    /// The one listener of a backend whose credential is shared.
    #[cfg(test)]
    pub(crate) fn shared(backend: &str) -> Self {
        Self {
            backend: backend.to_owned(),
            obs: None,
        }
    }
}

// Not derived: `obs` is an identity digest (MIK-8697 class).
impl std::fmt::Debug for ListenerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListenerKey")
            .field("backend", &self.backend)
            .field("per_user", &self.obs.is_some())
            .finish()
    }
}

/// The most per-user listeners one backend runs: the identity-slot budget
/// with one principal's share left for calls (MIK-8833 A5). Each is a task
/// and an open stream of its own.
pub(crate) const MAX_PER_USER_LISTENERS: usize =
    crate::backend::MAX_IDENTITY_SLOTS - crate::backend::MAX_SLOTS_PER_PRINCIPAL;
