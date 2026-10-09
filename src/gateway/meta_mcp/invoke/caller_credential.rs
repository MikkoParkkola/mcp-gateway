// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The per-dispatch identity-propagation credential, moved out of `invoke.rs`
//! unchanged (size ceiling). Its fields are `pub(super)`: visible to `invoke`
//! and its children, the same modules that could read them before the move.

/// The per-user identity-propagation credential resolved once for a single
/// dispatch (MIK-6704 / ADR-007). Carries the headers to put on the wire and
/// the cache binding to isolate cached results by user+audience. The default
/// (empty headers, `None` binding) means "not identity-scoped" — plain dispatch
/// and a shared cache key.
///
/// `Debug` is implemented manually to REDACT header values: `headers` may
/// carry a live bearer token/assertion resolved via identity propagation, and
/// a derived `Debug` would leak it through any `tracing!(?cred)`, error
/// context, or test-failure dump (CWE-532). Mirrors the sibling
/// [`crate::identity_propagation::PropagatedCredential`]'s redacting `Debug`
/// impl — header names are shown, values are replaced with `<redacted>`.
#[derive(Default)]
pub(super) struct CallerCredential {
    /// Per-request outbound headers (empty = none). Never logged verbatim —
    /// see the redacting `Debug` impl below.
    pub(super) headers: Vec<(String, String)>,
    /// Collision-safe user+audience cache binding. `Some` → mix into cache keys
    /// so per-user results stay isolated (IDP.8); `None` → shared key is safe.
    pub(super) cache_binding: Option<String>,
    /// A11-e′: the managed custody handle and the lease the headers were
    /// released under, kept to the post-dispatch 401 site. Only a vault mint
    /// produces one; every other strategy leaves it `None`.
    pub(super) managed: Option<crate::personal_accounts::ManagedLease>,
}

/// Headers, cache binding and, for a managed account, the lease they were
/// released under (A11-e′).
pub(crate) type HeldCredential = (
    Vec<(String, String)>,
    Option<String>,
    Option<crate::personal_accounts::ManagedLease>,
);

impl std::fmt::Debug for CallerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact header VALUES (they may carry a live token); show names only.
        let header_names: Vec<&str> = self.headers.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("CallerCredential")
            .field("headers", &format_args!("{header_names:?} = <redacted>"))
            .field("cache_binding", &self.cache_binding)
            .field("managed", &self.managed.is_some())
            .finish()
    }
}
