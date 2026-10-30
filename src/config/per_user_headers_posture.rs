// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which static headers a required identity binding's per-user sessions do
//! not send (ADR-007 IDP.7).
//!
//! A per-user session of a backend whose identity binding is required sends
//! only the calling user's own credential: never the backend's static headers
//! and never a gateway token. A config that sets static headers on such a
//! backend still loads (it worked before this rule), and startup names, per
//! backend, every header those sessions now leave off. Names only: a header's
//! value is the operator's secret and is never logged.

use super::Config;

impl Config {
    /// One warning per enabled backend whose identity binding is required
    /// and that sets static headers, naming the backend and each such header,
    /// sorted. Empty when there is none.
    ///
    /// The binding read is the one the backend runs with: a backend bound to
    /// a managed account runs with the binding that account compiles to. A
    /// config whose account bindings do not compile is refused before any
    /// backend starts, so it has no per-user sends to warn about.
    #[must_use]
    pub fn per_user_dropped_header_warnings(&self) -> Vec<String> {
        let bound = super::account_bindings::compile(self).unwrap_or_default();
        let required = |name: &str, backend: &super::BackendConfig| {
            bound
                .get(name)
                .and_then(|account| account.propagation.as_ref())
                .or(backend.identity_propagation.as_ref())
                .is_some_and(|binding| binding.required)
        };
        let mut warnings: Vec<(&str, String)> = self
            .backends
            .iter()
            .filter(|(name, backend)| {
                backend.enabled && !backend.headers.is_empty() && required(name.as_str(), backend)
            })
            .map(|(name, backend)| {
                let mut headers: Vec<&str> = backend.headers.keys().map(String::as_str).collect();
                headers.sort_unstable();
                (
                    name.as_str(),
                    format!(
                        "backend '{name}' has a required identity binding, so its per-user \
                         sessions send only each user's own credential and leave off its \
                         static headers: {}. A shared session to it, where one exists, still \
                         sends them.",
                        headers.join(", ")
                    ),
                )
            })
            .collect();
        warnings.sort_unstable_by(|a, b| a.0.cmp(b.0));
        warnings.into_iter().map(|(_, warning)| warning).collect()
    }
}

#[cfg(test)]
#[path = "per_user_headers_posture_tests.rs"]
mod tests;
