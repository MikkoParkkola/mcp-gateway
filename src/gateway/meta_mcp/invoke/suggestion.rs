// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The "did you mean?" pool an invocation failure answers with.
//!
//! A `tools/call` that misses gets Levenshtein hints drawn from the target
//! backend's cached tool list. The pool used to be that list raw, so a caller
//! could submit near-miss spellings against a named server and read its
//! catalogue back out of the error bodies — including tools the caller's
//! routing profile forbids (MIK-7518). That is an enumeration oracle, not an
//! incidental leak: a miss became more informative than a hit.
//!
//! Suggestions are a discovery surface, so they answer to the gates discovery
//! answers to — the `backend_allowed` + `tool_allowed` pair `search::list_tools`
//! and `spec_preview::collect_all_cached_tool_names` (MIK-7517) apply. The two
//! are not interchangeable: one decides whether the caller may see this server
//! at all, the other whether it may see this name.

use super::MetaMcp;
use crate::backend::Backend;
use crate::gateway::meta_mcp_helpers::did_you_mean;

impl MetaMcp {
    /// The names of `backend`'s cached tools that `session_id`'s profile admits.
    ///
    /// Empty when the profile denies the backend outright, so a forbidden
    /// server contributes no hint rather than a filtered one.
    pub(super) fn suggestible_tool_names(
        &self,
        backend: &Backend,
        session_id: Option<&str>,
    ) -> Vec<String> {
        let profile = self.active_profile(session_id);
        if !profile.backend_allowed(&backend.name) {
            return Vec::new();
        }
        backend
            .get_cached_tool_names()
            .into_iter()
            .filter(|name| profile.tool_allowed(name))
            .collect()
    }
}

/// The message a failed invocation of `tool` on `server` answers with.
///
/// `cached_names` is the already-authorized pool from
/// [`MetaMcp::suggestible_tool_names`]; this function adds no filtering of its
/// own, so the one place the profile is applied stays the one place above.
pub(super) fn invocation_miss_message(
    server: &str,
    tool: &str,
    cached_names: &[String],
    tool_is_cached: bool,
    backend_message: String,
) -> String {
    if cached_names.is_empty() || tool_is_cached {
        return backend_message;
    }
    let candidates: Vec<&str> = cached_names.iter().map(String::as_str).collect();
    match did_you_mean(tool, &candidates, 3, 3) {
        Some(hint) => format!("Tool '{tool}' not found on server '{server}'. {hint}"),
        None => format!("Tool '{tool}' not found on server '{server}'. {backend_message}"),
    }
}

#[cfg(test)]
#[path = "suggestion_authz_tests.rs"]
mod suggestion_authz_tests;
