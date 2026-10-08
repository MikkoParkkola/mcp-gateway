// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rewrite a backend's `http_url` or `ws_url` as `url` in gateway.yaml text.
//!
//! The rewrite works on the text, line by line, so every comment and every
//! other line stays as it was. It renames a key only where it is a direct
//! field of an entry under `backends:` and that entry has no `url` already.
//! A backend written in flow style (`name: { ... }`) is reported, not edited.

use std::collections::BTreeSet;

/// The result of a rewrite: the new text, the 1-based numbers of the lines
/// it changed, and the backends it could not edit.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct UrlRewrite {
    pub text: String,
    pub changed: Vec<usize>,
    pub skipped: Vec<String>,
}

/// Rewrite the aliases of every backend, or only of the backends in `only`.
pub(crate) fn rewrite_url_aliases(text: &str, only: Option<&BTreeSet<String>>) -> UrlRewrite {
    // Red-proof stub: changes nothing.
    let _ = only;
    UrlRewrite {
        text: text.to_string(),
        ..UrlRewrite::default()
    }
}

#[cfg(test)]
#[path = "backend_url_keys_tests.rs"]
mod tests;
