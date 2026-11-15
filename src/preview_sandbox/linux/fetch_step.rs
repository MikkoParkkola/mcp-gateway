// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The helper's npm fetch step (ADR-027 step 6): what the fetch command runs
//! with. Its environment is cleared and holds exactly these variables, so no
//! host proxy, `NODE_OPTIONS` or npm configuration reaches it.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the npm fetch step, a later commit, runs it")
)]

/// The npm fetch command's whole environment: the D5 list (proxy through the
/// relay with the fetch credential, no scripts, no git, the public registry)
/// plus the CA amendment's trust variables (the snapshot as `cafile`, strict
/// TLS, and an empty npmrc as both the user and the global config). `path` is
/// node's directory, then npm's.
pub(super) fn npm_env(credential: &str, port: u16, path: &str) -> Vec<(String, String)> {
    let _ = (credential, port, path);
    Vec::new()
}

#[cfg(test)]
#[path = "fetch_step_tests.rs"]
mod tests;
