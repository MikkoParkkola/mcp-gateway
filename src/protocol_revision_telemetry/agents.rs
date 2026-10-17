// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Bounded caller keys for requests that named no protocol revision (U1 v2).
//!
//! The breakdown finds the callers behind the unattributed share; it gates
//! nothing. Raw User-Agent strings are never stored (MIK-6704: label only).

/// Named clients that identify a caller on their own.
pub(crate) const NAMED_CLIENTS: &[&str] = &["claude", "codex", "cursor", "vscode", "chatgpt"];
/// Fixed User-Agent families.
pub(crate) const USER_AGENT_FAMILIES: &[&str] = &[
    "python-urllib",
    "python-requests",
    "python-httpx",
    "curl",
    "xh",
    "httpie",
    "node",
    "go",
    "reqwest",
    "absent",
    "other",
];

/// Bounded key for a request that named no revision. A named client wins; an
/// unknown or missing `clientInfo` falls through to the agent family, so it
/// cannot hide a more specific caller.
pub(crate) fn missing_revision_agent(
    client: &'static str,
    user_agent: Option<&str>,
) -> &'static str {
    let _ = (client, user_agent);
    "other"
}

#[cfg(test)]
#[path = "agents_tests.rs"]
mod tests;
