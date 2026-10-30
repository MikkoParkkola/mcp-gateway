// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The server-to-client notifications MCP defines, and what a backend's copy
//! of each meets at ingress.
//!
//! A method outside this list is not MCP's: a vendor's, under
//! `notifications/` or not. It keeps its members, because the protocol's
//! member rules say nothing about it.

/// What ingress does with a backend's protocol notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// Delivered without the gateway-only and scoped members it carries.
    Strip,
    /// Never delivered: the gateway owns task identity toward the client, so
    /// a backend's task notification names a task the client does not know.
    Drop,
}

/// Every server-to-client notification of a supported revision or the tasks
/// extension. The tests pin it to the per-revision schema table.
pub(crate) const PROTOCOL_NOTIFICATIONS: &[(&str, Rule)] = &[
    ("notifications/cancelled", Rule::Strip),
    ("notifications/progress", Rule::Strip),
    ("notifications/message", Rule::Strip),
    ("notifications/resources/updated", Rule::Strip),
    ("notifications/resources/list_changed", Rule::Strip),
    ("notifications/tools/list_changed", Rule::Strip),
    ("notifications/prompts/list_changed", Rule::Strip),
    ("notifications/elicitation/complete", Rule::Strip),
    ("notifications/subscriptions/acknowledged", Rule::Strip),
    ("notifications/tasks/status", Rule::Drop),
    // The tasks extension (SEP-2663), not a schema revision.
    ("notifications/tasks", Rule::Drop),
];

/// The rule for `method`; `None` for a method that is not MCP's.
pub(crate) fn rule(method: &str) -> Option<Rule> {
    PROTOCOL_NOTIFICATIONS
        .iter()
        .find(|(m, _)| *m == method)
        .map(|(_, rule)| *rule)
}

#[cfg(test)]
#[path = "notifications_tests.rs"]
mod tests;
