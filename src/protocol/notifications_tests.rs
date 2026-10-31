// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::collections::BTreeSet;

use super::*;

/// Each revision's `ServerNotification` union, from
/// `schema/<revision>/schema.ts` in modelcontextprotocol/modelcontextprotocol.
const BY_REVISION: &[(&str, &[&str])] = &[
    ("2024-11-05", BASE),
    ("2025-03-26", BASE),
    ("2025-06-18", BASE),
    (
        "2025-11-25",
        &[
            "notifications/cancelled",
            "notifications/progress",
            "notifications/message",
            "notifications/resources/updated",
            "notifications/resources/list_changed",
            "notifications/tools/list_changed",
            "notifications/prompts/list_changed",
            "notifications/elicitation/complete",
            "notifications/tasks/status",
        ],
    ),
    (
        "2026-07-28",
        &[
            "notifications/cancelled",
            "notifications/progress",
            "notifications/message",
            "notifications/resources/updated",
            "notifications/resources/list_changed",
            "notifications/tools/list_changed",
            "notifications/prompts/list_changed",
            "notifications/subscriptions/acknowledged",
        ],
    ),
];

const BASE: &[&str] = &[
    "notifications/cancelled",
    "notifications/progress",
    "notifications/message",
    "notifications/resources/updated",
    "notifications/resources/list_changed",
    "notifications/tools/list_changed",
    "notifications/prompts/list_changed",
];

/// The task notifications, each dropped: the extension's and 2025-11-25's.
const DROPPED: &[&str] = &["notifications/tasks", "notifications/tasks/status"];

fn listed(wanted: Rule) -> BTreeSet<&'static str> {
    PROTOCOL_NOTIFICATIONS
        .iter()
        .filter(|(_, rule)| *rule == wanted)
        .map(|(m, _)| *m)
        .collect()
}

/// A revision added to the gateway without its notifications in the table
/// fails here, before its notifications can pass ingress as a vendor's.
#[test]
fn the_table_covers_every_supported_revision() {
    let table: BTreeSet<&str> = BY_REVISION.iter().map(|(r, _)| *r).collect();
    let supported: BTreeSet<&str> = crate::protocol::SUPPORTED_VERSIONS
        .iter()
        .chain(crate::protocol::meta::MODERN_VERSIONS)
        .copied()
        .collect();
    assert_eq!(table, supported);
}

/// The two rules together list every revision's notifications and the tasks
/// extension's, and nothing else; the task notifications are the dropped ones.
#[test]
fn the_rules_list_exactly_the_protocol_notifications() {
    let mut every: BTreeSet<&str> = BY_REVISION
        .iter()
        .flat_map(|(_, methods)| methods.iter().copied())
        .collect();
    every.insert("notifications/tasks");
    let dropped: BTreeSet<&str> = DROPPED.iter().copied().collect();
    let stripped: BTreeSet<&str> = every.difference(&dropped).copied().collect();

    assert_eq!(listed(Rule::Drop), dropped);
    assert_eq!(listed(Rule::Strip), stripped);
    assert_eq!(
        PROTOCOL_NOTIFICATIONS.len(),
        every.len(),
        "a method listed twice"
    );
}

/// A vendor method keeps its members, under `notifications/` or not.
#[test]
fn a_vendor_method_has_no_rule() {
    assert_eq!(rule("notifications/acme/status"), None);
    assert_eq!(rule("acme/status"), None);
    assert_eq!(rule("notifications/progress"), Some(Rule::Strip));
    assert_eq!(rule("notifications/tasks/status"), Some(Rule::Drop));
}
