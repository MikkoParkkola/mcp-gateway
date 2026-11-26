// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The public `ReloadOutcome` keeps its shape for a library caller: built
//! from a struct literal outside the crate, and serialised with exactly the
//! members it always had. The settings save's "applied" signal travels
//! inside the crate, never as a field here.

use std::collections::BTreeSet;

use mcp_gateway::config_reload::ReloadOutcome;

fn keys(outcome: &ReloadOutcome) -> BTreeSet<String> {
    let value = serde_json::to_value(outcome).expect("serialises");
    let object = value.as_object().expect("an object");
    object.keys().cloned().collect()
}

#[test]
fn a_reload_outcome_is_built_and_serialised_as_before() {
    let minimal = ReloadOutcome {
        changes: "x".into(),
        restart_required: false,
        restart_reason: None,
        pending_restart_fields: vec![],
    };
    let want: BTreeSet<String> = ["changes", "restart_required"].map(String::from).into();
    assert_eq!(keys(&minimal), want);

    let full = ReloadOutcome {
        changes: "x".into(),
        restart_required: true,
        restart_reason: Some("server_address_changed"),
        pending_restart_fields: vec!["server.port".into()],
    };
    let want: BTreeSet<String> = [
        "changes",
        "restart_required",
        "restart_reason",
        "pending_restart_fields",
    ]
    .map(String::from)
    .into();
    assert_eq!(keys(&full), want);
}
