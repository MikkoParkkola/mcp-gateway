// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision fixture table, task replay's refusal site: a stored read whose
//! target the backend's `allowed_tools` now leaves out notes `allowed_tools`
//! with no rule id (`task_replay.rs:412`, via `blocked_tool_kind`; found while
//! coding). The check writes no record of its own (the read's judgement
//! answers it with its record), so this row pins the refusal it notes, as
//! `task_replay_rule_id_tests` does for the tool policy.

use std::sync::Arc;
use std::time::Duration;

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::invoke::audit::{take_refusal, with_route_scope};
use crate::security::decision_record::DecisionKind;

/// T3: a replay whose target `allowed_tools` leaves out is refused without
/// reading any catalogue, and notes `allowed_tools`, never a rule id.
#[tokio::test]
async fn t3_task_replay_allowed_tools() {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig {
            allowed_tools: Some(vec!["write".to_string()]),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    assert!(registry.register(Arc::clone(&backend)));
    let meta = MetaMcp::new(registry);
    let scope = crate::gateway::meta_mcp::InvokeScope {
        authorizer: &AllowAll,
        admin: crate::gateway::authz::AdminStanding::None,
        api_key_name: None,
        grant_key: None,
        agent_id: None,
        grant_subject: None,
        caller: crate::identity_propagation::CallerProof::Anonymous,
    };
    let noted = with_route_scope(async {
        assert!(
            meta.refused_without_catalogue(&backend, ("alpha", "read"), scope, None),
            "premise: the replay's target is refused"
        );
        take_refusal()
    })
    .await;
    assert_eq!(noted, Some((DecisionKind::AllowedTools, None)));
}
