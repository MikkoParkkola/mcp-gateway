// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored task's replay refused by the tool policy notes the deny entry's
//! id beside its kind, whether or not the target has a registry backend.

use std::sync::Arc;
use std::time::Duration;

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::ToolPolicyAuthorizer;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::invoke::audit::{take_refusal, with_route_scope};
use crate::security::decision_record::DecisionKind;
use crate::security::rule_id::RuleId;
use crate::security::{ToolPolicy, ToolPolicyConfig};

fn policy() -> ToolPolicy {
    ToolPolicy::from_config_keyed(
        &ToolPolicyConfig {
            deny: vec!["alpha:read".to_string()],
            use_default_deny: false,
            ..ToolPolicyConfig::default()
        },
        &crate::gateway::record_principal::test_record_key().rule_id_key(),
    )
}

fn expected() -> Option<(DecisionKind, Option<RuleId>)> {
    let key = crate::gateway::record_principal::test_record_key().rule_id_key();
    let bytes = serde_json::to_vec(&("deny", "alpha:read")).expect("serialises");
    Some((
        DecisionKind::ToolPolicy,
        Some(RuleId::of("tool_policy", &key, &bytes)),
    ))
}

fn alpha() -> Arc<Backend> {
    Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ))
}

fn scope(authorizer: &ToolPolicyAuthorizer<'_>) -> crate::gateway::meta_mcp::InvokeScope<'_> {
    crate::gateway::meta_mcp::InvokeScope {
        authorizer,
        is_admin: false,
        api_key_name: None,
        grant_key: None,
        agent_id: None,
        grant_subject: None,
        caller: crate::identity_propagation::CallerProof::Anonymous,
    }
}

#[tokio::test]
async fn a_replay_refused_with_its_backend_notes_the_rule() {
    let registry = Arc::new(BackendRegistry::new());
    let backend = alpha();
    assert!(registry.register(Arc::clone(&backend)));
    let meta = MetaMcp::new(registry);
    let policy = policy();
    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &policy,
        generation: None,
    };
    let noted = with_route_scope(async {
        assert!(meta.refused_without_catalogue(
            &backend,
            ("alpha", "read"),
            scope(&authorizer),
            None
        ));
        take_refusal()
    })
    .await;
    assert_eq!(noted, expected());
}

#[tokio::test]
async fn a_replay_refused_without_a_registry_backend_notes_the_rule() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let policy = policy();
    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &policy,
        generation: None,
    };
    let noted = with_route_scope(async {
        assert!(meta.target_refused_without_catalogue(("alpha", "read"), scope(&authorizer), None));
        take_refusal()
    })
    .await;
    assert_eq!(noted, expected());
}
