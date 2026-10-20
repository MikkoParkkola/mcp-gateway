// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8031 R3: one validated agent's task owner is never another's.

use super::{AUTH_DISABLED_TASK_OWNER, agent_task_owner};

#[test]
fn two_agents_never_share_a_task_owner() {
    let a = agent_task_owner("agent-a");
    assert_ne!(a, agent_task_owner("agent-b"));
    assert_ne!(a, AUTH_DISABLED_TASK_OWNER);
    // A separator inside an id cannot spell a shorter id's owner.
    assert_ne!(agent_task_owner("a"), agent_task_owner("1:a"));
    assert_ne!(agent_task_owner("a:b"), agent_task_owner("a"));
    // The id enters as its SHA-256 digest; a golden value catches format drift.
    assert_eq!(
        agent_task_owner("a"),
        "agent-jwt:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    );
}

/// Bot finding on #3489: a `client_id` has no configured length limit, and the
/// task owner it derives must still be one task admission accepts, with room
/// left for an idempotency key under the same metadata bound.
#[test]
fn a_long_client_id_still_owns_tasks() {
    let long = "a".repeat(5_000);
    let owner = agent_task_owner(&long);
    assert_eq!(
        owner.len(),
        "agent-jwt:".len() + 64,
        "the owner's length does not depend on the client_id's"
    );
    assert!(
        owner.len() + 1_024 <= crate::idempotency::admission::METADATA_LIMIT,
        "an idempotency key of 1 KiB still fits beside the owner"
    );
    assert!(
        crate::idempotency::admission::ExecutionAdmission::owner(&owner).is_ok(),
        "task admission accepts the owner"
    );
    assert_ne!(owner, agent_task_owner(&"a".repeat(5_001)));
}

/// A validated agent's identity as `agent_auth_middleware` inserts it.
fn agent(client_id: &str) -> crate::gateway::oauth::AgentIdentity {
    crate::gateway::oauth::AgentIdentity {
        client_id: client_id.to_string(),
        agent_name: client_id.to_string(),
        scopes: Vec::new(),
        raw_scopes: Vec::new(),
        quota_principal: None,
    }
}

/// A fixture state with gateway authentication `enabled`.
async fn state(
    enabled: bool,
) -> (
    std::sync::Arc<crate::gateway::router::AppState>,
    tempfile::TempDir,
) {
    let auth = crate::config::AuthConfig {
        enabled,
        ..crate::config::AuthConfig::default()
    };
    crate::gateway::router::tests::test_router_app_state_with_auth(&auth).await
}

/// MIK-8055 N7 (K1, K4): with gateway authentication on and no gateway
/// credential, a validated agent owns its tasks under the same owner it has
/// with authentication off, so switching authentication on keeps them.
#[tokio::test]
async fn an_agent_owns_the_same_tasks_with_gateway_auth_off_and_on() {
    let a = agent("agent-a");
    let (off, _off_store) = state(false).await;
    let (on, _on_store) = state(true).await;
    let owner_off = super::route_task_owner(&off, None, Some(&a), "");
    let owner_on = super::route_task_owner(&on, None, Some(&a), "");
    assert_eq!(owner_off, agent_task_owner("agent-a"));
    assert_eq!(
        owner_on, owner_off,
        "with gateway auth on, an agent with no gateway credential owns as its client_id"
    );
}

/// MIK-8055 N5 (K2): a gateway credential's owner key keeps precedence over
/// the agent arm, and no agent at all still resolves to no owner.
#[tokio::test]
async fn a_gateway_credential_keeps_precedence_over_the_agent_arm() {
    let a = agent("agent-a");
    let (on, _store) = state(true).await;
    let credential = super::route_task_owner(&on, None, None, "credential:key-a");
    assert_eq!(
        super::route_task_owner(&on, None, Some(&a), "credential:key-a"),
        credential,
        "a non-empty owner key decides, agent or not"
    );
    assert!(
        super::route_task_owner(&on, None, None, "").is_empty(),
        "no credential and no agent stays unattributed"
    );
}
