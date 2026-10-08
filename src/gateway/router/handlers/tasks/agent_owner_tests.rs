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
