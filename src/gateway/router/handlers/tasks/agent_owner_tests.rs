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
    assert_eq!(agent_task_owner("a"), "agent-jwt:1:a");
}
