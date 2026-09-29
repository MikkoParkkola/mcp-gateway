// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2259: the caller's declared agent label reaches the audit record of every
//! call it makes. The audit line reads `caller.agent_declared`, so a context
//! rebuilt for a chain step must carry the label rather than reset it.

use crate::gateway::authz::AllowAll;
use crate::security::{AgentIdentity, DeclaredLabel, DeclaredSource};

fn declared(tag: &str) -> AgentIdentity {
    AgentIdentity {
        declared: Some(DeclaredLabel {
            id: tag.to_owned(),
            source: DeclaredSource::Header,
        }),
        ..AgentIdentity::default()
    }
}

#[test]
fn a_chain_step_keeps_the_declared_agent_label() {
    let identity = declared("planner-7");
    let mut caller = super::authz_tests::ctx(&AllowAll);
    caller.agent_declared = identity.declared_agent_label();

    let retry = crate::protocol::mrtr::RetryFields::default();
    let step = caller.with_retry(&retry);

    assert_eq!(
        step.agent_declared
            .map(crate::security::DeclaredAgentLabel::as_str),
        Some("planner-7"),
        "a chain step must audit the label its caller declared"
    );
}
