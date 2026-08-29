// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An `env:` agent secret is judged on the value it RESOLVES to (MIK-7258).
//!
//! Lives here rather than beside the other agent-key tests because
//! `env::set_var` is unsafe in edition 2024 and the library forbids unsafe.
//!
//! WHY THIS CASE EXISTS. `Config::validate` refuses an agent whose HS256 secret
//! could not reject anybody. A first version exempted `env:` references from
//! that check, reasoning that a missing variable already fails validation
//! elsewhere. That reasoning was wrong in a way worth pinning: the existing
//! check asks whether the variable EXISTS, and a variable that exists and is
//! empty passes it. The forgeable configuration then reached a running gateway
//! through the one path nobody was looking at.

#![allow(unsafe_code)] // set_var/remove_var are unsafe in edition 2024

use mcp_gateway::config::{AgentDefinitionConfig, Config};

/// A config with agent auth on and one agent whose secret is `spec`.
fn with_agent_secret(spec: &str) -> Config {
    let mut c = Config::default();
    c.agent_auth.enabled = true;
    c.agent_auth.agents = vec![AgentDefinitionConfig {
        client_id: "svc".to_string(),
        name: "svc".to_string(),
        hs256_secret: Some(spec.to_string()),
        rs256_public_key: None,
        scopes: Vec::new(),
        issuer: None,
        audience: None,
    }];
    c
}

/// One test, not four: these mutate process-global state, and separate `#[test]`
/// functions run concurrently in the same binary. Sequencing them here is what
/// keeps one case from reading another's variable.
#[test]
fn an_env_agent_secret_is_judged_on_what_it_resolves_to() {
    let var = "MIK_7258_AGENT_SECRET";

    // A variable that EXISTS and is empty. This is the case the earlier
    // reasoning let through: present, so the existence check passes; empty, so
    // the key it builds verifies a token anyone can sign.
    unsafe { std::env::set_var(var, "") };
    let err = with_agent_secret(&format!("env:{var}"))
        .validate()
        .expect_err("an env: secret resolving to empty was accepted");
    assert!(
        err.to_string().contains("svc") && err.to_string().contains("0 bytes"),
        "the message must name the agent and what it resolved to: {err}"
    );

    // Present but too short is the same problem with more characters.
    unsafe { std::env::set_var(var, "short") };
    with_agent_secret(&format!("env:{var}"))
        .validate()
        .expect_err("an env: secret resolving to 5 bytes was accepted");

    // Long enough, and it validates — the check must not refuse a real secret.
    unsafe { std::env::set_var(var, "k".repeat(32)) };
    with_agent_secret(&format!("env:{var}"))
        .validate()
        .expect("a 32-byte resolved secret is the documented minimum");

    // Absent entirely: refused, naming the variable, so the operator is not
    // left guessing which one.
    unsafe { std::env::remove_var(var) };
    let err = with_agent_secret(&format!("env:{var}"))
        .validate()
        .expect_err("an env: secret pointing at nothing was accepted");
    assert!(
        err.to_string().contains(var),
        "the message must name the missing variable: {err}"
    );
}
