// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A `secrets:` rule on an `a2a_url` backend is refused at config load. The
//! A2A bridge forwards only the `message` argument and states its own
//! protocol header, so no rule of either target ever reached the agent.

use super::{BackendConfig, Config};

/// An A2A backend with one `argument` rule named `api`.
fn a2a_with_argument_rule() -> BackendConfig {
    crate::yaml::from_str(
        "a2a_url: https://agent.example.com\n\
         secrets:\n\
         \x20 - name: api\n\
         \x20   value: plain-a2a-value-cc03\n\
         \x20   inject_as: argument\n\
         \x20   inject_key: api_key\n",
    )
    .expect("the backend parses")
}

/// Config load refuses the rule, naming the backend and the rule.
#[test]
fn an_a2a_backend_with_a_secret_rule_is_refused_at_load() {
    let mut config = Config::default();
    config
        .backends
        .insert("agent".to_string(), a2a_with_argument_rule());
    let refusal = match config.validate() {
        Err(e) => e.to_string(),
        Ok(()) => panic!(
            "the config loaded: its secret rule is accepted though the A2A bridge \
             never forwards it"
        ),
    };
    assert!(
        refusal.contains("'agent'") && refusal.contains("'api'"),
        "the refusal must name the backend and the rule: {refusal}"
    );
    assert!(
        !refusal.contains("plain-a2a-value-cc03"),
        "the refusal echoed the rule's value: {refusal}"
    );
}
