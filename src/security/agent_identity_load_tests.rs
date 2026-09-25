// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A4b T21/T29: `known_agents` entries that cannot be enforced as written are
//! refused when the config loads, not discovered on the first request.

use super::*;
use crate::config::Config;

/// T21: a bare string is a parse error naming the sources it must declare.
#[test]
fn a_bare_string_known_agent_names_the_source_it_must_declare() {
    let error = serde_yaml::from_str::<AgentIdentityConfig>("known_agents: [runner]")
        .expect_err("a bare known_agents entry must not parse")
        .to_string();
    for needle in ["mtls", "jwt", "runner"] {
        assert!(error.contains(needle), "missing {needle}: {error}");
    }
}

/// A qualified entry still parses, and an unknown source keeps serde's detail.
#[test]
fn a_qualified_known_agent_parses_and_a_bad_source_says_why() {
    let config: AgentIdentityConfig =
        serde_yaml::from_str("known_agents: [{source: mtls, id: runner}]").unwrap();
    assert_eq!(
        config.known_agents,
        vec![KnownAgent {
            source: AgentSourceKey::Mtls,
            id: "runner".to_string(),
        }]
    );
    let error = serde_yaml::from_str::<AgentIdentityConfig>("known_agents: [{source: tls, id: x}]")
        .unwrap_err()
        .to_string();
    assert!(error.contains("tls"), "{error}");
}

fn config_with(enabled: bool, hatch: bool) -> Config {
    let mut config = Config::default();
    config.security.agent_identity = AgentIdentityConfig {
        enabled,
        allow_unverified_agent_identity: hatch,
        known_agents: vec![KnownAgent {
            source: AgentSourceKey::Declared,
            id: "x".to_string(),
        }],
        ..AgentIdentityConfig::default()
    };
    config
}

/// T29: with the feature on and the hatch off, a declared entry refuses load.
#[test]
fn a_declared_known_agent_without_the_hatch_fails_config_load() {
    Config::default().validate().expect("baseline config validates");
    let error = config_with(true, false)
        .validate()
        .expect_err("T29")
        .to_string();
    assert!(error.contains("allow_unverified_agent_identity"), "{error}");
}

/// Revision 2 cell: with the feature off the entry is dormant and loads.
/// C29: the hatch is the one way a declared entry loads with the feature on.
#[test]
fn a_declared_known_agent_loads_when_dormant_or_under_the_hatch() {
    config_with(false, false).validate().expect("dormant");
    config_with(true, true).validate().expect("C29");
}
