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
    Config::default()
        .validate()
        .expect("baseline config validates");
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

// ── #2244: faults that used to surface only at request time ─────────────────

fn require_id_config(hatch: bool) -> Config {
    let mut config = Config::default();
    config.security.agent_identity = AgentIdentityConfig {
        enabled: true,
        require_id: true,
        allow_unverified_agent_identity: hatch,
        ..AgentIdentityConfig::default()
    };
    config
}

/// `require_id` with no proof source and no hatch refuses every call; refuse
/// the config instead.
#[test]
fn require_id_without_any_proof_source_fails_config_load() {
    let error = require_id_config(false)
        .validate()
        .expect_err("unsatisfiable require_id")
        .to_string();
    assert!(error.contains("require_id"), "{error}");
}

/// Any one way to satisfy it loads: agent JWT, mTLS, or the hatch.
#[test]
fn require_id_loads_when_some_proof_source_can_satisfy_it() {
    let mut jwt = require_id_config(false);
    jwt.agent_auth.enabled = true;
    jwt.validate().expect("agent JWT");
    let mut mtls = require_id_config(false);
    mtls.mtls.enabled = true;
    mtls.validate().expect("mTLS");
    require_id_config(true).validate().expect("hatch");
}

/// The hatch weakens identity, so the gateway says so when it loads.
#[test]
fn the_unverified_hatch_warns_at_load() {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let buf = Buf::default();
    let sink = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || sink.clone())
        .with_ansi(false)
        .finish();
    // A callsite another thread cached as off would miss this capture (MIK-8254).
    crate::test_log_capture::keep_interest_open();
    tracing::subscriber::with_default(subscriber, || {
        require_id_config(true).validate().expect("hatch loads");
    });
    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("allow_unverified_agent_identity"), "{logs}");
}

/// Lookup is first-match, so a second row for one principal would be dead
/// config; refuse it.
#[test]
fn duplicate_principal_labels_fail_config_load() {
    let row = |labels: &[&str]| PrincipalLabels {
        source: ProofSource::VerifiedJwtSubject,
        id: "runner".to_string(),
        labels: labels.iter().map(|l| (*l).to_string()).collect(),
    };
    let mut config = Config::default();
    config.security.agent_identity.principal_labels = vec![row(&["a"]), row(&["b"])];
    let error = config
        .validate()
        .expect_err("duplicate principal_labels")
        .to_string();
    assert!(
        error.contains("principal_labels") && error.contains("runner"),
        "{error}"
    );
}
