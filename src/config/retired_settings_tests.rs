// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settings the gateway picks itself (Family settings-automatic-first,
//! MIK-8782 and MIK-8783): a config that still sets one loads, warns once,
//! and does not have the value honoured. The table here is the family's
//! guard, so a new retired key that misses either list fails.

use super::{RETIRED_KEYS, retired_warning};

/// A base64 32-byte Ed25519 seed, so a `security.signature_chain` fixture
/// loads on its own fields and fails only on what the row puts in it.
const SEED: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=";

/// Each retired setting: (dotted key, a file that sets it to a non-default value).
fn retired_settings() -> Vec<(&'static str, String)> {
    vec![
        (
            "capabilities.stale_check_secs",
            "capabilities:\n  stale_check_secs: 0\n".to_owned(),
        ),
        ("cache.enabled", "cache:\n  enabled: false\n".to_owned()),
        (
            "failsafe.retry.enabled",
            "failsafe:\n  retry:\n    enabled: false\n".to_owned(),
        ),
        (
            "failsafe.circuit_breaker.enabled",
            "failsafe:\n  circuit_breaker:\n    enabled: false\n".to_owned(),
        ),
        (
            "auth.client_circuit_breaker.enabled",
            "auth:\n  client_circuit_breaker:\n    enabled: false\n    failure_threshold: 3\n"
                .to_owned(),
        ),
        (
            "security.signature_chain.max_links",
            format!(
                "security:\n  signature_chain:\n    signing_key: {SEED}\n    key_id: gw-a\n    max_links: 4\n"
            ),
        ),
        (
            "server.protocol_revision_window",
            "server:\n  protocol_revision_window: record\n".to_owned(),
        ),
    ]
}

fn load_logs(text: &str) -> (Vec<serde_json::Value>, crate::Result<crate::config::Config>) {
    use crate::test_log_capture::records;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, text).expect("write config");
    let mut loaded = None;
    let logs = records(|| {
        loaded = Some(crate::config::Config::load(Some(&path)));
        // A reload warns no second time (the warning is logged once).
        let _ = crate::config::Config::load(Some(&path));
    });
    (logs, loaded.expect("load ran"))
}

/// T1.3: every retired setting loads and warns exactly once, naming the key.
#[test]
fn every_retired_setting_loads_and_warns_once() {
    use crate::test_log_capture::count;
    for (key, text) in retired_settings() {
        let (logs, loaded) = load_logs(&text);
        assert!(
            loaded.is_ok(),
            "{key}: a config that sets it must load: {:?}",
            loaded.err()
        );
        let warning = format!("`{key}` is ignored since 4.0");
        assert_eq!(count(&logs, "WARN", &warning), 1, "{key}: {logs:?}");
    }
}

/// T1.9: the UPGRADING fragment (folded into the guide at release, as
/// `upgrading_fragments.py assemble` does) quotes each retired setting's warning.
#[test]
fn upgrading_quotes_every_retired_setting_warning() {
    // The fragment until release assembly folds it into the guide and deletes
    // it, then the guide: whichever exists, so the row survives assembly.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let guide: String = ["docs/UPGRADING-4.0.md", "upgrading.d/8783.md"]
        .iter()
        .filter_map(|rel| std::fs::read_to_string(root.join(rel)).ok())
        .collect();
    for (key, _) in retired_settings() {
        let path: Vec<&str> = key.split('.').collect();
        let why = RETIRED_KEYS
            .iter()
            .find(|(p, _)| *p == path.as_slice())
            .map(|(_, why)| *why);
        let quote = why.map(|why| retired_warning(key, why));
        assert!(
            quote.as_deref().is_some_and(|q| guide.contains(q)),
            "{key}: UPGRADING must quote its warning: {quote:?}"
        );
    }
}

/// T2.8: dropping `deny_unknown_fields` on the chain section keeps a
/// misspelling there refused by the strict pass, by its full path, while
/// the retired `max_links` only warns.
#[test]
fn a_misspelled_signature_chain_key_is_still_refused() {
    let typo = format!(
        "security:\n  signature_chain:\n    signing_key: {SEED}\n    key_id: gw-a\n    key_idd: x\n"
    );
    let (_, loaded) = load_logs(&typo);
    let refusal = loaded.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        refusal.contains("security.signature_chain.key_idd"),
        "the refusal must name the misspelt key's path: {refusal:?}"
    );
}

/// T2.3: `failsafe.retry.enabled` is retired. A config that still says
/// `false` keeps retry on for what `resend_permission` allows; the internal
/// `RetryPolicy.enabled` is only ever cleared per call, for a denied resend.
#[test]
fn a_retired_retry_off_switch_leaves_retry_on() {
    let config: crate::config::RetryConfig =
        serde_json::from_value(serde_json::json!({ "enabled": false, "max_attempts": 3 }))
            .expect("a retry section with the retired key still parses");
    let policy = crate::failsafe::RetryPolicy::new(&config);
    assert!(
        policy.enabled,
        "retry follows the resend annotations, not a switch"
    );
    assert_eq!(
        policy.max_attempts, 3,
        "max_attempts stays the operator's hatch"
    );
}

/// T2.4: `failsafe.circuit_breaker.enabled` is retired: the backend breaker
/// trips whatever the file says, and `reset` (the `gateway_revive_server`
/// lever) still closes it.
#[test]
fn a_retired_breaker_off_switch_leaves_the_breaker_on() {
    use crate::failsafe::{CircuitBreaker, CircuitState};
    let config: crate::config::CircuitBreakerConfig = serde_json::from_value(serde_json::json!({
        "enabled": false, "failure_threshold": 2, "success_threshold": 1, "reset_timeout": "60s"
    }))
    .expect("a breaker section with the retired key still parses");
    let breaker = CircuitBreaker::new("b", &config);
    breaker.record_failure("x", std::time::Duration::ZERO);
    breaker.record_failure("x", std::time::Duration::ZERO);
    assert_eq!(
        breaker.state(),
        CircuitState::Open,
        "two failures open the breaker"
    );
    assert!(!breaker.can_proceed(), "an open breaker refuses");
    breaker.reset();
    assert_eq!(
        breaker.state(),
        CircuitState::Closed,
        "the revive lever closes it"
    );
}

/// T2.1 guard: no production code reads the retired stale-check interval.
#[test]
fn no_production_code_reads_the_stale_check_interval() {
    for (file, text) in [
        (
            "src/gateway/server/run_steps.rs",
            include_str!("../gateway/server/run_steps.rs"),
        ),
        (
            "src/gateway/server/stdio_loop.rs",
            include_str!("../gateway/server/stdio_loop.rs"),
        ),
        (
            "src/capability/watcher.rs",
            include_str!("../capability/watcher.rs"),
        ),
        (
            "src/config/features/capability.rs",
            include_str!("features/capability.rs"),
        ),
    ] {
        assert!(
            !text.contains("stale_check_secs"),
            "{file} still reads stale_check_secs"
        );
    }
}
