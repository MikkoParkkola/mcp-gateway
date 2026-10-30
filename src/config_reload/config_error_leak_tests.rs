// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8375: a refused reload is logged, so its reason must not carry the
//! value the new config got wrong.

use std::sync::Arc;

use super::*;
use crate::config::{Config, LiveEnv};
use crate::gateway::test_helpers::write_owner_only;

#[test]
fn a_refused_reload_does_not_log_the_value() {
    let sentinel = "cfgleak-sentinel-r4";
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    write_owner_only(&config, "server:\n  port: 39400\n").expect("write config");
    let startup = Config::load_evaluated(Some(&config)).expect("startup loads");
    let live = Arc::new(LiveConfig::new(startup.config.clone()));
    let env = LiveEnv::new(startup.overlay, startup.env_paths);

    write_owner_only(
        &config,
        format!("server:\n  port: 39400\nauth:\n  bearer_token: !!int {sentinel}\n"),
    )
    .expect("break it");
    let Err(reason) = load_config_patch(&config, &live, &env) else {
        panic!("the reload must be refused");
    };
    assert!(!reason.contains(sentinel), "the value leaked: {reason}");
    assert!(reason.contains("auth.bearer_token"), "{reason}");
}

/// A refused reload for a bad collusion glob names the key path and index,
/// never the pattern, for each glob-valued collusion setting.
#[test]
fn a_refused_reload_for_a_bad_collusion_glob_does_not_log_the_pattern() {
    let sentinel = "cfgleak-collusion-r5:[";
    let head = "security:\n  firewall:\n    enabled: true\n    collusion:\n      action: observe\n";
    let cases = [
        (
            format!("      sources: [\"a:*\", \"{sentinel}\"]\n"),
            "collusion.sources[1]",
        ),
        (
            format!("      non_egress: [\"{sentinel}\"]\n"),
            "collusion.non_egress[0]",
        ),
        (
            format!(
                "      allowed_flows:\n        - {{source: \"{sentinel}\", egress: \"b:*\"}}\n"
            ),
            "collusion.allowed_flows[0].source",
        ),
        (
            format!(
                "      allowed_flows:\n        - {{source: \"a:*\", egress: \"{sentinel}\"}}\n"
            ),
            "collusion.allowed_flows[0].egress",
        ),
    ];
    for (body, path) in cases {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("gateway.yaml");
        write_owner_only(&config, "server:\n  port: 39400\n").expect("write config");
        let startup = Config::load_evaluated(Some(&config)).expect("startup loads");
        let live = Arc::new(LiveConfig::new(startup.config.clone()));
        let env = LiveEnv::new(startup.overlay, startup.env_paths);
        write_owner_only(&config, format!("server:\n  port: 39400\n{head}{body}"))
            .expect("break it");
        let Err(reason) = load_config_patch(&config, &live, &env) else {
            panic!("{path}: the reload must be refused");
        };
        assert!(
            !reason.contains("cfgleak-collusion"),
            "{path}: the pattern leaked: {reason}"
        );
        assert!(reason.contains(path), "{path}: {reason}");
    }
}
