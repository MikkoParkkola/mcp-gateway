// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SUB.4 under a session routing profile: the current profile refuses before
//! a mismatch or a replay is served, and a restored profile finds the same
//! secured outcome. Split from `admission_tests.rs` for its line ceiling.

use super::*;

fn profile_replay(tool: &str, args: &Value, changed_args: &Value) {
    use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
    let profiles = std::collections::HashMap::from([
        (
            "restricted".into(),
            RoutingProfileConfig {
                deny_tools: Some(vec![SECOND.1.into()]),
                ..RoutingProfileConfig::default()
            },
        ),
        ("open".into(), RoutingProfileConfig::default()),
    ]);
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_code_mode(tool == "gateway_execute")
        .with_profile_registry(ProfileRegistry::from_config(&profiles, "open"));
    if tool == "gateway_run_playbook" {
        install_plan(&meta, original_plan());
    }
    let policy = MutablePolicy::new(SECOND);
    let retry = RetryFields {
        idempotency_key: Some("profile-bound-owner".into()),
        ..RetryFields::default()
    };
    let mut caller = context(&policy, &retry);
    caller.is_modern = false;
    retained_operation(&meta, &caller, tool, args);
    meta.session_profiles()
        .set_profile("legacy:session", "restricted");
    assert!(meta.active_profile(None).check(SECOND.0, SECOND.1).is_ok());
    for request in [args, changed_args] {
        let error = refusal(admit(&meta, &caller, tool, request, 3));
        // The representation names the session's active profile, so after the
        // switch even the unchanged plan is a mismatch, not a replay: in code
        // mode both requests answer as a missing step does (#3872 oracle 1).
        let any_request = if tool == "gateway_execute" {
            request
        } else {
            changed_args
        };
        if mismatch_of_a_hidden_step(tool, request, any_request, &error) {
            continue;
        }
        assert!(
            matches!(&error, Error::Protocol(message)
                if message.contains("routing profile") && message.contains(SECOND.1)),
            "the current session profile must refuse before mismatch/replay: {error}"
        );
    }
    meta.session_profiles()
        .set_profile("legacy:session", "open");
    assert_replay(admit(&meta, &caller, tool, args, 4), 4);
}

#[test]
fn sub4_replay_current_profile_playbook() {
    profile_replay(
        "gateway_run_playbook",
        &json!({"name":"protected-plan", "arguments":{"record":"original"}}),
        &json!({"name":"protected-plan", "arguments":{"record":"changed"}}),
    );
}

#[test]
fn sub4_replay_current_profile_code_mode() {
    profile_replay(
        "gateway_execute",
        &json!({"chain":[{"tool":format!("{}:{}",FIRST.0,FIRST.1)},
            {"tool":format!("{}:{}",SECOND.0,SECOND.1),"arguments":{"record":"original"}}]}),
        &json!({"chain":[{"tool":format!("{}:{}",FIRST.0,FIRST.1)},
            {"tool":format!("{}:{}",SECOND.0,SECOND.1),"arguments":{"record":"changed"}}]}),
    );
}

#[test]
fn sub4_replay_current_profile_single_target() {
    profile_replay(
        "gateway_invoke",
        &json!({"server":SECOND.0,"tool":SECOND.1,"arguments":{"record":"original"}}),
        &json!({"server":SECOND.0,"tool":SECOND.1,"arguments":{"record":"changed"}}),
    );
}
