// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The immutable-challenge response rows: a mutated challenge is audited as a
//! block, and an unchanged one, or one under disabled controls, is not. Moved
//! from `response_tests.rs` for the file-size ceiling.

use super::*;

/// MIK-7407.RESPONSE.3/.4; FWR-20. Inspect raw unknown parameters too.
/// The permission to redact ordinary results cannot rewrite a question.
#[test]
fn firewall_response_immutable_challenge_mutation_is_audited_as_block() {
    for action in [FirewallAction::Allow, FirewallAction::Warn] {
        let (firewall, _dir, path) = response_fixture(FirewallConfig {
            rules: vec![response_rule("inspect_me", action)],
            ..FirewallConfig::default()
        });
        let original = json!({"q1": {
            "method":"elicitation/create", "params":{"message":"Choose", "unknown":{"value":CANARY}}
        }});
        let mut challenge = original.clone();
        let verdict = firewall
            .check_response_artifact(
                &mut challenge,
                &[target("backend-a", "inspect_me")],
                &correlation(),
                ResponseArtifactKind::BridgeChallenge,
                ResponseMutationPolicy::Immutable,
            )
            .expect("nonempty server-bound targets");
        assert!(
            !verdict.allowed,
            "question mutation must refuse even if the rule says Allow/Warn"
        );
        assert_eq!(verdict.action, FirewallAction::Block);
        assert_eq!(challenge, original);
        assert_counts(&firewall, 1, 1, 1);
        let events = audit_entries(&path);
        assert_eq!(events.len(), 1);
        assert_response_event(
            &events[0],
            &correlation(),
            &[target("backend-a", "inspect_me")],
            ResponseArtifactKind::BridgeChallenge,
            FirewallAction::Block,
        );
    }
}

/// MIK-7407.RESPONSE.3/.4; FWR-20. Immutability does not turn unchanged
/// Warn/Allow questions into refusals, and disabled inspection stays a no-op.
#[test]
fn firewall_response_immutable_challenge_unchanged_and_disabled_controls() {
    for action in [FirewallAction::Allow, FirewallAction::Warn] {
        let (firewall, _dir, path) = response_fixture(FirewallConfig {
            rules: vec![response_rule("inspect_me", action)],
            ..FirewallConfig::default()
        });
        let original = json!({"q1":{"params":{"unknown":INJECTION}}});
        let mut challenge = original.clone();
        let verdict = firewall
            .check_response_artifact(
                &mut challenge,
                &[target("backend-a", "inspect_me")],
                &correlation(),
                ResponseArtifactKind::BridgeChallenge,
                ResponseMutationPolicy::Immutable,
            )
            .expect("nonempty server-bound targets");
        assert!(verdict.allowed);
        assert_eq!(verdict.action, action);
        assert_eq!(challenge, original);
        assert_counts(&firewall, 1, 1, 1);
        let events = audit_entries(&path);
        assert_eq!(events.len(), 1);
        assert_response_event(
            &events[0],
            &correlation(),
            &[target("backend-a", "inspect_me")],
            ResponseArtifactKind::BridgeChallenge,
            action,
        );
    }
    let (firewall, _dir, path) = response_fixture(FirewallConfig {
        scan_responses: false,
        rules: vec![response_rule("inspect_me", FirewallAction::Block)],
        ..FirewallConfig::default()
    });
    let original = json!({"q1":{"params":{"unknown":format!("{INJECTION} {CANARY}")}}});
    let mut challenge = original.clone();
    let verdict = firewall
        .check_response_artifact(
            &mut challenge,
            &[target("backend-a", "inspect_me")],
            &correlation(),
            ResponseArtifactKind::BridgeChallenge,
            ResponseMutationPolicy::Immutable,
        )
        .expect("nonempty server-bound targets");
    assert!(verdict.allowed);
    assert_eq!(challenge, original);
    assert_counts(&firewall, 0, 0, 0);
    assert!(audit_entries(&path).is_empty());
}
