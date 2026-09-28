// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! #2210: an opaque base64url value the gateway mints is never read as a
//! credential. Random ciphertext holds a GitHub-token-shaped run (a `gh?_`
//! prefix plus 36 letters and digits) about once in 20,000 envelopes; the
//! redactor then rewrote the protected `requestState` and the whole
//! continuation was refused.

use serde_json::json;

use super::{correlation, response_fixture, response_rule, target};
use crate::security::firewall::{FirewallAction, FirewallConfig};
use crate::security::response_policy::{ResponseArtifactKind, ResponseMutationPolicy};

/// A continuation envelope shape: URL-safe base64 with a token-shaped run in
/// the middle, bordered on both sides by more envelope characters. Split with
/// `concat!` so the source never holds a token-shaped literal.
const ENVELOPE: &str = concat!(
    "q7Zx-_9Kd2",
    "gh", "p_abcdefghijklmnopqrstuvwxyz0123456789",
    "Wm3-Qe_8rT1vLp0aB9"
);

#[test]
fn a_minted_envelope_with_a_token_shaped_run_is_delivered_unchanged() {
    let (firewall, _dir, _path) = response_fixture(FirewallConfig {
        rules: vec![response_rule("inspect_me", FirewallAction::Allow)],
        ..FirewallConfig::default()
    });
    let mut response = json!({
        "resultType": "input_required",
        "inputRequests": {"q1": {"params": {"message": "Choose"}}},
        "requestState": ENVELOPE,
    });
    let verdict = firewall
        .check_response_artifact(
            &mut response,
            &[target("backend-a", "inspect_me")],
            &correlation(),
            ResponseArtifactKind::FinalResponse,
            ResponseMutationPolicy::PreserveInputRequired,
        )
        .expect("nonempty server-bound targets");
    assert!(verdict.allowed, "envelope refused: {:?}", verdict.findings);
    assert!(verdict.findings.is_empty(), "{:?}", verdict.findings);
    assert_eq!(response["requestState"], ENVELOPE);
}
