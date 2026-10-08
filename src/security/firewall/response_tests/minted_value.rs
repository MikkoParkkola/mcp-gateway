// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! #2210: a continuation this gateway minted is never read as a credential.
//! Random ciphertext holds a GitHub-token-shaped run (a `gh?_` prefix plus 36
//! letters and digits) about once in 20,000 envelopes; the redactor then
//! rewrote the protected `requestState` and the whole continuation was
//! refused. Only a value that opens under this gateway's own keyring is
//! exempt: a backend string of the same shape is not.

use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde_json::{Value, json};

use super::{correlation, response_fixture, response_rule, target};
use crate::protocol::continuation::{ContinuationState, Keyring, Payload, now_unix_secs};
use crate::security::firewall::{Firewall, FirewallAction, FirewallConfig};
use crate::security::response_policy::{ResponseArtifactKind, ResponseMutationPolicy};

/// Bytes of the token head a tamper may touch; the credential-shaped run is
/// required to sit past it so the tampered copy still holds one.
const HEAD: usize = 16;

/// The GitHub and Slack token shapes, matched anywhere in the text and
/// independently of the redactor under test.
fn credential_shaped(text: &str) -> bool {
    static SHAPE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"gh[pos]_[A-Za-z0-9]{36}|xox[bprs]-[A-Za-z0-9-]{10,}")
            .expect("token shape compiles")
    });
    SHAPE.is_match(text)
}

/// A GitHub-token-shaped secret, split so no literal token sits in the source.
const SECRET: &str = concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789");

/// The entry point the gateway's response path uses for a firewall over
/// `state`'s keyring. The directory is returned so the audit file outlives
/// the test body.
fn gateway_firewall(state: &Arc<ContinuationState>) -> (Firewall, tempfile::TempDir) {
    let (firewall, dir, _path) = response_fixture(FirewallConfig {
        rules: vec![response_rule("inspect_me", FirewallAction::Allow)],
        ..FirewallConfig::default()
    });
    (firewall.with_continuations(Arc::clone(state)), dir)
}

/// Mint envelopes until one holds a credential-shaped run after its head. A
/// padded payload lengthens the ciphertext so a run turns up within a few
/// hundred mints.
pub(crate) fn mint_credential_shaped(keyring: &Keyring) -> String {
    mint_credential_shaped_at(keyring, now_unix_secs())
}

/// [`mint_credential_shaped`] for an envelope issued at `issued_at`.
fn mint_credential_shaped_at(keyring: &Keyring, issued_at: u64) -> String {
    let padding = "x".repeat(3000);
    (0..200_000)
        .find_map(|_| {
            let payload = Payload::mint(
                "backend-a".into(),
                Some(padding.clone()),
                "principal".into(),
                "digest".into(),
                "replica".into(),
                "hold".into(),
                issued_at,
            );
            let token = keyring.mint(&payload).expect("a fresh payload seals");
            credential_shaped(&token[HEAD..]).then_some(token)
        })
        .expect("ciphertext holds a credential-shaped run within 200,000 mints")
}

fn input_required(state: &str) -> Value {
    json!({
        "resultType": "input_required",
        "inputRequests": {"q1": {"params": {"message": "Choose"}}},
        "requestState": state,
    })
}

fn inspect(
    firewall: &Firewall,
    response: &mut Value,
    mutation: ResponseMutationPolicy,
) -> crate::security::firewall::FirewallVerdict {
    firewall
        .check_response_artifact(
            response,
            &[target("backend-a", "inspect_me")],
            &correlation(),
            ResponseArtifactKind::FinalResponse,
            mutation,
        )
        .expect("nonempty server-bound targets")
}

#[test]
fn a_minted_continuation_with_a_token_shaped_run_is_delivered_unchanged() {
    let state = Arc::new(ContinuationState::new());
    let (firewall, _dir) = gateway_firewall(&state);
    let token = mint_credential_shaped(state.keyring());
    for mutation in [
        ResponseMutationPolicy::Redact,
        ResponseMutationPolicy::PreserveInputRequired,
        ResponseMutationPolicy::Immutable,
    ] {
        let mut response = input_required(&token);
        let verdict = inspect(&firewall, &mut response, mutation);
        assert!(
            verdict.allowed,
            "{mutation:?} refused: {:?}",
            verdict.findings
        );
        assert!(verdict.findings.is_empty(), "{:?}", verdict.findings);
        assert_eq!(response["requestState"], token, "{mutation:?}");
    }
}

#[test]
fn a_continuation_minted_by_another_keyring_is_still_redacted() {
    let state = Arc::new(ContinuationState::new());
    let (firewall, _dir) = gateway_firewall(&state);
    let foreign = mint_credential_shaped(ContinuationState::new().keyring());
    let mut response = input_required(&foreign);
    let verdict = inspect(&firewall, &mut response, ResponseMutationPolicy::Redact);
    assert!(!verdict.findings.is_empty());
    assert_ne!(response["requestState"], foreign);
}

#[test]
fn a_tampered_continuation_is_still_redacted() {
    let state = Arc::new(ContinuationState::new());
    let (firewall, _dir) = gateway_firewall(&state);
    let token = mint_credential_shaped(state.keyring());
    let mut chars: Vec<char> = token.chars().collect();
    chars[5] = if chars[5] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    let mut response = input_required(&tampered);
    let verdict = inspect(&firewall, &mut response, ResponseMutationPolicy::Redact);
    assert!(!verdict.findings.is_empty());
    assert_ne!(response["requestState"], tampered);
}

#[test]
fn a_foreign_continuation_in_a_protected_field_is_refused() {
    let state = Arc::new(ContinuationState::new());
    let (firewall, _dir) = gateway_firewall(&state);
    let foreign = mint_credential_shaped(ContinuationState::new().keyring());
    let mut response = input_required(&foreign);
    let verdict = inspect(
        &firewall,
        &mut response,
        ResponseMutationPolicy::PreserveInputRequired,
    );
    assert!(!verdict.allowed);
    assert_eq!(response["requestState"], foreign, "refusal restores it");
}

#[test]
fn a_firewall_without_a_keyring_redacts_every_continuation() {
    let state = Arc::new(ContinuationState::new());
    let token = mint_credential_shaped(state.keyring());
    let (firewall, _dir, _path) = response_fixture(FirewallConfig::default());
    let mut response = input_required(&token);
    let verdict = inspect(&firewall, &mut response, ResponseMutationPolicy::Redact);
    assert!(!verdict.findings.is_empty());
}

#[test]
fn an_expired_own_minted_continuation_is_still_redacted() {
    let state = Arc::new(ContinuationState::new());
    let (firewall, _dir) = gateway_firewall(&state);
    let expired_token = mint_credential_shaped_at(state.keyring(), now_unix_secs() - 1_000_000);
    let mut response = input_required(&expired_token);
    let verdict = inspect(&firewall, &mut response, ResponseMutationPolicy::Redact);
    assert!(!verdict.findings.is_empty());
    assert_ne!(response["requestState"], expired_token);
}

#[test]
fn a_secret_glued_after_an_own_minted_continuation_is_redacted() {
    let state = Arc::new(ContinuationState::new());
    let (firewall, _dir) = gateway_firewall(&state);
    let token = mint_credential_shaped(state.keyring());
    let glued = format!("{token}{SECRET}");
    let mut response = input_required(&glued);
    let verdict = inspect(&firewall, &mut response, ResponseMutationPolicy::Redact);
    assert!(!verdict.findings.is_empty());
    assert!(!response["requestState"].as_str().unwrap().contains(SECRET));
}

#[test]
fn a_secret_after_a_space_following_an_own_minted_continuation_is_redacted() {
    let state = Arc::new(ContinuationState::new());
    let (firewall, _dir) = gateway_firewall(&state);
    let token = mint_credential_shaped(state.keyring());
    let spaced = format!("{token} {SECRET}");
    let mut response = input_required(&spaced);
    let verdict = inspect(&firewall, &mut response, ResponseMutationPolicy::Redact);
    assert!(!verdict.findings.is_empty());
    assert!(!response["requestState"].as_str().unwrap().contains(SECRET));
}
