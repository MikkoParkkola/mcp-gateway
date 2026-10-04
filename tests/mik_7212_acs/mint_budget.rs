// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use mcp_gateway::protocol::continuation::{
    ContinuationError, ContinuationPurpose, Keyring, Payload,
};

fn payload() -> Payload {
    Payload {
        backend_id: "weather".into(),
        backend_request_state: Some("state".into()),
        principal_fingerprint: "sha256:caller-a".into(),
        original_request_digest: "sha256:req-1".into(),
        origin_replica: "gw-1".into(),
        // 200s wide, and every `open` below is called at 1_500 inside it.
        // `Keyring::mint` refuses a window wider than
        // `CONTINUATION_LIFETIME_SECS` (300), so a fixture spanning
        // 1_000..2_000 no longer seals — see MRTR.8b.
        issued_at: 1_400,
        expires_at: 1_600,
        jti: "jti-1".into(),
        hold_key: "exchange-1".into(),
        next_step: None,
        rounds_used: 0,
        // A backend `input_required` continuation, the domain every case
        // in this module mints and redeems in.
        purpose: ContinuationPurpose::BackendInput,
    }
}

#[test]
fn a_key_stops_minting_once_it_has_spent_its_budget() {
    // AES-GCM with a random 96-bit nonce collides on the birthday bound, and
    // a nonce reused under one key loses confidentiality outright rather
    // than gradually. Rotation is what keeps a deployment under the bound;
    // this is what makes the bound enforced instead of hoped for.
    let keyring = Keyring::new(&[(1, [7u8; 32])])
        .expect("keyring")
        .with_mint_budget(2);

    assert!(keyring.mint(&payload()).is_ok());
    assert!(keyring.mint(&payload()).is_ok());
    assert_eq!(
        keyring.mint(&payload()).err(),
        Some(ContinuationError::MintBudgetExhausted),
        "a key must refuse to seal past its budget"
    );
    // And it stays refused rather than recovering on the next call.
    assert_eq!(
        keyring.mint(&payload()).err(),
        Some(ContinuationError::MintBudgetExhausted)
    );
}

#[test]
fn the_budget_cannot_be_raised_above_the_ceiling() {
    // The ceiling is a property of AES-GCM with random nonces, not a
    // preference, so a caller may rotate sooner and may not rotate later.
    let raised = Keyring::new(&[(1, [7u8; 32])])
        .expect("keyring")
        .with_mint_budget(u64::MAX);
    assert_eq!(
        raised.mint_budget_remaining(),
        1_u64 << 32,
        "a budget above the ceiling must clamp to it, not disable the check"
    );

    let lowered = Keyring::new(&[(1, [7u8; 32])])
        .expect("keyring")
        .with_mint_budget(8);
    assert_eq!(lowered.mint_budget_remaining(), 8);
    lowered.mint(&payload()).expect("mint");
    assert_eq!(
        lowered.mint_budget_remaining(),
        7,
        "the remaining budget must fall as envelopes are sealed"
    );
}

#[test]
fn an_exhausted_key_still_verifies_what_it_already_sealed() {
    // Refusing to mint must not orphan the envelopes already in flight.
    let keyring = Keyring::new(&[(1, [7u8; 32])])
        .expect("keyring")
        .with_mint_budget(1);
    let token = keyring.mint(&payload()).expect("first mint");
    assert!(keyring.mint(&payload()).is_err());

    assert_eq!(
        keyring.open(&token, 1_500).expect("opens").jti,
        "jti-1",
        "an exhausted key must keep verifying envelopes it already minted"
    );
}
