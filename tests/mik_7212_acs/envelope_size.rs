// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use mcp_gateway::protocol::continuation::{
    ContinuationError, ContinuationPurpose, Keyring, Payload,
};

fn payload_with_state(state: String) -> Payload {
    Payload {
        backend_id: "weather".into(),
        backend_request_state: Some(state),
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
fn an_oversized_token_is_refused_before_it_is_decoded() {
    // The token is client-controlled and arrives on every retry. Decoding
    // first means an attacker sizes the gateway's allocation and its AEAD
    // work with a string, which is a denial of service that needs no valid
    // key. The bound is checked against the encoded length, so nothing is
    // allocated on its behalf.
    let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
    let huge = "A".repeat(64 * 1024);

    assert_eq!(
        keyring.open(&huge, 1_500).err(),
        Some(ContinuationError::TooLarge),
        "an oversized continuation must be refused on its length alone"
    );
}

#[test]
fn a_payload_too_large_to_open_is_never_minted() {
    // Minting an envelope the gateway would then refuse to open is a bug
    // that surfaces only on the retry, long after the cause. Both ends
    // enforce the same bound so that cannot happen.
    let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");

    assert_eq!(
        keyring
            .mint(&payload_with_state("s".repeat(32 * 1024)))
            .err(),
        Some(ContinuationError::TooLarge),
        "a backend state too large to redeem must be refused at mint"
    );
}

#[test]
fn a_token_of_exactly_the_permitted_size_is_judged_on_its_contents() {
    // The bound is "longer than", so a token *at* the limit passes the
    // length gate and is refused, if at all, for what it contains. Nothing
    // pinned that boundary: the oversized test above uses 64 KiB and the
    // ordinary one a few hundred bytes, so relaxing the comparison to `>=`
    // changed no test's outcome. `cargo-mutants` made exactly that
    // substitution in `Keyring::open` and the suite stayed green.
    let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
    // `MAX_ENVELOPE_LEN` is private to its module; 8 KiB is its value, and
    // a token one byte longer is the case the test above covers.
    let at_limit = "A".repeat(8 * 1024);

    let refusal = keyring.open(&at_limit, 1_500).err();
    assert!(
        refusal.is_some() && refusal != Some(ContinuationError::TooLarge),
        "a token at the limit must be judged on its contents, not its length: {refusal:?}"
    );
}

#[test]
fn a_client_facing_refusal_still_tells_the_caller_something() {
    // Its sibling above pins what a refusal must not reveal, and an empty
    // string satisfies that perfectly — which is why `cargo-mutants` could
    // replace `client_message` with `""` and leave the suite green. A
    // refusal a caller cannot read is not a refusal.
    for internal in [
        ContinuationError::UnknownKey(3),
        ContinuationError::UnknownVersion(9),
        ContinuationError::NotAuthentic,
        ContinuationError::Expired,
        ContinuationError::Malformed,
        ContinuationError::TooLarge,
    ] {
        let shown = internal.client_message();
        assert!(
            shown.contains("continuation"),
            "a refusal must name what was refused: {shown:?}"
        );
    }
}

#[test]
fn an_ordinary_envelope_is_unaffected_by_the_bound() {
    // The bound must sit above real backend state, or it is an outage
    // rather than a guard.
    let keyring = Keyring::new(&[(1, [7u8; 32])]).expect("keyring");
    let token = keyring
        .mint(&payload_with_state("s".repeat(2_048)))
        .expect("2 KiB of backend state is ordinary and must mint");

    assert_eq!(
        keyring
            .open(&token, 1_500)
            .expect("opens")
            .backend_request_state
            .expect("the state that was minted must come back")
            .len(),
        2_048
    );
}
