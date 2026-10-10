// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use mcp_gateway::protocol::continuation::{
    ConsumedLedger, ContinuationError, ContinuationPurpose, InFlight, Keyring, Payload, Routing,
};

fn payload() -> Payload {
    Payload {
        backend_id: "weather".into(),
        backend_request_state: Some("Bearer super-secret-backend-token".into()),
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
fn a_formatted_payload_never_carries_sealed_state_or_bindings() {
    // The envelope is sealed on the wire and plaintext in memory. A derived
    // `Debug` undoes the sealing the moment anything logs one: the backend's
    // own state may carry the authorization it was issued, and the caller
    // bindings identify who may redeem the exchange.
    let formatted = format!("{:?}", payload());

    for secret in [
        "super-secret-backend-token",
        "sha256:caller-a",
        "sha256:req-1",
    ] {
        assert!(
            !formatted.contains(secret),
            "formatting a Payload leaked {secret}: {formatted}"
        );
    }
    assert!(
        formatted.contains("jti-1") && formatted.contains("weather"),
        "redaction must still leave a Payload diagnosable: {formatted}"
    );
}

#[test]
fn a_wrong_binding_of_any_length_is_refused_identically() {
    // The behavioural half of the constant-time fix. Stated as what it
    // proves: this row cannot observe timing, and it passes against the
    // short-circuiting implementation too — verified by running it against
    // one. The timing property itself is a code-shape property, asserted by
    // reading `redeemable_by`, and it is recorded that way rather than
    // dressed up as a test that catches it.
    let sealed = payload();
    for wrong in ["", "x", "sha256:caller-", "sha256:caller-a-and-then-some"] {
        assert_eq!(
            sealed.redeemable_by(wrong, "sha256:req-1"),
            Err(ContinuationError::NotAuthentic),
            "a wrong principal of any length must be refused identically"
        );
    }
    assert_eq!(
        sealed.redeemable_by("sha256:caller-a", "sha256:req-1"),
        Ok(())
    );
}

#[test]
fn a_keyring_refuses_two_keys_sharing_one_id() {
    // Lookup takes the first match, so a duplicate id silently shadows a key
    // that is still expected to verify. The failure surfaces one replica at
    // a time, on envelopes minted before the deploy — the worst possible
    // shape for a configuration error.
    assert_eq!(
        Keyring::new(&[(1, [7u8; 32]), (1, [9u8; 32])]).err(),
        Some(ContinuationError::Malformed),
        "a keyring with a duplicated key id must be refused at construction"
    );
    assert!(Keyring::new(&[(1, [7u8; 32]), (2, [9u8; 32])]).is_ok());
}

#[test]
fn a_refusal_shown_to_a_client_names_no_key_or_version() {
    // The internal cause stays for the operator; the client is told only
    // that the continuation was refused. Reporting *which* key id or wire
    // version was wrong lets a caller map the active keyring and the build,
    // one probe at a time.
    for internal in [
        ContinuationError::UnknownKey(3),
        ContinuationError::UnknownVersion(9),
        ContinuationError::NotAuthentic,
        ContinuationError::Expired,
        ContinuationError::Malformed,
    ] {
        let shown = internal.client_message();
        assert!(
            !shown.contains('3') && !shown.contains('9'),
            "a client-facing refusal must not fingerprint the keyring: {shown}"
        );
    }
    // The operator still gets the detail.
    assert!(ContinuationError::UnknownKey(3).to_string().contains('3'));
}

#[tokio::test]
async fn the_ledger_refuses_a_new_entry_rather_than_forget_a_live_one() {
    // At capacity there are two ways to stay bounded: forget something
    // already spent, or refuse something new. Forgetting reopens a replay
    // window on a continuation whose envelope still opens — the exact
    // property this ledger exists to hold. Refusing costs a caller one
    // retry. The bounded-ness test alone cannot tell these apart, which is
    // why it is not the only row.
    let ledger = ConsumedLedger::new(2);
    assert!(ledger.consume("jti-a", 9_999, 1_000).await);
    assert!(ledger.consume("jti-b", 9_999, 1_000).await);

    assert!(
        !ledger.consume("jti-c", 9_999, 1_000).await,
        "a full ledger must refuse a new continuation, not evict a live one"
    );
    assert!(
        !ledger.consume("jti-a", 9_999, 1_000).await,
        "the entries already spent must still be remembered as spent"
    );
    assert!(!ledger.consume("jti-b", 9_999, 1_000).await);
}

#[tokio::test]
async fn expired_entries_are_reclaimed_before_a_refusal() {
    // Refusing while holding entries nobody can replay would be a denial of
    // service dressed as caution.
    let ledger = ConsumedLedger::new(2);
    assert!(ledger.consume("jti-old", 1_000, 1_000).await);
    assert!(ledger.consume("jti-live", 9_999, 1_000).await);

    assert!(
        ledger.consume("jti-new", 9_999, 5_000).await,
        "capacity held by an expired entry must be reclaimed, not refused"
    );
    assert!(
        !ledger.consume("jti-live", 9_999, 5_000).await,
        "reclaiming must take the expired entry, never the live one"
    );
}

#[tokio::test]
async fn a_completed_exchange_releases_its_capacity() {
    // Without an explicit completion, capacity counts every exchange ever
    // started until its deadline passes, so a healthy gateway refuses new
    // elicitations because of ones that finished long ago.
    let table = InFlight::new("gw-1", 1);
    let key = table
        .hold(
            "weather",
            &mcp_gateway::protocol::continuation::QuotaKey::new(
                mcp_gateway::protocol::continuation::QuotaSource::KeyName("test"),
            ),
            9_999,
            0,
        )
        .await
        .expect("capacity");
    assert!(
        table
            .hold(
                "weather",
                &mcp_gateway::protocol::continuation::QuotaKey::new(
                    mcp_gateway::protocol::continuation::QuotaSource::KeyName("test")
                ),
                9_999,
                0
            )
            .await
            .is_none()
    );

    assert!(
        table.complete(&key, 0).await,
        "completing must report the release"
    );
    assert!(
        table
            .hold(
                "weather",
                &mcp_gateway::protocol::continuation::QuotaKey::new(
                    mcp_gateway::protocol::continuation::QuotaSource::KeyName("test")
                ),
                9_999,
                0
            )
            .await
            .is_some(),
        "a finished exchange must return its slot"
    );
    assert!(
        !table.complete("no-such-key", 0).await,
        "completing an unknown exchange must report that it released nothing"
    );
}

#[tokio::test]
async fn a_completed_exchange_is_gone_for_routing() {
    let table = InFlight::new("gw-1", 4);
    let key = table
        .hold(
            "weather",
            &mcp_gateway::protocol::continuation::QuotaKey::new(
                mcp_gateway::protocol::continuation::QuotaSource::KeyName("test"),
            ),
            9_999,
            0,
        )
        .await
        .expect("capacity");
    assert!(table.complete(&key, 0).await);

    assert!(
        matches!(table.route(&key, 0).await, Routing::Gone),
        "a retry against a finished exchange must fail explicitly"
    );
}

// Multi-threaded on purpose: on a current-thread runtime the lock is never
// held across an await, so a `try_lock` implementation would never collide
// and this row could not fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routing_waits_for_the_lock_rather_than_reporting_the_exchange_gone() {
    // `Gone` means the exchange no longer exists, and a caller acts on it by
    // failing the retry. Answering it for a lock held by a concurrent reaper
    // turns ordinary contention into a lost elicitation, which is precisely
    // what the routing table exists to prevent.
    use std::sync::Arc;

    let table = Arc::new(InFlight::new("gw-1", 4));
    let key = table
        .hold(
            "weather",
            &mcp_gateway::protocol::continuation::QuotaKey::new(
                mcp_gateway::protocol::continuation::QuotaSource::KeyName("test"),
            ),
            9_999,
            0,
        )
        .await
        .expect("capacity");

    // Hammer routing while reclamation runs concurrently: `hold` takes the same
    // lock, so a `try_lock` implementation reports `Gone` for an exchange
    // that is plainly still held.
    let reaper = {
        let table = Arc::clone(&table);
        tokio::spawn(async move {
            for _ in 0..500 {
                table
                    .hold(
                        "weather",
                        &mcp_gateway::protocol::continuation::QuotaKey::new(
                            mcp_gateway::protocol::continuation::QuotaSource::KeyName("test"),
                        ),
                        9_999,
                        0,
                    )
                    .await;
                tokio::task::yield_now().await;
            }
        })
    };
    for _ in 0..500 {
        assert!(
            matches!(table.route(&key, 0).await, Routing::Here),
            "a held exchange must route to its holder even under contention"
        );
        tokio::task::yield_now().await;
    }
    reaper.await.expect("reaper");
}
