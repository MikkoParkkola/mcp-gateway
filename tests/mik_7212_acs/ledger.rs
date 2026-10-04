// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::sync::Arc;

use mcp_gateway::protocol::continuation::ConsumedLedger;

#[tokio::test]
async fn ac_mrtr_5_a_continuation_redeems_once() {
    let ledger = ConsumedLedger::new(1_000);
    assert!(
        ledger.consume("jti-1", 2_000, 1_000).await,
        "first redemption wins"
    );
    assert!(
        !ledger.consume("jti-1", 2_000, 1_000).await,
        "a replay must be refused"
    );
}

#[tokio::test]
async fn ac_mrtr_5_two_racing_redemptions_produce_exactly_one_winner() {
    // Check-then-consume as two steps loses this: both callers check, both
    // see it unconsumed, and a destructive continuation runs twice. The
    // race is the test — a sequential pair would pass either way.
    let ledger = Arc::new(ConsumedLedger::new(1_000));
    let mut handles = Vec::new();
    for _ in 0..16 {
        let ledger = Arc::clone(&ledger);
        handles.push(tokio::spawn(async move {
            tokio::task::yield_now().await;
            ledger.consume("jti-race", 2_000, 1_000).await
        }));
    }
    let mut winners = 0;
    for handle in handles {
        if handle.await.expect("task must not panic") {
            winners += 1;
        }
    }
    assert_eq!(winners, 1, "exactly one redemption may succeed");
}

#[tokio::test]
async fn ac_mrtr_8_the_ledger_is_bounded_and_evicts_on_expiry() {
    // A client that starts continuations and walks away is the common case:
    // the spec says a server MUST NOT assume the client will retry. An
    // unbounded ledger keyed on abandonment is a memory-exhaustion vector
    // reachable by any client.
    let ledger = ConsumedLedger::new(1_000);
    for n in 0..500 {
        ledger.consume(&format!("jti-{n}"), 2_000, 1_000).await;
    }
    assert_eq!(ledger.len().await, 500);

    // Past every deadline, the entries go.
    ledger.evict_expired(2_001).await;
    assert_eq!(
        ledger.len().await,
        0,
        "entries must not outlive the continuations they guard"
    );
}

#[tokio::test]
async fn ac_mrtr_8_the_ledger_refuses_to_grow_without_limit() {
    // Even before anything expires. Eviction on a deadline is not a bound
    // when the attacker chooses the arrival rate.
    let ledger = ConsumedLedger::new(64);
    for n in 0..1_000 {
        ledger.consume(&format!("jti-{n}"), 9_999, 1_000).await;
    }
    assert!(
        ledger.len().await <= 64,
        "the ledger must hold its capacity against an unbounded arrival rate"
    );
}

#[tokio::test]
async fn ac_mrtr_5_retention_outlives_the_continuation_it_guards() {
    // A ledger that forgets before the envelope expires is a replay window
    // with extra steps: the envelope still opens, and nothing remembers it
    // was spent.
    let ledger = ConsumedLedger::new(1_000);
    assert!(ledger.consume("jti-live", 2_000, 1_000).await);
    ledger.evict_expired(1_999).await;
    assert!(
        !ledger.consume("jti-live", 2_000, 1_000).await,
        "an unexpired continuation must still be remembered as spent"
    );
}
