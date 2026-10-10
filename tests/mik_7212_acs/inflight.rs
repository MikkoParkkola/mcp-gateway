// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::sync::Arc;

use mcp_gateway::protocol::continuation::{InFlight, Routing};

#[tokio::test]
async fn ac_mrtr_6_a_retry_reaching_the_holding_replica_is_served_here() {
    let table = InFlight::new("gw-1", 100);
    let key = table
        .hold(
            "weather",
            &mcp_gateway::protocol::continuation::QuotaKey::new(
                mcp_gateway::protocol::continuation::QuotaSource::KeyName("test"),
            ),
            2_000,
            0,
        )
        .await
        .expect("capacity");

    assert!(matches!(table.route(&key, 0).await, Routing::Here));
}

#[tokio::test]
async fn ac_mrtr_6_a_retry_landing_on_another_replica_fails_explicitly() {
    // MRTR.6 offers two arms — reach the replica holding the exchange, OR
    // fail explicitly — and the accepted design took the second: the
    // cross-replica guarantee holds cryptographically, with no shared store
    // and no affinity. This is that arm, at the boundary where it matters.
    //
    // Not started afresh, which is the outcome the criterion forbids:
    // beginning a second exchange would leave the first hanging on another
    // replica and ask the user the same question twice — and for a
    // destructive tool, the second answer would authorise a call the first
    // one already authorised. `Gone` is a refusal the client can act on.
    //
    // Two tables, because that is what two replicas are: `InFlight` is per
    // process with no shared store. A single table cannot stage this — it
    // would have to be asked about a key it minted itself, which is the
    // same-replica case one test up.
    let minting = InFlight::new("gw-1", 100);
    let receiving = InFlight::new("gw-2", 100);
    let key = minting
        .hold(
            "weather",
            &mcp_gateway::protocol::continuation::QuotaKey::new(
                mcp_gateway::protocol::continuation::QuotaSource::KeyName("test"),
            ),
            2_000,
            0,
        )
        .await
        .expect("capacity");

    assert!(
        matches!(receiving.route(&key, 0).await, Routing::Gone),
        "a retry for an exchange another replica holds is refused, never restarted"
    );
    // AND the exchange is still open where it was minted: the refusal above
    // must be the receiving replica not knowing, never the exchange having
    // been consumed or invalidated by the attempt.
    assert!(
        matches!(minting.route(&key, 0).await, Routing::Here),
        "the minting replica still holds the exchange after a foreign retry"
    );
}

#[tokio::test]
async fn ac_mrtr_6_an_unknown_exchange_fails_explicitly() {
    // The replica that held it died, or the entry was evicted. Either way
    // the honest answer is a refusal the client can act on — never a silent
    // second exchange.
    let table = InFlight::new("gw-1", 100);
    assert!(matches!(table.route("no-such-key", 0).await, Routing::Gone));
}

#[tokio::test]
async fn ac_mrtr_8_the_table_is_bounded() {
    // A client may abandon a continuation, and the specification says a
    // server MUST NOT assume otherwise. So entries arrive at a rate the
    // client sets, and refusing at capacity is the difference between a
    // bounded table and a memory-exhaustion vector.
    let table = InFlight::new("gw-1", 4);
    for _ in 0..4 {
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
                .is_some()
        );
    }
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
            .is_none(),
        "at capacity the gateway must refuse to start a new exchange rather \
         than grow, and refusing is what the caller turns into an error the \
         client can see"
    );
}

#[tokio::test]
async fn ac_mrtr_8_an_abandoned_exchange_is_reclaimed() {
    let table = InFlight::new("gw-1", 4);
    let key = table
        .hold(
            "weather",
            &mcp_gateway::protocol::continuation::QuotaKey::new(
                mcp_gateway::protocol::continuation::QuotaSource::KeyName("test"),
            ),
            1_000,
            0,
        )
        .await
        .expect("capacity");
    for _ in 1..4 {
        table
            .hold(
                "weather",
                &mcp_gateway::protocol::continuation::QuotaKey::new(
                    mcp_gateway::protocol::continuation::QuotaSource::KeyName("test"),
                ),
                1_000,
                0,
            )
            .await
            .expect("capacity");
    }

    // The table is full of exchanges nobody came back for. A caller
    // arriving after their deadline must still get a slot -- reclamation
    // happens on the path that enforces the bound, so there is no reaper
    // to forget to call.
    assert!(
        table
            .hold(
                "weather",
                &mcp_gateway::protocol::continuation::QuotaKey::new(
                    mcp_gateway::protocol::continuation::QuotaSource::KeyName("test")
                ),
                9_999,
                1_001
            )
            .await
            .is_some(),
        "a table full of abandoned exchanges must reclaim rather than refuse"
    );
    assert!(
        matches!(table.route(&key, 1_001).await, Routing::Gone),
        "an abandoned exchange must not hold its slot forever"
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
        "and its slot must come back"
    );
}

#[tokio::test]
async fn ac_mrtr_6_the_key_is_not_something_the_client_chooses() {
    // Two exchanges for the same backend must not collide, and a client
    // must not be able to name someone else's.
    let table = Arc::new(InFlight::new("gw-1", 100));
    let a = table
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
    let b = table
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
    assert_ne!(a, b, "each exchange gets its own key");
}
