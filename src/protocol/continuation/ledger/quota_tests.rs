// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8293: the in-flight table's per-caller share. Rows on `InFlight::hold`
//! itself, the one place a slot is taken, so a mutant that weakens the share
//! anywhere is red here whatever route reached it.

use super::{IN_FLIGHT_CAPACITY, InFlight};
use crate::protocol::continuation::{PRINCIPAL_SLOTS, QuotaKey};

/// Before any deadline this module sets.
const T: u64 = 1_000;

fn key(name: &str) -> QuotaKey {
    QuotaKey::for_test(name)
}

/// Fill `quota`'s share of a full-size table, every hold live past `T`.
async fn fill(table: &InFlight, quota: &QuotaKey) -> Vec<String> {
    let mut held = Vec::with_capacity(PRINCIPAL_SLOTS);
    for i in 0..PRINCIPAL_SLOTS {
        let deadline = T + 100 + u64::try_from(i).expect("small");
        held.push(
            table
                .hold("backend", quota, deadline, T)
                .await
                .expect("setup: within the caller's share"),
        );
    }
    held
}

/// P1 (design D3): the share is 1/64 of the pool, 64 slots. Pinned beside the
/// capacity pin so the two cannot drift apart. Mutant m3's neighbour: a share
/// that is no longer derived from the capacity.
#[test]
fn p1_the_share_is_one_sixty_fourth_of_the_pool() {
    assert_eq!(IN_FLIGHT_CAPACITY, 4_096);
    assert_eq!(PRINCIPAL_SLOTS, 64);
}

/// S5 (SLOTQ.1, SLOTQ.5): at the chokepoint, alice is refused her 65th slot
/// and bob, on the same table, is not. Mutants: m1 (no share check), m2 (one
/// count for every key), m3 (`>` for `>=`, which admits a 65th).
#[tokio::test]
async fn s5_a_caller_is_refused_past_its_share_and_another_is_not() {
    let table = InFlight::new("gw-1", IN_FLIGHT_CAPACITY);
    let (alice, bob) = (key("alice"), key("bob"));
    fill(&table, &alice).await;
    assert!(
        table.hold("backend", &alice, T + 100, T).await.is_none(),
        "alice's 65th slot was granted"
    );
    assert!(
        table.hold("backend", &bob, T + 100, T).await.is_some(),
        "bob was refused for alice's share"
    );
    assert_eq!(table.len(T).await, PRINCIPAL_SLOTS + 1);
}

/// S5b: a table smaller than the share caps a caller at its capacity, so the
/// existing full-table rows keep their meaning.
#[tokio::test]
async fn s5b_a_small_table_caps_a_caller_at_its_capacity() {
    let table = InFlight::new("gw-1", 4);
    let alice = key("alice");
    for _ in 0..4 {
        assert!(table.hold("backend", &alice, T + 10, T).await.is_some());
    }
    assert!(table.hold("backend", &alice, T + 10, T).await.is_none());
}

/// S4c (SLOTQ.4): each way a slot is freed returns alice's share: `complete`,
/// `try_complete`, and her holds expiring. Mutant m9: a count that includes
/// expired holds keeps her refused after expiry.
#[tokio::test]
async fn s4c_every_free_returns_the_callers_share() {
    let table = InFlight::new("gw-1", IN_FLIGHT_CAPACITY);
    let alice = key("alice");
    let held = fill(&table, &alice).await;
    assert!(
        table.hold("backend", &alice, T + 100, T).await.is_none(),
        "setup: at the share"
    );

    assert!(
        table.complete(&held[0], T).await,
        "setup: complete frees a held slot"
    );
    assert!(
        table.hold("backend", &alice, T + 100, T).await.is_some(),
        "complete did not return alice's share"
    );

    assert_eq!(
        table.try_complete(&held[1]),
        Some(true),
        "setup: try_complete frees a slot"
    );
    assert!(
        table.hold("backend", &alice, T + 100, T).await.is_some(),
        "try_complete did not return alice's share"
    );

    // Past every deadline `fill` set (the latest is T + 100 + 63).
    let later = T + 1_000;
    assert!(
        table
            .hold("backend", &alice, later + 100, later)
            .await
            .is_some(),
        "expiry did not return alice's share"
    );
    assert_eq!(table.len(later).await, 1, "only the new hold is live");
}

/// S7 (SLOTQ.1): the pool's own bound still holds under the share. With
/// capacity 4, alice and bob take two each and carol is refused although her
/// share is untouched. Mutant m10: the global capacity check removed.
#[tokio::test]
async fn s7_the_global_bound_still_applies() {
    let table = InFlight::new("gw-1", 4);
    for quota in [key("alice"), key("alice"), key("bob"), key("bob")] {
        assert!(
            table.hold("backend", &quota, T + 10, T).await.is_some(),
            "setup"
        );
    }
    assert!(
        table
            .hold("backend", &key("carol"), T + 10, T)
            .await
            .is_none(),
        "a full pool admitted carol"
    );
}
