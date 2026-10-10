// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8293 S4b: a hold released by the MIK-8176 request scope gives the
//! caller's slot back under the per-caller cap.

use std::sync::Arc;

use crate::protocol::continuation::{ContinuationState, now_unix_secs};

/// The per-caller cap the rows expect (design r3 D3).
const CAP: usize = 64;

/// Take one slot as `fingerprint` and register it in the open scope, unsent.
async fn take(continuation: &Arc<ContinuationState>, fingerprint: &str) -> bool {
    let now = now_unix_secs();
    let Some(payload) = continuation
        .begin_exchange(
            "alpha".into(),
            None,
            fingerprint.to_owned(),
            "digest".into(),
            now,
        )
        .await
    else {
        return false;
    };
    super::sealed_hold::register(continuation, &payload.hold_key, "env-unsent");
    true
}

/// Occupancy, polled briefly: a release on a contended table completes on the
/// runtime rather than in place (`sealed_hold::release`).
async fn settled_len(continuation: &ContinuationState, want: usize) -> usize {
    let mut len = continuation.in_flight().len(now_unix_secs()).await;
    for _ in 0..50 {
        if len == want {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        len = continuation.in_flight().len(now_unix_secs()).await;
    }
    len
}

/// S4b (SLOTQ.4): inside one request scope, alice takes her 64 slots and her
/// 65th is refused. The scope ends with nothing handed off, so MIK-8176
/// releases every hold through `InFlight::complete`, and her next slot is
/// served. Red on base: the 65th is served. Mutant m9-family: a count that
/// ignores released holds keeps her refused.
#[tokio::test]
async fn s4b_a_scope_release_frees_slots_under_the_cap() {
    let continuation = Arc::new(ContinuationState::new());
    let refused_65th = super::sealed_hold::scoped(async {
        for i in 0..CAP {
            assert!(
                take(&continuation, "alice").await,
                "setup: slot {i} refused"
            );
        }
        assert_eq!(
            continuation.in_flight().len(now_unix_secs()).await,
            CAP,
            "setup: alice's slots are held"
        );
        !take(&continuation, "alice").await
    })
    .await;
    assert!(refused_65th, "alice's 65th slot was served");

    assert_eq!(
        settled_len(&continuation, 0).await,
        0,
        "setup: the scope released nothing"
    );
    assert!(
        take(&continuation, "alice").await,
        "a released slot was not reusable"
    );
}
