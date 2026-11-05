// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A0 cells on the meta route (`gateway_invoke`): two callers never share a
//! cached or stored idempotent result (moved from `a0_per_caller_cache.rs`).

use super::*;

/// T1 — two API keys, same tool and arguments, response cache on: the second
/// key must not be served the first key's cached result.
#[tokio::test]
async fn meta_route_cache_does_not_serve_one_api_key_callers_result_to_another() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, _dir) = gateway(Setup::two_keys(true), &calls).await;

    let (a, b) = resolved(async {
        let a = post_meta(&state, 1, Some("k-1"), with_key(ALICE)).await;
        (a, post_meta(&state, 2, Some("k-2"), with_key(BOB)).await)
    })
    .await;
    ok("alice", &a);
    ok("bob", &b);

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "bob hit alice's entry: {}",
        b.1
    );
    assert_eq!(delivery(&b.1).as_deref(), Some("call-2"), "bob: {}", b.1);
}

/// T2 — positive control: one key repeating itself still hits the cache.
#[tokio::test]
async fn meta_route_same_api_key_still_hits_cache() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, _dir) = gateway(Setup::two_keys(true), &calls).await;

    let (first, second) = resolved(async {
        let first = post_meta(&state, 1, Some("k-1"), with_key(ALICE)).await;
        (
            first,
            post_meta(&state, 2, Some("k-2"), with_key(ALICE)).await,
        )
    })
    .await;
    ok("first", &first);
    ok("second", &second);

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the repeat missed the cache"
    );
    assert_eq!(delivery(&second.1).as_deref(), Some("call-1"));
}

/// T3 — two API keys, one idempotency key, response cache OFF so only the
/// retry key can separate or pool them: no replay across keys.
#[tokio::test]
async fn meta_route_idempotency_key_does_not_replay_across_api_keys() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, _dir) = gateway(Setup::two_keys(false), &calls).await;

    let (a, b) = resolved(async {
        let a = post_meta(&state, 1, Some("shared"), with_key(ALICE)).await;
        (a, post_meta(&state, 2, Some("shared"), with_key(BOB)).await)
    })
    .await;
    ok("alice", &a);
    ok("bob", &b);

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "bob replayed alice: {}",
        b.1
    );
    assert_eq!(delivery(&b.1).as_deref(), Some("call-2"));
}

/// T3b — positive control, response cache OFF: one key sending one
/// idempotency key twice is deduplicated by the guard. Fails for an
/// implementation that skips the guard for every authenticated caller.
#[tokio::test]
async fn meta_route_same_api_key_idempotency_key_still_deduplicates() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, _dir) = gateway(Setup::two_keys(false), &calls).await;

    let (first, second) = resolved(async {
        let first = post_meta(&state, 1, Some("k1"), with_key(ALICE)).await;
        (
            first,
            post_meta(&state, 2, Some("k1"), with_key(ALICE)).await,
        )
    })
    .await;
    ok("first", &first);
    ok("second", &second);

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the keyed repeat ran twice"
    );
    assert_eq!(delivery(&second.1).as_deref(), Some("call-1"));
}
