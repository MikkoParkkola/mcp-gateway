// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8399 S16: the single-flight permit runs its abandon hook once when
//! the fill gives no answer, never when it answers, and not when the
//! generation moved. The hook runs under the cache's write guard together
//! with the `in_flight` clear, so no newer fill or store can interleave; it
//! therefore must not read this cache's state, and these hooks only count.

use std::sync::Arc;
use std::time::Duration;

use super::{AbandonHook, CachedMetadata};

type Cache = CachedMetadata<Vec<u8>>;

/// A hook that records each run.
fn recording(_cache: &Arc<Cache>) -> (AbandonHook, Arc<parking_lot::Mutex<Vec<bool>>>) {
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let hook: AbandonHook = Box::new(move || log.lock().push(true));
    (hook, seen)
}

const TTL: Duration = Duration::from_secs(600);

/// S16: a fill that errors runs the hook exactly once, before the flight
/// clears.
#[tokio::test]
async fn s16_an_errored_fill_runs_its_hook_once() {
    let cache = Arc::new(Cache::new());
    let (hook, seen) = recording(&cache);
    let result = cache
        .get_or_fetch_shared_then(
            TTL,
            |_| async { Err::<(Vec<u8>, ()), _>(crate::Error::Transport("lost".into())) },
            |()| {},
            |_| {},
            Some(hook),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(*seen.lock(), vec![true], "the hook ran once");
    assert!(!cache.fill_in_flight(), "and the flight cleared after it");
}

/// S16, success: an answered fill never runs the hook.
#[tokio::test]
async fn s16_an_answered_fill_never_runs_its_hook() {
    let cache = Arc::new(Cache::new());
    let (hook, seen) = recording(&cache);
    cache
        .get_or_fetch_shared_then(
            TTL,
            |_| async { Ok((vec![1u8], ())) },
            |()| {},
            |_| {},
            Some(hook),
        )
        .await
        .expect("the fill answers");
    assert!(seen.lock().is_empty());
}

/// S16, cancellation: a fill whose future is dropped runs the hook once,
/// inside the flight.
#[tokio::test]
async fn s16_a_dropped_fill_runs_its_hook_once() {
    let cache = Arc::new(Cache::new());
    let (hook, seen) = recording(&cache);
    let started = Arc::new(tokio::sync::Notify::new());
    let task = tokio::spawn({
        let (cache, started) = (Arc::clone(&cache), Arc::clone(&started));
        async move {
            cache
                .get_or_fetch_shared_then(
                    TTL,
                    |_| {
                        let started = Arc::clone(&started);
                        async move {
                            started.notify_one();
                            std::future::pending::<crate::Result<(Vec<u8>, ())>>().await
                        }
                    },
                    |()| {},
                    |_| {},
                    Some(hook),
                )
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(30), started.notified())
        .await
        .expect("the fetch started");
    task.abort();
    let _ = task.await;
    assert_eq!(*seen.lock(), vec![true]);
    assert!(!cache.fill_in_flight());
}

/// S16, generation: an invalidation during an errored fill means newer
/// state was supplied, so the hook stands down.
#[tokio::test]
async fn s16_a_fill_whose_generation_moved_does_not_run_its_hook() {
    let cache = Arc::new(Cache::new());
    let (hook, seen) = recording(&cache);
    let result = cache
        .get_or_fetch_shared_then(
            TTL,
            |_| {
                let cache = Arc::clone(&cache);
                async move {
                    cache.invalidate_then(|| {});
                    Err::<(Vec<u8>, ()), _>(crate::Error::Transport("lost".into()))
                }
            },
            |()| {},
            |_| {},
            Some(hook),
        )
        .await;
    assert!(result.is_err());
    assert!(seen.lock().is_empty(), "a moved generation ran the hook");
}

/// S16, success with a moved generation: an answered fill never runs its
/// hook, even when an invalidation ran while it fetched.
#[tokio::test]
async fn s16_an_answered_fill_whose_generation_moved_never_runs_its_hook() {
    let cache = Arc::new(Cache::new());
    let (hook, seen) = recording(&cache);
    cache
        .get_or_fetch_shared_then(
            TTL,
            |_| {
                let cache = Arc::clone(&cache);
                async move {
                    cache.invalidate_then(|| {});
                    Ok((vec![1u8], ()))
                }
            },
            |()| {},
            |_| {},
            Some(hook),
        )
        .await
        .expect("the fill answers");
    assert!(seen.lock().is_empty());
}
