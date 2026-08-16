// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Generic single-flight TTL cache used by [`super::Backend`] for the four
//! metadata lists (tools/resources/resource-templates/prompts).

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::sync::watch;

use crate::Result;

pub(crate) struct CachedMetadata<T> {
    state: RwLock<CachedMetadataState<T>>,
}

struct CachedMetadataState<T> {
    value: Option<Arc<T>>,
    cached_at: Option<Instant>,
    in_flight: Option<watch::Sender<()>>,
}

impl<T> Default for CachedMetadataState<T> {
    fn default() -> Self {
        Self {
            value: None,
            cached_at: None,
            in_flight: None,
        }
    }
}

enum CacheFetchState<'a, T> {
    Cached(Arc<T>),
    Wait(watch::Receiver<()>),
    Fetch(FetchPermit<'a, T>),
}

struct FetchPermit<'a, T> {
    cache: &'a CachedMetadata<T>,
    sender: watch::Sender<()>,
}

impl<T> Drop for FetchPermit<'_, T> {
    fn drop(&mut self) {
        self.cache.state.write().in_flight = None;
        let _ = self.sender.send(());
    }
}

impl<T> CachedMetadata<T> {
    pub(crate) fn new() -> Self {
        Self {
            state: RwLock::new(CachedMetadataState::default()),
        }
    }

    pub(crate) fn with_cached<R>(&self, map: impl FnOnce(Option<&Arc<T>>) -> R) -> R {
        let state = self.state.read();
        map(state.value.as_ref())
    }

    pub(crate) fn is_fresh(&self, ttl: Duration) -> bool {
        let state = self.state.read();
        matches!(
            (&state.value, state.cached_at),
            (Some(_), Some(cached_at)) if cached_at.elapsed() < ttl
        )
    }

    pub(crate) fn snapshot_shared(&self) -> Option<Arc<T>> {
        let state = self.state.read();
        state.value.clone()
    }

    pub(super) fn store_shared(&self, value: Arc<T>) {
        let mut state = self.state.write();
        state.value = Some(value);
        state.cached_at = Some(Instant::now());
    }

    /// Forget the cached value only if it still satisfies `discard`.
    ///
    /// Exists because a cached answer cannot otherwise be re-asked, and one
    /// answer needs re-asking: an EMPTY tool list. It is stored with a fresh
    /// timestamp like any other, so a caller that retries reads the same empty
    /// list back within microseconds and never reaches the backend at all --
    /// the retry looks like diligence and is a no-op.
    ///
    /// CONDITIONAL, deliberately, and there is no unconditional form. Clearing
    /// whatever is there races with a real cost, raised in review: a caller that
    /// observed an EMPTY list, then invalidated, could erase a non-empty list
    /// another reader had populated in between -- turning a backend that had
    /// just become discoverable back into an invisible one. The predicate runs
    /// under the same write lock as the clear, so nothing slips between the
    /// decision and the effect.
    ///
    /// Deliberately does NOT cancel an in-flight fetch: that fetch is already
    /// going to the backend, which is what the caller wanted.
    pub(super) fn invalidate_if(&self, discard: impl Fn(&T) -> bool) {
        let mut state = self.state.write();
        let should_clear = state.value.as_ref().is_some_and(|v| discard(v));
        if should_clear {
            state.value = None;
            state.cached_at = None;
        }
    }

    fn acquire(&self, ttl: Duration) -> CacheFetchState<'_, T> {
        {
            let state = self.state.read();
            if let Some(value) = Self::fresh_value(&state, ttl) {
                return CacheFetchState::Cached(value);
            }
            if let Some(sender) = state.in_flight.as_ref() {
                return CacheFetchState::Wait(sender.subscribe());
            }
        }

        let mut state = self.state.write();
        if let Some(value) = Self::fresh_value(&state, ttl) {
            return CacheFetchState::Cached(value);
        }
        if let Some(sender) = state.in_flight.as_ref() {
            return CacheFetchState::Wait(sender.subscribe());
        }

        let (sender, _receiver) = watch::channel(());
        state.in_flight = Some(sender.clone());
        CacheFetchState::Fetch(FetchPermit {
            cache: self,
            sender,
        })
    }

    pub(crate) async fn get_or_fetch_shared<F, Fut>(
        &self,
        ttl: Duration,
        fetch: F,
    ) -> Result<Arc<T>>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        loop {
            match self.acquire(ttl) {
                CacheFetchState::Cached(value) => return Ok(value),
                CacheFetchState::Wait(mut receiver) => {
                    let _ = receiver.changed().await;
                }
                CacheFetchState::Fetch(permit) => {
                    let result = fetch().await.map(Arc::new);
                    if let Ok(value) = &result {
                        self.store_shared(Arc::clone(value));
                    }
                    drop(permit);
                    return result;
                }
            }
        }
    }

    fn fresh_value(state: &CachedMetadataState<T>, ttl: Duration) -> Option<Arc<T>> {
        if let (Some(value), Some(cached_at)) = (&state.value, state.cached_at)
            && cached_at.elapsed() < ttl
        {
            return Some(Arc::clone(value));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::CachedMetadata;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    const LONG_TTL: Duration = Duration::from_secs(300);

    #[tokio::test]
    async fn an_empty_result_is_cached_like_any_other() {
        // The behaviour that made a retry meaningless, pinned so the fix below
        // is understood as deliberate rather than incidental.
        let cache: CachedMetadata<Vec<u8>> = CachedMetadata::new();
        let calls = Arc::new(AtomicU32::new(0));

        for _ in 0..3 {
            let seen = Arc::clone(&calls);
            let _ = cache
                .get_or_fetch_shared(LONG_TTL, || {
                    let seen = Arc::clone(&seen);
                    async move {
                        seen.fetch_add(1, Ordering::SeqCst);
                        Ok(Vec::new())
                    }
                })
                .await;
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "an empty result is served from cache, so retrying never re-asks"
        );
    }

    #[tokio::test]
    async fn invalidate_makes_the_next_call_reach_the_backend() {
        let cache: CachedMetadata<Vec<u8>> = CachedMetadata::new();
        let calls = Arc::new(AtomicU32::new(0));

        for round in 0..3 {
            if round > 0 {
                cache.invalidate_if(Vec::is_empty);
            }
            let seen = Arc::clone(&calls);
            let _ = cache
                .get_or_fetch_shared(LONG_TTL, || {
                    let seen = Arc::clone(&seen);
                    async move {
                        seen.fetch_add(1, Ordering::SeqCst);
                        Ok(Vec::new())
                    }
                })
                .await;
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "each invalidated round must actually ask the backend again"
        );
    }

    #[tokio::test]
    async fn invalidate_if_never_erases_a_value_that_no_longer_matches() {
        // Raised in review, and it is the dangerous direction: a caller that
        // observed an EMPTY list and then invalidated could erase a non-empty
        // list another reader had populated in between -- turning a backend
        // that had just become discoverable back into an invisible one.
        let cache: CachedMetadata<Vec<u8>> = CachedMetadata::new();
        let _ = cache
            .get_or_fetch_shared(LONG_TTL, || async { Ok(vec![1u8, 2, 3]) })
            .await;

        cache.invalidate_if(Vec::is_empty);

        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);
        let value = cache
            .get_or_fetch_shared(LONG_TTL, || {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Ok(Vec::new())
                }
            })
            .await
            .expect("the populated value must survive");

        assert_eq!(*value, vec![1u8, 2, 3], "a populated list was erased");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "and it should not have refetched"
        );
    }

    #[tokio::test]
    async fn invalidate_on_an_empty_cache_is_harmless() {
        let cache: CachedMetadata<Vec<u8>> = CachedMetadata::new();
        cache.invalidate_if(Vec::is_empty);

        let value = cache
            .get_or_fetch_shared(LONG_TTL, || async { Ok(vec![1u8, 2, 3]) })
            .await
            .expect("fetch after a no-op invalidate");

        assert_eq!(*value, vec![1u8, 2, 3]);
    }
}
