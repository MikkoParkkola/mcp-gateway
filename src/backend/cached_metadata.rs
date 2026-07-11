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
