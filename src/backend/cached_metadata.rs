// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Generic single-flight TTL cache used by [`super::Backend`] for the four
//! metadata lists (tools/resources/resource-templates/prompts).

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::sync::watch;

use crate::Result;

pub(crate) struct CachedMetadata<T> {
    state: RwLock<CachedMetadataState<T>>,
    /// Told after every accepted store, whichever writer made it (`MIK-8127`):
    /// set once, on a backend's shared tool slot only.
    store_observer: std::sync::OnceLock<StoreObserver>,
}

/// One fill's mark, opaque here: handed to the fill's fetch and to every
/// caller that waits on that fill, never to another fill (MIK-8046).
pub(crate) type FillMark = Arc<AtomicBool>;

/// What [`CachedMetadata::observe_stores`] runs after an accepted store.
pub(crate) type StoreObserver = Arc<dyn Fn() + Send + Sync>;

struct CachedMetadataState<T> {
    value: Option<Arc<T>>,
    cached_at: Option<Instant>,
    in_flight: Option<(watch::Sender<()>, FillMark)>,
    /// Bumped by every invalidation. A fill stores its answer only if the
    /// generation it started under is still current, so an invalidation that
    /// lands mid-fill voids that fill instead of being overwritten by it
    /// (MIK-7334.CATALOGUE.1, "changes and revocation").
    generation: u64,
    /// Sticky: never cleared by `invalidate_if`.
    ever_populated: bool,
}

impl<T> Default for CachedMetadataState<T> {
    fn default() -> Self {
        Self {
            value: None,
            cached_at: None,
            in_flight: None,
            generation: 0,
            ever_populated: false,
        }
    }
}

enum CacheFetchState<'a, T> {
    Cached(Arc<T>),
    Wait(watch::Receiver<()>, FillMark),
    Fetch(FetchPermit<'a, T>),
}

struct FetchPermit<'a, T> {
    cache: &'a CachedMetadata<T>,
    sender: watch::Sender<()>,
    mark: FillMark,
    /// The generation current when this fetch was authorized.
    generation: u64,
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
            store_observer: std::sync::OnceLock::new(),
        }
    }

    /// Run `observer` after every store this cache accepts from now on. The
    /// first observer stays; a later one is ignored.
    pub(crate) fn observe_stores(&self, observer: StoreObserver) {
        let _ = self.store_observer.set(observer);
    }

    fn stored(&self) {
        if let Some(observer) = self.store_observer.get() {
            observer();
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

    /// Store `value` only if no invalidation has run since `generation`.
    ///
    /// The fill path's store. A cold fill has no stored value for
    /// [`Self::invalidate_if`] to clear, so without this check a revocation
    /// that lands while the fetch is on the wire is silently overwritten by
    /// the pre-revocation answer and served for the rest of the TTL. The
    /// fetch's own caller still receives its result; only the cache is denied
    /// it, so the next reader re-asks.
    ///
    /// `on_stored` runs under the same write guard, so state derived from the
    /// fill (the tools-truncated flag) is published together with the value:
    /// a reader holding the read guard never sees one without the other.
    fn store_if_current(&self, value: Arc<T>, generation: u64, on_stored: impl FnOnce()) {
        let mut state = self.state.write();
        if state.generation != generation {
            return;
        }
        Self::store_locked(&mut state, value, on_stored);
        drop(state);
        self.stored();
    }

    /// The one store both writers share, run under the caller's write guard
    /// so `on_stored`'s derived state is published with the value.
    fn store_locked(state: &mut CachedMetadataState<T>, value: Arc<T>, on_stored: impl FnOnce()) {
        on_stored();
        state.value = Some(value);
        state.cached_at = Some(Instant::now());
        state.ever_populated = true;
    }

    /// Store `value` now, whatever the slot holds and whether or not a fill
    /// is on the wire. For a list the caller was shown in full, which is newer
    /// than anything cached or in flight: the generation moves, so a fill
    /// already on the wire lands for its own caller but cannot overwrite this.
    /// `on_stored` runs under the write guard, as in [`Self::store_if_current`].
    pub(crate) fn replace(&self, value: T, on_stored: impl FnOnce()) {
        let mut state = self.state.write();
        Self::store_locked(&mut state, Arc::new(value), on_stored);
        state.generation = state.generation.wrapping_add(1);
        drop(state);
        self.stored();
    }

    /// Not `value.is_some()`: `invalidate_if` clears the value, so that would
    /// report a backend enumerated a moment ago as never asked.
    pub(crate) fn ever_populated(&self) -> bool {
        self.state.read().ever_populated
    }

    /// One guard: read separately, a fetch landing between them publishes a lie.
    pub(crate) fn with_cached_and_populated<R>(
        &self,
        map: impl FnOnce(Option<&Arc<T>>, bool) -> R,
    ) -> R {
        let state = self.state.read();
        map(state.value.as_ref(), state.ever_populated)
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
        if state.value.as_ref().is_some_and(|v| !discard(v)) {
            // A populated answer this caller did not ask to forget stays, and
            // so does the generation: a fill already on the wire is still
            // welcome to replace it.
            return;
        }
        Self::clear_locked(&mut state);
    }

    /// Forget the value whatever it holds, and run `on_cleared` under the
    /// same write guard: state derived from the dropped value is cleared with
    /// it, as [`Self::store_if_current`] publishes such state with a stored
    /// one. A fill stored right after cannot have its own derived state
    /// erased by a separate, later clear (MIK-7940).
    pub(super) fn invalidate_then(&self, on_cleared: impl FnOnce()) {
        let mut state = self.state.write();
        Self::clear_locked(&mut state);
        on_cleared();
    }

    fn clear_locked(state: &mut CachedMetadataState<T>) {
        state.value = None;
        state.cached_at = None;
        state.generation = state.generation.wrapping_add(1);
    }

    fn acquire(&self, ttl: Duration) -> CacheFetchState<'_, T> {
        {
            let state = self.state.read();
            if let Some(value) = Self::fresh_value(&state, ttl) {
                return CacheFetchState::Cached(value);
            }
            if let Some((sender, mark)) = state.in_flight.as_ref() {
                return CacheFetchState::Wait(sender.subscribe(), Arc::clone(mark));
            }
        }

        let mut state = self.state.write();
        if let Some(value) = Self::fresh_value(&state, ttl) {
            return CacheFetchState::Cached(value);
        }
        if let Some((sender, mark)) = state.in_flight.as_ref() {
            return CacheFetchState::Wait(sender.subscribe(), Arc::clone(mark));
        }

        let (sender, _receiver) = watch::channel(());
        let mark = FillMark::default();
        state.in_flight = Some((sender.clone(), Arc::clone(&mark)));
        CacheFetchState::Fetch(FetchPermit {
            cache: self,
            sender,
            mark,
            generation: state.generation,
        })
    }

    #[cfg(test)]
    pub(crate) async fn get_or_fetch_shared<F, Fut>(
        &self,
        ttl: Duration,
        fetch: F,
    ) -> Result<Arc<T>>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let fetch = &fetch;
        self.get_or_fetch_shared_then(
            ttl,
            |_| async move { fetch().await.map(|v| (v, ())) },
            |()| {},
            |_| {},
        )
        .await
    }

    /// [`Self::get_or_fetch_shared`] whose fetch also yields a side value `A`,
    /// handed to `on_stored` ONLY when the generation check accepted the
    /// store. State derived from a fill (the tools-truncated flag) is then
    /// voided by the same mid-fill invalidation that voids the value.
    ///
    /// `fetch` gets its fill's [`FillMark`]; `waiting` is told, before each
    /// wait, the mark of the fill this caller now waits on, and `None` when
    /// it runs the fill itself, so it never reads a fill it left (MIK-8046).
    pub(crate) async fn get_or_fetch_shared_then<A, F, Fut, S, W>(
        &self,
        ttl: Duration,
        fetch: F,
        on_stored: S,
        waiting: W,
    ) -> Result<Arc<T>>
    where
        F: Fn(FillMark) -> Fut,
        Fut: Future<Output = Result<(T, A)>>,
        S: FnOnce(A),
        W: Fn(Option<FillMark>),
    {
        loop {
            match self.acquire(ttl) {
                CacheFetchState::Cached(value) => return Ok(value),
                CacheFetchState::Wait(mut receiver, mark) => {
                    waiting(Some(mark));
                    let _ = receiver.changed().await;
                }
                CacheFetchState::Fetch(permit) => {
                    waiting(None);
                    let result = fetch(Arc::clone(&permit.mark)).await;
                    let result = result.map(|(value, side)| {
                        let value = Arc::new(value);
                        self.store_if_current(Arc::clone(&value), permit.generation, || {
                            on_stored(side);
                        });
                        value
                    });
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

    /// `MIK-8127`: the observer hears every accepted store, from either
    /// writer, and never a fill an invalidation voided.
    #[tokio::test]
    async fn the_store_observer_hears_each_accepted_store_once() {
        let cache: CachedMetadata<Vec<u8>> = CachedMetadata::new();
        let heard = Arc::new(AtomicU32::new(0));
        let count = Arc::clone(&heard);
        cache.observe_stores(Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
        }));
        let filled = cache.get_or_fetch_shared(LONG_TTL, || async { Ok(vec![1u8]) });
        filled.await.expect("fill");
        assert_eq!(heard.load(Ordering::SeqCst), 1, "a fill");
        cache.replace(vec![2u8], || {});
        assert_eq!(heard.load(Ordering::SeqCst), 2, "a replace");
        cache.invalidate_if(|_| true);
        let voided = cache.get_or_fetch_shared(LONG_TTL, || async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(vec![3u8])
        });
        let revoke = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cache.invalidate_if(|_| true);
        };
        let (voided, ()) = tokio::join!(voided, revoke);
        voided.expect("the voided fill still answers its caller");
        assert_eq!(
            heard.load(Ordering::SeqCst),
            2,
            "a voided fill stores nothing"
        );
    }

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

    /// MIK-7940 finding 5: the derived-state clear runs while the cache is
    /// still write-locked, so no fill can store between the two.
    #[test]
    fn invalidate_then_clears_derived_state_under_the_guard() {
        let cache: CachedMetadata<Vec<u8>> = CachedMetadata::new();
        let mut locked = false;
        cache.invalidate_then(|| locked = cache.state.try_read().is_none());
        assert!(
            locked,
            "the derived clear ran under the cache's write guard"
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

    /// MIK-7334.CATALOGUE.1 conjunct 4 — "including changes and revocation".
    ///
    /// `invalidate_if` can only clear a value that is already stored. During a
    /// COLD fill there is none, so the invalidate is a no-op and the in-flight
    /// answer — fetched before the revocation, under the old authorization —
    /// lands afterwards and is served for the rest of the TTL. The invalidate
    /// must instead void the fill that was already on the wire when it ran.
    #[tokio::test]
    async fn an_invalidate_during_a_fill_is_not_overwritten_by_it() {
        let cache: CachedMetadata<Vec<u8>> = CachedMetadata::new();
        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);

        let fill = cache.get_or_fetch_shared(LONG_TTL, || {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(vec![1u8, 2, 3])
            }
        });
        let revoke = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cache.invalidate_if(Vec::is_empty);
        };
        let (filled, ()) = tokio::join!(fill, revoke);

        assert_eq!(
            *filled.expect("the fill still answers its own caller"),
            vec![1u8, 2, 3],
            "the caller that asked before the revocation still gets its answer"
        );
        assert!(
            cache.snapshot_shared().is_none(),
            "a fill that was in flight when the invalidate ran must not be cached"
        );

        let after = cache
            .get_or_fetch_shared(LONG_TTL, || {
                let seen = Arc::clone(&calls);
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Ok(Vec::new())
                }
            })
            .await
            .expect("post-revocation read");
        assert!(
            after.is_empty(),
            "the next reader must re-ask, not be served"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2, "the re-ask must be real");
    }

    /// `MIK-8046`: a waiter is told the mark of the fill it waits on, the
    /// same mark that fill's fetch holds; the owner is told it waits on none,
    /// and the next fill gets a fresh mark.
    #[tokio::test]
    async fn a_waiter_reads_the_mark_of_the_fill_it_waits_on() {
        let cache: CachedMetadata<Vec<u8>> = CachedMetadata::new();
        let first_mark = parking_lot::Mutex::new(None);
        let heard = parking_lot::Mutex::new(Vec::new());
        let owner = cache.get_or_fetch_shared_then(
            LONG_TTL,
            |mark| {
                *first_mark.lock() = Some(Arc::clone(&mark));
                async move {
                    mark.store(true, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok((vec![1u8], ()))
                }
            },
            |()| {},
            |mark| heard.lock().push(("owner", mark)),
        );
        let waiter = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cache
                .get_or_fetch_shared_then(
                    LONG_TTL,
                    |_| async { Ok((vec![2u8], ())) },
                    |()| {},
                    |mark| heard.lock().push(("waiter", mark)),
                )
                .await
        };
        let (owner, waiter) = tokio::join!(owner, waiter);
        assert_eq!(*owner.unwrap(), vec![1u8]);
        assert_eq!(*waiter.unwrap(), vec![1u8], "the waiter joined the fill");
        let first_mark = first_mark.lock().clone().expect("the owner's fetch ran");
        {
            let heard = heard.lock();
            assert!(
                matches!(heard[0], ("owner", None)),
                "the owner waits on no fill"
            );
            let ("waiter", Some(mark)) = &heard[1] else {
                panic!("the waiter hears which fill it waits on");
            };
            assert!(
                Arc::ptr_eq(mark, &first_mark),
                "the waiter reads that fill's own mark"
            );
            assert!(mark.load(Ordering::SeqCst), "and sees what the fill set");
        }

        cache.invalidate_if(|_| true);
        let later = parking_lot::Mutex::new(None);
        cache
            .get_or_fetch_shared_then(
                LONG_TTL,
                |mark| {
                    *later.lock() = Some(mark);
                    async { Ok((vec![3u8], ())) }
                },
                |()| {},
                |_| {},
            )
            .await
            .unwrap();
        let later = later.lock().clone().expect("the later fetch ran");
        assert!(
            !Arc::ptr_eq(&later, &first_mark),
            "a later fill gets its own mark"
        );
        assert!(
            !later.load(Ordering::SeqCst),
            "unset until that fill sets it"
        );
    }
}
