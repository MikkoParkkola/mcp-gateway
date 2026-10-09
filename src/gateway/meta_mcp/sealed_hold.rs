// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A sealed question's in-flight slot, owned by the copies of its answer
//! (MIK-8176, family continuation-slot-release).
//!
//! Every mint registers a hold right after its slot is taken, in the request
//! scope its route opened at its outermost boundary. Stage 1 of 4: the type,
//! the registry and the mints, with no change in behaviour. Drop only counts
//! what a later stage releases: a hold whose last copy goes without ever
//! reaching a transport.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tracing::warn;

use crate::protocol::continuation::ContinuationState;

/// One minted slot, shared (behind an `Arc`) by every copy of the answer
/// that carries it. The slot's fate follows its last clone.
pub(crate) struct SealedHold {
    continuation: Arc<ContinuationState>,
    /// Set once any copy reaches a transport; the slot then lives until
    /// redeemed or expired.
    handed_off: AtomicBool,
}

impl Drop for SealedHold {
    fn drop(&mut self) {
        if !self.handed_off.load(Ordering::Acquire) {
            // Stage 1 counts; the release itself arrives with the handoffs.
            self.continuation
                .hold_counts()
                .unhanded_drops
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

tokio::task_local! {
    /// The holds minted while the open request is served, owned by the
    /// outermost opener.
    static HOLDS: Arc<Mutex<Vec<Arc<SealedHold>>>>;
}

/// Run `future` inside a request scope that collects the holds its mints
/// take. Inside an open scope this adds nothing, so the outermost boundary
/// owns them: an inner scope ending cannot drop them early.
pub(crate) async fn scoped<F: Future>(future: F) -> F::Output {
    if HOLDS.try_with(|_| ()).is_ok() {
        return future.await;
    }
    HOLDS.scope(Arc::default(), future).await
}

/// Register the slot a mint just took from `continuation`.
///
/// A mint with no open scope registers nothing, so nothing can release its
/// slot early: it waits for expiry, as every slot did before. Counted and
/// warned; the slot-release matrix asserts no route's cell mints unscoped,
/// so a route or a spawn that drops the scope fails CI there.
pub(crate) fn register(continuation: &Arc<ContinuationState>) {
    let counts = continuation.hold_counts();
    let scoped = HOLDS
        .try_with(|holds| {
            let hold = Arc::new(SealedHold {
                continuation: Arc::clone(continuation),
                handed_off: AtomicBool::new(false),
            });
            holds
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(hold);
        })
        .is_ok();
    if scoped {
        counts.registered.fetch_add(1, Ordering::Relaxed);
    } else {
        counts.unscoped.fetch_add(1, Ordering::Relaxed);
        // Exported, so a production route that misses its scope shows to the
        // operator: nonzero means some slots only ever expire.
        telemetry_metrics::counter!("mcp_continuation_unscoped_mint_total").increment(1);
        warn!("A continuation slot was minted outside any request scope");
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt as _;

    use super::{Arc, ContinuationState, Ordering, register, scoped};

    /// Registered, unscoped and dropped-without-handoff counts.
    fn counts(continuation: &ContinuationState) -> [u64; 3] {
        let counts = continuation.hold_counts();
        [
            counts.registered.load(Ordering::Relaxed),
            counts.unscoped.load(Ordering::Relaxed),
            counts.unhanded_drops.load(Ordering::Relaxed),
        ]
    }

    /// A nested scope adds nothing: the outermost opener owns the holds, so
    /// an inner scope ending cannot drop them early.
    #[tokio::test]
    async fn an_inner_scope_does_not_own_the_holds() {
        let continuation = Arc::new(ContinuationState::new());
        scoped(async {
            scoped(async { register(&continuation) }).await;
            assert_eq!(
                counts(&continuation),
                [1, 0, 0],
                "the inner scope dropped it"
            );
        })
        .await;
        assert_eq!(counts(&continuation), [1, 0, 1]);
    }

    /// A request dropped mid-flight drops every hold it registered.
    #[tokio::test]
    async fn a_cancelled_request_drops_its_holds() {
        let continuation = Arc::new(ContinuationState::new());
        let mut request = Box::pin(scoped(async {
            register(&continuation);
            register(&continuation);
            std::future::pending::<()>().await;
        }));
        assert!((&mut request).now_or_never().is_none());
        assert_eq!(counts(&continuation), [2, 0, 0]);
        drop(request);
        assert_eq!(counts(&continuation), [2, 0, 2]);
    }

    /// A mint outside any scope is counted and holds nothing, so nothing can
    /// release its slot early.
    #[test]
    fn an_unscoped_mint_is_counted_not_held() {
        let continuation = Arc::new(ContinuationState::new());
        register(&continuation);
        assert_eq!(counts(&continuation), [0, 1, 0]);
    }
}
