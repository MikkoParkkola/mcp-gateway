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
        warn!("A continuation slot was minted outside any request scope");
    }
}
