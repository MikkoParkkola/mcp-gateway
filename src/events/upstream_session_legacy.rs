// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The legacy half of a listener session (MIK-7898 SESS.2b, design D5): the
//! `resources/subscribe` calls a backend's ledger has due, the release walk
//! on stop, and the URI filter of the legacy tap.

use std::sync::{Arc, Weak};
use std::time::Instant;

use tracing::warn;

use super::{Era, OPEN_LIMIT, RELEASE_LIMIT, State};
use crate::backend::Backend;
use crate::events::upstream_listener::Shared;
use crate::events::upstream_need::ledger::{drive, holder_of};
use crate::transport::upstream_tap::{UpstreamListen, Watched};

/// Order `due` (sorted by URI) to start after `last`, wrapping around.
pub(super) fn resume_after(due: &mut [(String, bool)], last: Option<&str>) {
    if let Some(last) = last {
        let next = due.partition_point(|(uri, _)| uri.as_str() <= last);
        due.rotate_left(next);
    }
}

/// The legacy URI filter of `shared`'s need, read at each update (D5).
pub(super) fn watched_by(shared: &Arc<Shared>) -> Watched {
    let shared = Arc::downgrade(shared);
    Watched::by(move |uri| shared.upgrade().is_some_and(|s| s.need.lock().watches(uri)))
}

impl State<'_> {
    /// Legacy: send the calls the backend's ledger has due (D5), one per
    /// URI, the whole pass bounded by `OPEN_LIMIT`; a URI the deadline cut
    /// is uncertain and the rest wait for the next pass.
    pub(super) async fn sync_legacy(
        &mut self,
        backend: &Backend,
        handle: &Weak<dyn UpstreamListen>,
    ) {
        if self.era == Era::Modern || self.resource_interest_unsupported {
            return;
        }
        let ledger = self.shared.ledger();
        if let Some(transport) = handle.upgrade() {
            ledger
                .lock()
                .observe(holder_of(handle, transport.legacy_pin().holder));
        }
        let mut due = ledger.lock().due(Instant::now());
        // Resume after the URI the last pass reached, so URIs that hang
        // cannot starve the ones ordered after them.
        resume_after(&mut due, self.legacy_cursor.as_deref());
        let cursor = &mut self.legacy_cursor;
        let pass = async {
            for (uri, subscribe) in due {
                *cursor = Some(uri.clone());
                if !drive(&ledger, &backend.name, handle, &uri, subscribe, OPEN_LIMIT).await {
                    return false;
                }
            }
            true
        };
        if !tokio::time::timeout(OPEN_LIMIT, pass).await.unwrap_or(true) {
            self.resource_interest_unsupported = true;
        }
        if ledger.lock().unplaced() > 0 && ledger.lock().warn_cap() {
            warn!(
                backend = %self.shared.name,
                "upstream listener: watched URIs not subscribed on the new session; the URI cap is held by stranded keys until config removal or restart"
            );
        }
    }

    /// Best effort on stop: a legacy peer keeps `resources/subscribe` state
    /// until told otherwise, so unsubscribe every key an answer can still
    /// release, in order, all within `RELEASE_LIMIT`. Keys not reached stay
    /// charged; a later task's passes reconcile them.
    pub(super) async fn release(&mut self, backend: &Backend) {
        if self.era == Era::Modern {
            return;
        }
        let ledger = self.shared.ledger();
        let uris = ledger.lock().releasable();
        let Some(handle) = self.handle.clone() else {
            return;
        };
        let walk = async {
            for uri in uris {
                if !drive(&ledger, &backend.name, &handle, &uri, false, OPEN_LIMIT).await {
                    return;
                }
            }
        };
        let _ = tokio::time::timeout(RELEASE_LIMIT, walk).await;
    }
}
