// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a listener counts interest: adding and holding a key's interest, and
//! removing it, which ends an idle task. Moved from `upstream_listener.rs`
//! for the file-size ceiling.

use std::sync::Arc;

use super::{ListenerKey, UpstreamListeners, admit};
use crate::events::upstream_need::{Full, Interest, Need};

impl UpstreamListeners {
    /// Count one more live key for `backend`, starting its task when it is
    /// the first.
    ///
    /// # Errors
    /// [`Full`] when the backend's URI budget is spent.
    pub(crate) fn add(&self, key: &ListenerKey, interest: &Interest) -> Result<(), Full> {
        let mut map = self.backends.lock();
        let (shared, outcome) = loop {
            // A task that ended (a reload made its backend ineligible, or it
            // went idle) is replaced, not reused, if the interest returns; so
            // is one whose ledger belongs to a `Backend` the registry no longer
            // holds (config removal or replacement, D5). The replacement
            // inherits the interest still counted, so later removals balance.
            let ledger = self.ledger(key);
            let mut carried = Need::default();
            if let Some(old) = map
                .get(key)
                .filter(|s| s.stop.is_cancelled() || !Arc::ptr_eq(&s.ledger(), &ledger))
            {
                old.stop.cancel();
                carried = std::mem::take(&mut *old.need.lock());
                map.remove(key);
            }
            let shared = Arc::clone(
                map.entry(key.clone())
                    .or_insert_with(|| self.start(key, carried, ledger)),
            );
            // The task's idle self-stop also runs under `need`: either it
            // stopped first and this picks a successor, or this admission
            // makes the need non-empty before it looks.
            let mut need = shared.need.lock();
            if shared.stop.is_cancelled() {
                continue;
            }
            let outcome = admit(&shared, &mut need, interest);
            drop(need);
            break (shared, outcome);
        };
        match outcome {
            Ok(true) => shared.wake.send_modify(|n| *n += 1),
            Ok(false) => {}
            Err(full) => {
                let ledger = shared.ledger();
                let mut ledger = ledger.lock();
                if ledger.warn_cap() {
                    let ((keys, bytes, stranded), unplaced) = (ledger.size(), ledger.unplaced());
                    tracing::warn!(
                        backend = %key.backend,
                        keys,
                        bytes,
                        stranded,
                        unplaced,
                        "upstream listener: URI cap held by stranded keys until config removal or restart"
                    );
                }
                drop(ledger);
                // A refusal for capacity keeps an idle task running while
                // its passes can still release keys (D5 cleanup).
                if shared.is_idle() {
                    shared.stop.cancel();
                    map.remove(key);
                } else {
                    shared.wake.send_modify(|n| *n += 1);
                }
                return Err(full);
            }
        }
        Ok(())
    }

    /// Count a key for a backend that cannot be listened to now (absent or
    /// refused), starting nothing: the entry is an ended one, which the
    /// revive sweep starts once the backend can be (`D6.EVENTS_MISC.6`). On a
    /// backend whose task runs it counts there.
    ///
    /// # Errors
    /// The URI budget is spent, as [`Self::add`] refuses; `tools_changed` has
    /// no URI budget and is always counted.
    pub(crate) fn hold(&self, key: &ListenerKey, interest: &Interest) -> Result<(), Full> {
        let mut map = self.backends.lock();
        let shared = map.entry(key.clone()).or_insert_with(|| {
            let ended = self.entry(key, Need::default(), self.ledger(key));
            ended.stop.cancel();
            ended
        });
        if shared.need.lock().add(interest)? && !shared.stop.is_cancelled() {
            shared.wake.send_modify(|n| *n += 1);
        }
        Ok(())
    }

    /// Count one key fewer; the last one stops the task.
    pub(crate) fn remove(&self, key: &ListenerKey, interest: &Interest) {
        let mut map = self.backends.lock();
        let Some(shared) = map.get(key).cloned() else {
            return;
        };
        let (changed, no_uris) = {
            let mut need = shared.need.lock();
            let changed = need.remove(interest);
            if let Interest::ResourceUpdated(uri) = interest
                && !need.watches(uri)
            {
                shared.ledger().lock().unwant(uri);
            }
            (changed, !need.watches_any())
        };
        // With no URI watched the snapshot is no longer read, so it stops
        // answering for a new URI (design r3 L4, LIFE.3b).
        if no_uris {
            shared.snapshot.lock().clear();
        }
        if shared.is_idle() {
            shared.stop.cancel();
            map.remove(key);
        } else if changed {
            shared.wake.send_modify(|n| *n += 1);
        }
    }
}
