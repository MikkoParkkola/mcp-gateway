// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The capability part a backend publishes: the snapshot of what it serves,
//! the sequence that orders publishes, the operation lock and the coverage
//! of the operation in progress. Split from the backend so its file stays
//! under the size ceiling.

#[cfg(test)]
use super::Arc;
use super::indexed::{OperationUnread, ServedSource, part_from};
use super::{CapabilityBackend, CapabilityPart, PartDigest, part_digest};

/// A row's look at one delivery. The publish stub never calls it.
#[cfg(test)]
pub(super) type DeliveryObserver = Arc<dyn Fn(&CapabilityBackend) + Send + Sync>;

impl CapabilityBackend {
    /// Digest capability bytes with `key`. The caller derived it. Digests are
    /// taken at load, outside the catalogue lock.
    #[must_use]
    pub(crate) fn with_revision_key(mut self, key: [u8; 32]) -> Self {
        self.revision_key = Some(key);
        self
    }

    /// The file `path`'s bytes digest to, when this backend has a revision key.
    pub(super) fn source_of(&self, path: &str, bytes: &[u8]) -> ServedSource {
        ServedSource {
            path: path.to_string(),
            digest: self.revision_key.map(|key| part_digest(&key, bytes)),
        }
    }

    /// The capability part for what is served now.
    ///
    /// Under the catalogue read lock: one `(path, digest)` per served entry
    /// that has a file, both files when two directories hold one name, and
    /// nothing for an entry registered without a file. A source with no
    /// digest was loaded on a backend with no revision key, so it has no
    /// pair to contribute. Refused and rug-pulled capabilities are absent
    /// because their slots are gone. `Partial` when the operation that
    /// installed this catalogue left a path unread; the entries are the same
    /// either way.
    #[cfg(test)]
    pub(crate) fn capability_snapshot(&self) -> CapabilityPart<PartDigest> {
        let caps = self.capabilities.read();
        part_from(&caps)
    }

    /// The next load sequence. The caller holds the catalogue write lock, so
    /// the number and the snapshot name one catalogue.
    pub(super) fn alloc_seq(&self) -> u64 {
        self.revision_seq
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            + 1
    }

    /// Snapshot and sequence under the catalogue write lock. For a scan that
    /// has already installed its catalogue: the lock is the swap, and the
    /// publish happens after this returns.
    pub(crate) fn take_served_revision(&self) -> (u64, CapabilityPart<PartDigest>) {
        let caps = self.capabilities.write();
        let seq = self.alloc_seq();
        let part = part_from(&caps);
        (seq, part)
    }

    /// The operation lock, taken immediately after the test's Acquire step.
    /// Hold the guard across the load, the swap and the publish.
    pub(crate) async fn lock_operation(&self) -> tokio::sync::MutexGuard<'_, ()> {
        #[cfg(test)]
        crate::capability::op_gate::reach(crate::capability::op_gate::Step::Acquire);
        self.operation.lock().await
    }

    /// A configured directory, or a file in a readable directory, could not
    /// be read. Recorded on the operation in progress, which is the set a
    /// snapshot reads only once that operation has stored it on the catalogue.
    pub(crate) fn note_unreadable(&self, path: &str) {
        self.recording.lock().note(path);
    }

    /// The HTTP scan or the stdio startup is starting. Its catalogue is the
    /// one it is about to install, so the unreadable set starts empty and
    /// notes land on it. A reload does not use this: clearing here would
    /// relabel the catalogue still being served.
    pub(crate) fn begin_incremental_coverage(&self) {
        let unread = OperationUnread::default();
        let mut caps = self.capabilities.write();
        caps.unread = unread.clone();
        *self.recording.lock() = unread;
    }

    /// A reload is starting. Its notes stay off the catalogue until install
    /// stores them with the entries it writes.
    pub(super) fn begin_reload_coverage(&self) {
        *self.recording.lock() = OperationUnread::default();
    }

    /// Publish `(seq, part)` after a catalogue swap, with no catalogue lock held.
    ///
    /// The handoff records the part and, once a live config is attached,
    /// delivers it after its own mutex is released. The observer runs after
    /// that, so it can take the catalogue write lock.
    pub(crate) fn publish_revision(&self, seq: u64, part: CapabilityPart<PartDigest>) {
        self.handoff.publish(seq, part);
        #[cfg(test)]
        self.notify_delivery();
    }

    /// The startup scan's publish and its end, one handoff acquisition.
    ///
    /// `true` when this call marked the scan complete. Unattached, the scan
    /// stays parked and this is `false`.
    pub(crate) fn publish_initial_scan(&self, seq: u64, part: CapabilityPart<PartDigest>) -> bool {
        // Set before the publish, which can make the scan ready, as
        // mark_initial_scan_complete sets it before its flag: the readiness-order
        // row reads what a probe that sees the scan complete could see. A scan
        // that parks here is completed later by attach, after this was set.
        #[cfg(test)]
        let _ = self
            .records_at_scan_complete
            .set(self.rug_pull_records().len());
        let transitioned = self.handoff.publish_and_end(seq, part);
        #[cfg(test)]
        self.notify_delivery();
        transitioned
    }

    /// Arm the observer the next [`Self::new`] on this thread copies in.
    /// Taken once, so a later backend on the same thread does not keep it.
    #[cfg(test)]
    pub(crate) fn install_next_delivery_observer(observer: DeliveryObserver) {
        NEXT_DELIVERY_OBSERVER.with(|slot| *slot.borrow_mut() = Some(observer));
    }

    /// Arm the observer on a backend the row already holds.
    #[cfg(test)]
    pub(crate) fn set_delivery_observer(&self, observer: DeliveryObserver) {
        *self.delivery_observer.lock() = Some(observer);
    }

    /// `true` while some caller holds the operation lock. The guard from a
    /// free lock is dropped here, so the check does not keep it.
    #[cfg(test)]
    pub(crate) fn operation_lock_held(&self) -> bool {
        let guard = self.operation.try_lock();
        let held = guard.is_err();
        drop(guard);
        held
    }

    /// `true` when the catalogue write lock is free. The guard is dropped
    /// here, so the check does not keep it.
    #[cfg(test)]
    pub(crate) fn catalogue_write_free(&self) -> bool {
        let guard = self.capabilities.try_write();
        let free = guard.is_some();
        drop(guard);
        free
    }

    /// A publish calls this after the catalogue lock and the handoff mutex
    /// are both dropped. The observer tries the catalogue write lock from
    /// inside the delivery.
    #[cfg(test)]
    pub(super) fn notify_delivery(&self) {
        let observer = self.delivery_observer.lock().clone();
        if let Some(observer) = observer {
            observer(self);
        }
    }
}

#[cfg(test)]
thread_local! {
    static NEXT_DELIVERY_OBSERVER: std::cell::RefCell<Option<DeliveryObserver>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn take_delivery_observer() -> Option<DeliveryObserver> {
    NEXT_DELIVERY_OBSERVER.with(|slot| slot.borrow_mut().take())
}
