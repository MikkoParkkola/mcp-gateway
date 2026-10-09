// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What reaches the change feed (`MIK-8127`).
//!
//! A nudge says "the tools discovery shows for this backend may have changed;
//! look again". It is not an announcement: the drain compares what discovery
//! shows now with what it last announced, and announces only a difference. So
//! a producer may nudge freely, and none of them has to know whether anything
//! visible moved.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::protocol::Tool;

/// Never reused, unlike an allocation address: a nudge left over from a
/// replaced instance must not be read as one about its successor.
static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

pub(super) fn next_instance() -> u64 {
    NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed)
}

/// What a backend nudge reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NudgeKind {
    /// Something that can change the visible tools happened: a store, a
    /// registration, a removal, a descriptor verdict.
    Changed,
    /// This instance's first fill attempt ended without storing a list, or it
    /// was registered with no warm-up at all: until it stores one, it shows
    /// nothing, and that is now a decided state rather than a pending one.
    Resolved,
}

/// One message on the change feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ToolsNudge {
    /// A registry backend, by name and instance.
    Backend {
        name: String,
        instance: u64,
        kind: NudgeKind,
    },
    /// A grant on a registry backend was revoked (`MIK-8148`): every caller
    /// whose binding starts with `prefix` lost its view. One per revocation,
    /// which admin and grant events drive, not traffic, so it is not coalesced.
    Revoked {
        name: String,
        instance: u64,
        prefix: String,
    },
    /// The capability catalogue, which is not a registry backend.
    Catalogue { name: String },
}

/// What one per-user slot holds now.
pub(crate) enum SlotView {
    /// No slot holds the binding.
    Absent,
    /// The slot has stored no list.
    Unfilled,
    /// The slot's list, filtered as discovery serves it.
    Holds(Arc<Vec<Tool>>),
}

/// Set by any per-user slot's store while a nudge for it is queued and
/// unread; cleared by the drain before it reads the slots. So the feed holds
/// at most ONE store nudge per backend, however many callers store meanwhile.
pub(crate) type ViewsDirty = Arc<std::sync::atomic::AtomicBool>;

/// The sending half of the change feed.
pub(crate) type NudgeFeed = tokio::sync::mpsc::UnboundedSender<ToolsNudge>;

impl super::Backend {
    /// This instance's identity, unique for the life of the process. A
    /// continuation binds it too (`MIK-8168`), so a backend replaced under the
    /// same name is never answered a round the old one asked.
    #[must_use]
    pub(crate) fn instance(&self) -> u64 {
        self.instance
    }

    /// Route this instance's nudges to `feed`, and nudge after every list its
    /// shared tool slot stores, whichever path stored it. Once per instance.
    pub(super) fn attach_nudges(&self, feed: &NudgeFeed) {
        if self.nudge_feed.set(feed.clone()).is_err() {
            return;
        }
        let (feed, name, instance) = (feed.clone(), self.name.clone(), self.instance);
        self.shared_entry()
            .tools_cache
            .observe_stores(Arc::new(move || {
                let _ = feed.send(ToolsNudge::Backend {
                    name: name.clone(),
                    instance,
                    kind: NudgeKind::Changed,
                });
            }));
        // Slots opened before the feed existed. NO SLOT IS MISSED, and the
        // order of the two steps is what makes it so: the feed is set BEFORE
        // this walk, and `pooled_entry_with` checks for the feed while holding
        // the new slot's shard WRITE guard. A slot that checked before the feed
        // was set is still being inserted under that guard, so this walk blocks
        // on its shard and then sees it; a slot whose shard the walk already
        // passed checks after the feed was set. Observing twice is harmless:
        // the first observer stays.
        for slot in &self.pool {
            self.observe_slot(slot.key(), slot.value());
        }
    }

    /// Nudge after every list per-user slot `key` stores (`MIK-8148`). A no-op
    /// for the shared slot, which `attach_nudges` observes, and before a feed
    /// is attached.
    pub(super) fn observe_slot(&self, key: &super::PoolKey, entry: &super::pool::PooledEntry) {
        let (super::PoolKey::PerUser { .. }, Some(feed)) = (key, self.nudge_feed.get()) else {
            return;
        };
        let (feed, name, instance) = (feed.clone(), self.name.clone(), self.instance);
        let dirty = Arc::clone(&self.views_dirty);
        entry.tools_cache.observe_stores(Arc::new(move || {
            // Coalesced per backend: while a nudge is queued, a store adds
            // nothing, because the drain reads every slot as it is then.
            if dirty.swap(true, Ordering::SeqCst) {
                return;
            }
            let _ = feed.send(ToolsNudge::Backend {
                name: name.clone(),
                instance,
                kind: NudgeKind::Changed,
            });
        }));
    }

    /// The drain is about to read every per-user slot: a store from now on
    /// queues a fresh nudge, so none is lost between this and the read.
    pub(crate) fn clear_views_dirty(&self) {
        self.views_dirty.store(false, Ordering::SeqCst);
    }

    /// Nudge the drain that the grant behind `binding_prefix` was revoked.
    pub(super) fn nudge_revoked(&self, binding_prefix: &str) {
        if let Some(feed) = self.nudge_feed.get() {
            let _ = feed.send(ToolsNudge::Revoked {
                name: self.name.clone(),
                instance: self.instance,
                prefix: binding_prefix.to_string(),
            });
        }
    }

    /// What per-user slot `binding` holds now, as discovery would serve it
    /// (descriptor-blocked names removed).
    #[must_use]
    pub(crate) fn per_user_view(&self, binding: &str) -> SlotView {
        let key = super::PoolKey::PerUser {
            binding: binding.to_string(),
        };
        let Some(entry) = self.pool.get(&key).map(|slot| Arc::clone(slot.value())) else {
            return SlotView::Absent;
        };
        match entry.tools_cache.snapshot_shared() {
            Some(tools) => SlotView::Holds(self.without_blocked(tools)),
            None => SlotView::Unfilled,
        }
    }

    /// Store `tools` into per-user slot `binding`, opening it if needed, the
    /// way a fill does, so its observer runs.
    #[cfg(test)]
    pub(crate) fn store_per_user_tools_for_test(&self, binding: &str, tools: Vec<Tool>) {
        let key = super::PoolKey::PerUser {
            binding: binding.to_string(),
        };
        self.pooled_entry(&key)
            .expect("a per-user slot is admitted")
            .tools_cache
            .replace(tools, || ());
    }

    /// Withhold tool `name` from every slot's served view, as a descriptor
    /// verdict does.
    #[cfg(test)]
    pub(crate) fn block_tool_for_test(&self, name: &str) {
        let mut verdicts = super::descriptor_gate::Verdicts::default();
        verdicts.add_unparseable([(name.to_string(), "digest".to_string())]);
        self.commit_verdicts("", super::Listing::Complete, verdicts);
    }

    /// Have the next drain snapshot block tool `name` mid-snapshot.
    #[cfg(test)]
    pub(crate) fn block_mid_snapshot_for_test(&self, name: &str) {
        *self.snapshot_seam.lock() = Some(name.to_string());
    }

    /// The snapshot seam: commits the verdict a test asked for, once.
    #[cfg(test)]
    pub(crate) fn run_snapshot_seam_for_test(&self) {
        if let Some(name) = self.snapshot_seam.lock().take() {
            self.block_tool_for_test(&name);
        }
    }

    /// Every per-user slot's binding, for a backend-wide recompute.
    #[must_use]
    pub(crate) fn per_user_bindings(&self) -> Vec<String> {
        self.pool
            .iter()
            .filter_map(|slot| match slot.key() {
                super::PoolKey::PerUser { binding } => Some(binding.clone()),
                super::PoolKey::Shared => None,
            })
            .collect()
    }

    /// Nudge the drain about this instance. A no-op before a feed is attached.
    pub(crate) fn nudge_tools(&self, kind: NudgeKind) {
        if let Some(feed) = self.nudge_feed.get() {
            let _ = feed.send(ToolsNudge::Backend {
                name: self.name.clone(),
                instance: self.instance,
                kind,
            });
        }
    }

    /// The list the shared slot holds now, as discovery would serve it
    /// (descriptor-blocked names removed), or `None` when nothing is stored;
    /// and whether this instance ever stored one. One read of the slot:
    /// reading the two separately would let a store or an invalidation land
    /// in between.
    #[must_use]
    pub(crate) fn stored_tools_snapshot(&self) -> (Option<Arc<Vec<Tool>>>, bool) {
        let (stored, populated) = self
            .shared_entry()
            .tools_cache
            .with_cached_and_populated(|tools, populated| (tools.cloned(), populated));
        (stored.map(|tools| self.without_blocked(tools)), populated)
    }
}

#[cfg(test)]
mod tests {
    use super::{NudgeKind, ToolsNudge};
    use crate::backend::Backend;
    use crate::backend::descriptor_gate::{Listing, Verdicts};

    fn backend(name: &str) -> Backend {
        Backend::new(
            name,
            crate::config::BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        )
    }

    #[tokio::test]
    async fn a_descriptor_verdict_nudges_the_drain() {
        // A verdict filters the shared view without any list being stored.
        let backend = backend("a");
        let (feed, mut nudges) = tokio::sync::mpsc::unbounded_channel();
        backend.attach_nudges(&feed);
        let mut verdicts = Verdicts::default();
        verdicts.add_unparseable([("x".to_string(), "digest".to_string())]);
        backend.commit_verdicts("", Listing::Complete, verdicts);
        assert_eq!(
            nudges.try_recv().ok(),
            Some(ToolsNudge::Backend {
                name: "a".to_string(),
                instance: backend.instance(),
                kind: NudgeKind::Changed,
            })
        );
    }

    /// `MIK-8148`: a per-user slot's catalogue is what that user's discovery
    /// shows, so a list it stores must reach the drain like a shared one.
    fn per_user(binding: &str) -> crate::backend::PoolKey {
        crate::backend::PoolKey::PerUser {
            binding: binding.to_string(),
        }
    }

    #[tokio::test]
    async fn a_per_user_store_nudges_the_drain() {
        let backend = backend("a");
        let (feed, mut nudges) = tokio::sync::mpsc::unbounded_channel();
        backend.attach_nudges(&feed);
        let slot = backend
            .pooled_entry(&per_user("idp:u1"))
            .expect("a per-user slot is admitted");
        slot.tools_cache.replace(Vec::new(), || ());
        assert_eq!(
            std::iter::from_fn(|| nudges.try_recv().ok()).count(),
            1,
            "one store into a per-user slot, one nudge"
        );
    }

    #[tokio::test]
    async fn a_per_user_slot_opened_before_the_feed_still_nudges() {
        let backend = backend("a");
        let slot = backend
            .pooled_entry(&per_user("idp:u1"))
            .expect("a per-user slot is admitted");
        let (feed, mut nudges) = tokio::sync::mpsc::unbounded_channel();
        backend.attach_nudges(&feed);
        slot.tools_cache.replace(Vec::new(), || ());
        assert_eq!(
            std::iter::from_fn(|| nudges.try_recv().ok()).count(),
            1,
            "a slot that predates the feed is observed too"
        );
    }

    #[tokio::test]
    async fn stores_queued_before_the_drain_reads_coalesce_into_one_nudge() {
        let backend = backend("a");
        let (feed, mut nudges) = tokio::sync::mpsc::unbounded_channel();
        backend.attach_nudges(&feed);
        let slot = backend
            .pooled_entry(&per_user("idp:u1"))
            .expect("a per-user slot is admitted");
        for _ in 0..3 {
            slot.tools_cache.replace(Vec::new(), || ());
        }
        assert_eq!(std::iter::from_fn(|| nudges.try_recv().ok()).count(), 1);
        backend.clear_views_dirty();
        slot.tools_cache.replace(Vec::new(), || ());
        assert_eq!(
            std::iter::from_fn(|| nudges.try_recv().ok()).count(),
            1,
            "a store after the drain read queues a fresh nudge"
        );
    }

    /// agy's concurrent-attach case, interleaved on purpose: a creation checks
    /// for the feed (not set yet) while holding the new slot's shard, and the
    /// feed attaches before it inserts. The walk must wait for that shard and
    /// then observe the slot.
    #[test]
    fn a_slot_opened_while_the_feed_attaches_is_still_observed() {
        let backend = std::sync::Arc::new(backend("a"));
        let key = per_user("idp:u1");
        let (feed, mut nudges) = tokio::sync::mpsc::unbounded_channel();
        let (checked_tx, checked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

        let creator = {
            let (backend, key) = (std::sync::Arc::clone(&backend), key.clone());
            std::thread::spawn(move || {
                let dashmap::mapref::entry::Entry::Vacant(vacant) = backend.pool.entry(key.clone())
                else {
                    panic!("premise: the slot is new");
                };
                let entry =
                    crate::backend::pool::PooledEntry::new(&backend.name, &backend.failsafe_config);
                backend.observe_slot(&key, &entry);
                checked_tx.send(()).expect("main waits");
                release_rx.recv().expect("main releases");
                vacant.insert(std::sync::Arc::new(entry));
            })
        };
        checked_rx.recv().expect("the creation checked the feed");
        let attacher = {
            let backend = std::sync::Arc::clone(&backend);
            std::thread::spawn(move || backend.attach_nudges(&feed))
        };
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            !attacher.is_finished(),
            "premise: the walk is held at the creating shard"
        );
        release_tx.send(()).expect("the creator waits");
        creator.join().expect("creator");
        attacher.join().expect("attacher");

        let slot = backend.pooled_entry(&key).expect("the slot exists");
        slot.tools_cache.replace(Vec::new(), || ());
        assert_eq!(
            std::iter::from_fn(|| nudges.try_recv().ok()).count(),
            1,
            "the slot opened during attach is observed"
        );
    }

    #[tokio::test]
    async fn many_callers_storing_while_the_drain_is_held_queue_one_nudge() {
        // The bound the change feed relies on: one store nudge per backend
        // until the drain reads, however many distinct callers store.
        let backend = backend("a");
        let (feed, mut nudges) = tokio::sync::mpsc::unbounded_channel();
        backend.attach_nudges(&feed);
        for n in 0..64 {
            backend
                .pooled_entry(&per_user(&format!("idp:u{n}")))
                .expect("admitted")
                .tools_cache
                .replace(Vec::new(), || ());
        }
        assert_eq!(std::iter::from_fn(|| nudges.try_recv().ok()).count(), 1);
    }

    #[tokio::test]
    async fn an_idle_sweep_sends_one_nudge_however_many_slots_close() {
        let backend = backend("a");
        for user in ["idp:u1", "idp:u2", "idp:u3"] {
            backend.pooled_entry(&per_user(user)).expect("admitted");
        }
        let (feed, mut nudges) = tokio::sync::mpsc::unbounded_channel();
        backend.attach_nudges(&feed);
        assert_eq!(
            backend.evict_idle_per_user_entries(std::time::Duration::ZERO),
            3
        );
        assert_eq!(std::iter::from_fn(|| nudges.try_recv().ok()).count(), 1);
    }

    #[tokio::test]
    async fn a_revocation_nudges_even_when_no_slot_is_open() {
        let backend = backend("a");
        let (feed, mut nudges) = tokio::sync::mpsc::unbounded_channel();
        backend.attach_nudges(&feed);
        assert_eq!(backend.evict_identity_slots("idp:9:nobody:"), 0);
        assert_eq!(
            nudges.try_recv().ok(),
            Some(ToolsNudge::Revoked {
                name: "a".to_string(),
                instance: backend.instance(),
                prefix: "idp:9:nobody:".to_string(),
            })
        );
    }

    /// `MIK-8208`: descriptor verdicts and shared-slot stores land on the
    /// same feed as per-user stores, so they share its bound: one queued
    /// nudge per backend while the drain is held, however many land.
    #[tokio::test]
    async fn many_verdicts_while_the_drain_is_held_queue_one_nudge() {
        let backend = backend("a");
        let (feed, mut nudges) = tokio::sync::mpsc::unbounded_channel();
        backend.attach_nudges(&feed);
        for n in 0..64 {
            backend.block_tool_for_test(&format!("t{n}"));
        }
        assert_eq!(std::iter::from_fn(|| nudges.try_recv().ok()).count(), 1);
        backend.clear_views_dirty();
        backend.block_tool_for_test("after");
        assert_eq!(
            std::iter::from_fn(|| nudges.try_recv().ok()).count(),
            1,
            "a verdict after the drain read queues a fresh nudge"
        );
    }

    #[tokio::test]
    async fn many_shared_stores_while_the_drain_is_held_queue_one_nudge() {
        let backend = backend("a");
        let (feed, mut nudges) = tokio::sync::mpsc::unbounded_channel();
        backend.attach_nudges(&feed);
        for _ in 0..64 {
            backend.shared_entry().tools_cache.replace(Vec::new(), || ());
        }
        assert_eq!(std::iter::from_fn(|| nudges.try_recv().ok()).count(), 1);
    }

    #[tokio::test]
    async fn instances_never_share_an_identity() {
        assert_ne!(backend("a").instance(), backend("a").instance());
    }
}
