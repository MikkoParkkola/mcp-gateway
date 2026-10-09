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
    /// One per-user slot of a registry backend (`MIK-8148`), by binding.
    Binding {
        name: String,
        instance: u64,
        binding: String,
        event: SlotEvent,
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

/// What happened to a per-user slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotEvent {
    /// It stored a list.
    Stored,
    /// It was closed for idleness: what its caller sees did not change.
    Idle,
    /// It was closed because its caller's grant was revoked: what that caller
    /// sees did change.
    Revoked,
}

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
        // Slots opened before the feed existed. One opened concurrently is
        // observed by `pooled_entry_with` too; the first observer stays.
        for slot in &self.pool {
            self.observe_slot(slot.key(), slot.value());
        }
    }

    /// Nudge after every list per-user slot `key` stores (`MIK-8148`). A no-op
    /// for the shared slot, which `attach_nudges` observes, and before a feed
    /// is attached.
    pub(super) fn observe_slot(&self, key: &super::PoolKey, entry: &super::pool::PooledEntry) {
        let (super::PoolKey::PerUser { binding }, Some(feed)) = (key, self.nudge_feed.get()) else {
            return;
        };
        let (feed, name, instance, binding) = (
            feed.clone(),
            self.name.clone(),
            self.instance,
            binding.clone(),
        );
        entry.tools_cache.observe_stores(Arc::new(move || {
            let _ = feed.send(ToolsNudge::Binding {
                name: name.clone(),
                instance,
                binding: binding.clone(),
                event: SlotEvent::Stored,
            });
        }));
    }

    /// Nudge the drain that per-user slot `key` closed for `event`'s reason.
    pub(super) fn nudge_slot_closed(&self, key: &super::PoolKey, event: SlotEvent) {
        if let (super::PoolKey::PerUser { binding }, Some(feed)) = (key, self.nudge_feed.get()) {
            let _ = feed.send(ToolsNudge::Binding {
                name: self.name.clone(),
                instance: self.instance,
                binding: binding.clone(),
                event,
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
    async fn instances_never_share_an_identity() {
        assert_ne!(backend("a").instance(), backend("a").instance());
    }
}
