// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The executor's private MCP children: one per (capability, caller), how a
//! call leases one, and how each is stopped.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::super::cli_run::Workdir;
use crate::backend::Backend;
use crate::capability::CapabilityDefinition;
use crate::capability::definition::McpConfig;
use crate::{Error, Result};

/// Most live children one capability may have (one per caller).
pub(crate) const MAX_CHILDREN_PER_CAPABILITY: usize = 16;
/// An unused child is stopped after this long.
pub(crate) const IDLE_STOP: Duration = Duration::from_secs(300);

/// One caller's server for one capability.
struct Child {
    backend: Arc<Backend>,
    /// The definition it was started from; a changed one restarts it.
    config: McpConfig,
    /// Fingerprint of the env values it was started with; a rotated one restarts it.
    env_fp: u64,
    /// The provider timeout it runs under; a changed one restarts it.
    timeout: Duration,
    /// Which start this is, so a late `discard` cannot remove a newer child.
    id: u64,
    in_flight: Arc<AtomicUsize>,
    /// Set at acquire and again when a call ends, so a long call is not idle.
    last_used: Arc<Mutex<Instant>>,
    /// The runtime it was started on, so a stop from a thread without one
    /// (a replacement registered by an embedder) still reaches it.
    runtime: Option<tokio::runtime::Handle>,
    /// Dropped after the backend is stopped, removing the tree.
    _workdir: Workdir,
}

/// The executor's private MCP children, keyed by (capability, caller).
#[derive(Default)]
pub(crate) struct McpChildren {
    map: Mutex<HashMap<(String, String), Child>>,
    sweeping: AtomicBool,
    next_id: std::sync::atomic::AtomicU64,
    /// Bumped on every unload, reload and quarantine; see
    /// `CapabilityExecutionContext::mcp_generation`.
    generations: Mutex<HashMap<String, u64>>,
    /// The gateway's stop deadline, joined by every child backend built here.
    pub(in crate::capability::executor) stop_deadline:
        std::sync::OnceLock<Arc<crate::transport::StopDeadline>>,
    /// Test-only pause in `evict`, with the children out of the map and the
    /// map lock still held, for the row that races a gateway stop against it.
    #[cfg(test)]
    pub(super) evict_holds_the_lock: crate::test_pause::Slot,
}

/// Decrements a child's in-flight count when a call ends, however it ends.
pub(crate) struct InFlight(Arc<AtomicUsize>, Arc<Mutex<Instant>>);

impl Drop for InFlight {
    fn drop(&mut self) {
        *self.1.lock() = Instant::now();
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A child leased for one call.
pub(super) struct Lease {
    pub(super) backend: Arc<Backend>,
    pub(super) busy: InFlight,
    pub(super) id: u64,
}

impl McpChildren {
    /// The caller's child for `capability`, started if needed, marked busy.
    pub(super) fn acquire(
        &self,
        capability: &CapabilityDefinition,
        config: &McpConfig,
        principal: &str,
        (env_fp, timeout): (u64, Duration),
        epoch_current: impl Fn(u64) -> bool,
        start: impl FnOnce() -> Result<(Arc<Backend>, Workdir)>,
    ) -> Result<Lease> {
        let key = (capability.name.clone(), principal.to_owned());
        let mut stale = Vec::new();
        let mut map = self.map.lock();
        // Under the map lock: an unload bumps the epoch and then evicts under
        // this same lock, so a call from before the unload either gets its child
        // evicted or is refused here; none starts one that outlives the unload.
        if !epoch_current(self.generation(&capability.name)) {
            return Err(Error::Config(format!(
                "capability '{}' changed while this call was starting; retry",
                capability.name
            )));
        }
        if map.get(&key).is_some_and(|child| {
            child.config != *config || child.env_fp != env_fp || child.timeout != timeout
        }) && let Some(old) = map.remove(&key)
        {
            stale.push(old);
        }
        if !map.contains_key(&key) {
            let live = map
                .keys()
                .filter(|(cap, _)| *cap == capability.name)
                .count();
            if live >= MAX_CHILDREN_PER_CAPABILITY {
                // Evict the least recently used IDLE child; never a busy one.
                let victim = map
                    .iter()
                    .filter(|((cap, _), child)| {
                        *cap == capability.name && child.in_flight.load(Ordering::Acquire) == 0
                    })
                    .min_by_key(|(_, child)| *child.last_used.lock())
                    .map(|(k, _)| k.clone());
                let Some(victim) = victim else {
                    return Err(Error::RateLimited(format!(
                        "capability '{}' already serves {MAX_CHILDREN_PER_CAPABILITY} busy callers; \
                         retry shortly",
                        capability.name
                    )));
                };
                stale.extend(map.remove(&victim));
            }
            let (backend, workdir) = start()?;
            if let Some(deadline) = self.stop_deadline.get() {
                let _ = backend.stop_deadline.set(Arc::clone(deadline));
            }
            map.insert(
                key.clone(),
                Child {
                    backend,
                    config: config.clone(),
                    env_fp,
                    timeout,
                    id: self.next_id.fetch_add(1, Ordering::Relaxed),
                    in_flight: Arc::new(AtomicUsize::new(0)),
                    last_used: Arc::new(Mutex::new(Instant::now())),
                    runtime: tokio::runtime::Handle::try_current().ok(),
                    _workdir: workdir,
                },
            );
        }
        let child = map.get_mut(&key).expect("present: inserted above");
        *child.last_used.lock() = Instant::now();
        child.in_flight.fetch_add(1, Ordering::AcqRel);
        let lease = Lease {
            backend: Arc::clone(&child.backend),
            busy: InFlight(Arc::clone(&child.in_flight), Arc::clone(&child.last_used)),
            id: child.id,
        };
        drop(map);
        // A changed config or the least recently used idle child: healthy, so
        // the graceful stop.
        stop_all(stale, ChildEnd::Graceful);
        Ok(lease)
    }

    /// Stop children idle for at least `idle`, and every child of a
    /// capability not in `loaded` (unloaded or rug-pulled).
    pub(crate) fn evict(&self, idle: Duration, loaded: &dyn Fn(&str) -> bool) {
        let now = Instant::now();
        let mut map = self.map.lock();
        // An unloaded capability's child goes even mid-call, and at once: a
        // revocation. An idle one only when it has no call in flight, and
        // gracefully.
        let unloaded: Vec<_> = map
            .keys()
            .filter(|(cap, _)| !loaded(cap))
            .cloned()
            .collect();
        let idle_keys: Vec<_> = map
            .iter()
            .filter(|((cap, _), child)| {
                loaded(cap)
                    && child.in_flight.load(Ordering::Acquire) == 0
                    && now.duration_since(*child.last_used.lock()) >= idle
            })
            .map(|(k, _)| k.clone())
            .collect();
        let revoked: Vec<Child> = unloaded.iter().filter_map(|k| map.remove(k)).collect();
        let idled: Vec<Child> = idle_keys.iter().filter_map(|k| map.remove(k)).collect();
        #[cfg(test)]
        self.evict_holds_the_lock.pause_on_thread();
        drop(map);
        stop_all(revoked, ChildEnd::Now);
        stop_all(idled, ChildEnd::Graceful);
    }

    /// Start the once-a-minute idle sweep. It holds only a `Weak`, so it
    /// ends with the executor. (Registered backends are swept by the gateway;
    /// these are deliberately not registered.)
    pub(super) fn ensure_sweeper(self: &Arc<Self>) {
        if self.sweeping.swap(true, Ordering::AcqRel) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let weak = Arc::downgrade(self);
        handle.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let Some(children) = weak.upgrade() else {
                    break;
                };
                children.evict(IDLE_STOP, &|_| true);
            }
        });
    }

    /// The current revocation generation of one capability.
    pub(crate) fn generation(&self, capability: &str) -> u64 {
        self.generations
            .lock()
            .get(capability)
            .copied()
            .unwrap_or(0)
    }

    /// Revoke the calls of one capability that read an earlier generation.
    pub(crate) fn bump_generation(&self, capability: &str) {
        // Under the map lock `acquire` holds from its epoch check to the
        // lease, so a reload cannot land between the two. Same
        // order as `acquire`: map, then generations.
        let _admission = self.map.lock();
        *self
            .generations
            .lock()
            .entry(capability.to_owned())
            .or_insert(0) += 1;
    }

    /// Stop one caller's child (a call on it timed out, so it may be wedged).
    pub(super) fn discard(&self, capability: &str, principal: &str, id: u64) {
        let key = (capability.to_owned(), principal.to_owned());
        let mut map = self.map.lock();
        // Only the child that timed out: a newer one under the same key stays.
        let gone = if map.get(&key).is_some_and(|child| child.id == id) {
            map.remove(&key)
        } else {
            None
        };
        drop(map);
        // It timed out: unresponsive, so the kill at once.
        stop_all(gone.into_iter().collect(), ChildEnd::Now);
    }

    /// Mark the caller's child busy, as a call in flight would.
    #[cfg(test)]
    pub(crate) fn hold_for_test(&self, _caller: &str) -> Vec<InFlight> {
        self.map
            .lock()
            .values()
            .map(|child| {
                child.in_flight.fetch_add(1, Ordering::AcqRel);
                InFlight(Arc::clone(&child.in_flight), Arc::clone(&child.last_used))
            })
            .collect()
    }

    /// Clone every child's backend, as a call's lease does, so a test can
    /// keep a "call in flight" past the child's eviction.
    #[cfg(all(test, unix))]
    pub(crate) fn lease_backends_for_test(&self) -> Vec<Arc<Backend>> {
        self.map
            .lock()
            .values()
            .map(|child| Arc::clone(&child.backend))
            .collect()
    }

    /// The id of the one child of `capability`, for tests.
    #[cfg(test)]
    pub(crate) fn id_for_test(&self, capability: &str) -> u64 {
        let map = self.map.lock();
        let (_, child) = map
            .iter()
            .find(|((cap, _), _)| cap == capability)
            .expect("a child exists");
        child.id
    }

    /// `discard` for the only caller used in tests.
    #[cfg(test)]
    pub(crate) fn discard_for_test(&self, capability: &str, id: u64) {
        let principal = {
            let map = self.map.lock();
            map.keys()
                .find(|(cap, _)| cap == capability)
                .map(|(_, p)| p.clone())
                .expect("a child exists")
        };
        self.discard(capability, &principal, id);
    }

    /// Live children, for tests.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.lock().len()
    }
}

/// How a stopped child's process tree ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildEnd {
    /// Healthy (idle, or its config changed): the MCP stdio order, within
    /// its backend's close budget.
    Graceful,
    /// Revoked or unresponsive: the kill at once.
    Now,
}

/// Stop each child's backend (which ends its process tree), then drop its
/// directory. Runs off the caller's path.
fn stop_all(children: Vec<Child>, end: ChildEnd) {
    // Each child stops on the runtime that drives it: the current one may be
    // entered but never driven, and a stop spawned there would never run.
    let current = tokio::runtime::Handle::try_current().ok();
    for child in children {
        // First, synchronously and without any runtime: hand every process tree
        // the child's backend owns, pooled or held by a busy caller, to the
        // reaper. The async stop below may never run on an idle or dropped
        // runtime.
        match end {
            ChildEnd::Graceful => child
                .backend
                .hand_over_now(tokio::time::Instant::now() + child.backend.budgets.close_stage),
            ChildEnd::Now => child.backend.retire_now(),
        }
        let Some(handle) = child.runtime.clone().or_else(|| current.clone()) else {
            continue;
        };
        handle.spawn(async move {
            let _ = child.backend.stop().await;
            drop(child);
        });
    }
}
