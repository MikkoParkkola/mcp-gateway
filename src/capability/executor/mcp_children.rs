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

/// The children and the gateway stop's latch, under one lock: the stop sets
/// the latch in the same hold that takes every child, so no call can put a new
/// child in behind it.
#[derive(Default)]
struct Children {
    by_key: HashMap<(String, String), Child>,
    stopped: bool,
}

/// The executor's private MCP children, keyed by (capability, caller).
#[derive(Default)]
pub(crate) struct McpChildren {
    /// Never held across blocking I/O: a gateway stop takes it plainly.
    map: Mutex<Children>,
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
        let current = |child: &Child| {
            child.config == *config && child.env_fp == env_fp && child.timeout == timeout
        };
        {
            let mut map = self.map.lock();
            self.admit(&map, &capability.name, &epoch_current)?;
            if let Some(child) = map.by_key.get_mut(&key).filter(|child| current(child)) {
                return Ok(lease(child));
            }
        }
        // Built with the map lock released: its directory and its program's
        // PATH lookup are file-system calls a stalled mount can hold, and a
        // gateway stop must never wait on them. A start that fails returns
        // here, before any child has left the map.
        let candidate = start()?;
        // Declared after the candidate, so dropped before it: an unused
        // candidate's directory is removed only once the lock is released.
        let mut map = self.map.lock();
        // Read again right before the insert: an unload (epoch) or a stop
        // (latch) while the candidate was built refuses it here.
        self.admit(&map, &capability.name, &epoch_current)?;
        if let Some(child) = map.by_key.get_mut(&key).filter(|child| current(child)) {
            // Another call put one in meanwhile; the candidate goes unused.
            return Ok(lease(child));
        }
        // Every check that can refuse comes before the first removal, so
        // nothing returns between a removal and its handover.
        let others = map
            .by_key
            .keys()
            .filter(|(cap, caller)| *cap == capability.name && *caller != key.1)
            .count();
        let victim = if others >= MAX_CHILDREN_PER_CAPABILITY {
            // The least recently used IDLE child; never a busy one.
            let victim = map
                .by_key
                .iter()
                .filter(|((cap, caller), child)| {
                    *cap == capability.name
                        && *caller != key.1
                        && child.in_flight.load(Ordering::Acquire) == 0
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
            Some(victim)
        } else {
            None
        };
        // The key's stale child (a changed config) and the victim: healthy,
        // so the graceful end, handed over before the lock is released.
        let removed: Vec<Child> = std::iter::once(&key)
            .chain(victim.as_ref())
            .filter_map(|k| map.by_key.remove(k))
            .collect();
        hand_over(&removed, ChildEnd::Graceful);
        let (backend, workdir) = candidate;
        if let Some(deadline) = self.stop_deadline.get() {
            let _ = backend.stop_deadline.set(Arc::clone(deadline));
        }
        let child = map.by_key.entry(key).insert_entry(Child {
            backend,
            config: config.clone(),
            env_fp,
            timeout,
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            in_flight: Arc::new(AtomicUsize::new(0)),
            last_used: Arc::new(Mutex::new(Instant::now())),
            runtime: tokio::runtime::Handle::try_current().ok(),
            _workdir: workdir,
        });
        let lease = lease(child.into_mut());
        drop(map);
        finish(removed);
        Ok(lease)
    }

    /// Whether a call may have a child now: refused once the gateway stop has
    /// run, or when the capability changed since the call read it. Read under
    /// the map lock: an unload bumps the epoch and then evicts under it, and a
    /// stop latches under it, so a call is either refused here or its child
    /// is in the map when they look.
    fn admit(
        &self,
        children: &Children,
        capability: &str,
        epoch_current: &impl Fn(u64) -> bool,
    ) -> Result<()> {
        if children.stopped {
            return Err(Error::Config(format!(
                "capability '{capability}': the gateway is stopping"
            )));
        }
        if !epoch_current(self.generation(capability)) {
            return Err(Error::Config(format!(
                "capability '{capability}' changed while this call was starting; retry"
            )));
        }
        Ok(())
    }

    /// End every child for the gateway stop, by `deadline`: the latch and the
    /// handover in one hold of the map lock, busy children included (each
    /// backend's `stopping` latch refuses a leased call's later start).
    pub(crate) fn stop_for_gateway(&self, deadline: tokio::time::Instant) {
        let mut map = self.map.lock();
        map.stopped = true;
        let all: Vec<Child> = map.by_key.drain().map(|(_, child)| child).collect();
        hand_over(&all, ChildEnd::By(deadline));
        drop(map);
        finish(all);
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
            .by_key
            .keys()
            .filter(|(cap, _)| !loaded(cap))
            .cloned()
            .collect();
        let idle_keys: Vec<_> = map
            .by_key
            .iter()
            .filter(|((cap, _), child)| {
                loaded(cap)
                    && child.in_flight.load(Ordering::Acquire) == 0
                    && now.duration_since(*child.last_used.lock()) >= idle
            })
            .map(|(k, _)| k.clone())
            .collect();
        let revoked: Vec<Child> = unloaded
            .iter()
            .filter_map(|k| map.by_key.remove(k))
            .collect();
        let idled: Vec<Child> = idle_keys
            .iter()
            .filter_map(|k| map.by_key.remove(k))
            .collect();
        #[cfg(test)]
        self.evict_holds_the_lock.pause_on_thread();
        // Handed over before the unlock: a gateway stop that takes the lock
        // after this finds them already in the reaper's hands.
        hand_over(&revoked, ChildEnd::Now);
        hand_over(&idled, ChildEnd::Graceful);
        drop(map);
        finish(revoked);
        finish(idled);
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
        // Under the map lock `acquire` holds from its last epoch check to the
        // insert, so a reload cannot land between the two. Same
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
        let gone: Vec<Child> = if map.by_key.get(&key).is_some_and(|child| child.id == id) {
            map.by_key.remove(&key).into_iter().collect()
        } else {
            Vec::new()
        };
        // It timed out: unresponsive, so the kill at once.
        hand_over(&gone, ChildEnd::Now);
        drop(map);
        finish(gone);
    }

    /// Mark the caller's child busy, as a call in flight would.
    #[cfg(test)]
    pub(crate) fn hold_for_test(&self, _caller: &str) -> Vec<InFlight> {
        self.map
            .lock()
            .by_key
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
            .by_key
            .values()
            .map(|child| Arc::clone(&child.backend))
            .collect()
    }

    /// The id of the one child of `capability`, for tests.
    #[cfg(test)]
    pub(crate) fn id_for_test(&self, capability: &str) -> u64 {
        let map = self.map.lock();
        let (_, child) = map
            .by_key
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
            map.by_key
                .keys()
                .find(|(cap, _)| cap == capability)
                .map(|(_, p)| p.clone())
                .expect("a child exists")
        };
        self.discard(capability, &principal, id);
    }

    /// Live children, for tests.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.lock().by_key.len()
    }
}

/// Mark `child` busy for one call.
fn lease(child: &mut Child) -> Lease {
    *child.last_used.lock() = Instant::now();
    child.in_flight.fetch_add(1, Ordering::AcqRel);
    Lease {
        backend: Arc::clone(&child.backend),
        busy: InFlight(Arc::clone(&child.in_flight), Arc::clone(&child.last_used)),
        id: child.id,
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
    /// The gateway stop: the MCP stdio order, planned to end by the stage's
    /// deadline rather than the close budget.
    By(tokio::time::Instant),
}

/// Hand every process tree the children's backends own, pooled or held by a
/// busy caller, to the reaper: synchronously and without any runtime, under
/// the map lock that removed them, so no child is ever out of the map and out
/// of the reaper's hands at once. The async stop in [`finish`] may never run
/// on an idle or dropped runtime.
fn hand_over(children: &[Child], end: ChildEnd) {
    for child in children {
        match end {
            ChildEnd::Graceful => child
                .backend
                .hand_over_now(tokio::time::Instant::now() + child.backend.budgets.close_stage),
            ChildEnd::By(deadline) => child.backend.hand_over_now(deadline),
            ChildEnd::Now => child.backend.retire_now(),
        }
    }
}

/// After the unlock: stop each handed-over child's backend (which waits for
/// its reaps), then drop its directory. Runs off the caller's path.
fn finish(children: Vec<Child>) {
    // Each child stops on the runtime that drives it: the current one may be
    // entered but never driven, and a stop spawned there would never run.
    let current = tokio::runtime::Handle::try_current().ok();
    for child in children {
        let Some(handle) = child.runtime.clone().or_else(|| current.clone()) else {
            continue;
        };
        handle.spawn(async move {
            let _ = child.backend.stop().await;
            drop(child);
        });
    }
}
