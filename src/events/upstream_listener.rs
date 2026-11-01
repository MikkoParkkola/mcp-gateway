// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One listener task per backend that has live upstream-notification
//! subscriptions (MIK-7630 I5 design §5). This file owns the map and the
//! counted interest; the task's connection logic is `upstream_session`.
//!
//! Nothing here reaches `SubscriptionRegistry`: upstream notifications go
//! only to `EventsHub::emit`, so a downstream `subscriptions/listen` client
//! never sees them (§7).

use std::collections::HashMap;
use std::sync::{Arc, Weak};

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::EventsHub;
#[cfg(test)]
use super::types::RpcError;
use super::upstream_need::ledger::Ledger;
use super::upstream_need::{Full, Interest, Need, Snapshot};
use crate::backend::{Backend, BackendRegistry};

/// How often ended listeners are checked for a backend that can be listened
/// to again (MIK-7944 `D6.EVENTS_MISC.6`).
/// ponytail: up to this long between a backend turning eligible and its
/// listener starting; a push from reload and transport detection would cut it.
const REVIVE_EVERY: std::time::Duration = std::time::Duration::from_secs(30);
/// At most one confirming catalogue read per backend this often (MIK-8194):
/// a delivery that would need another within it is admitted, as an
/// unconfirmed absence proves nothing (design section 7).
const CONFIRM_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

#[path = "upstream_listener_authz.rs"]
mod authz;
#[path = "upstream_listener_interest.rs"]
mod interest;
#[path = "upstream_listener_key.rs"]
mod key;
pub(crate) use key::{ListenerKey, MAX_PER_USER_LISTENERS};

/// What one listener task and the event source share.
pub(super) struct Shared {
    pub name: String,
    /// The listener this task is: `name` is its backend.
    pub key: ListenerKey,
    pub need: Mutex<Need>,
    /// What the backend's legacy holders may keep of ours (D5). Shared by
    /// every task of the backend; taken after `need` when both are held.
    /// Swapped by [`Shared::refresh_ledger`] when the backend is replaced.
    pub ledger: Mutex<Arc<Mutex<Ledger>>>,
    /// The registry's current backend's ledger, from the listener map.
    pub resolve: Box<dyn Fn() -> Option<Arc<Mutex<Ledger>>> + Send + Sync>,
    pub snapshot: Mutex<Snapshot>,
    /// A modern stream's age at which it is replaced (D2); tests shorten it.
    pub recycle: std::time::Duration,
    /// Bumped on every change of the upstream filter.
    pub wake: watch::Sender<u64>,
    pub stop: CancellationToken,
    /// Held for a task's whole life, its stop cleanup included, so a
    /// successor for the same backend starts only after it.
    pub gate: Arc<tokio::sync::Mutex<()>>,
    /// The backends the live config makes unable to offer upstream events,
    /// read at each use (MIK-7894).
    pub ineligible: super::backend_source::Ineligible,
    /// The backend tools notices not yet served. Kept across sessions, so one
    /// that ends first does not drop them (MIK-8007). Not across a task stop:
    /// that ends the interest they were owed to.
    pub tools: Mutex<super::upstream_session::ToolsDebt>,
    /// Test pause between a task finding its backend gone and parking (T35).
    #[cfg(test)]
    pub before_park: Arc<crate::test_pause::Slot>,
    /// Test pause as a task starts its reconnect backoff (T35).
    #[cfg(test)]
    pub before_backoff: Arc<crate::test_pause::Slot>,
    /// What ended each of the task's waits, and when it began one (T35).
    #[cfg(test)]
    pub waits: super::upstream_session::WaitProbe,
    /// Whether the task ran where a login may begin, read as it starts
    /// (MIK-8269): background upkeep must not.
    #[cfg(test)]
    pub ran_interactive: Mutex<Option<bool>>,
}

impl Shared {
    /// What a log line may say of `error`: a per-user listener's transport
    /// errors can echo its subscriber's credential, so only that the error
    /// happened is logged.
    pub(super) fn error_text(&self, error: &dyn std::fmt::Display) -> String {
        if self.key.obs.is_some() {
            "withheld".to_owned()
        } else {
            error.to_string()
        }
    }

    /// Whether the live config now refuses this backend's upstream events.
    pub(super) fn is_ineligible(&self) -> bool {
        (self.ineligible)().contains(&self.name)
    }

    /// The ledger this task charges now.
    pub(super) fn ledger(&self) -> Arc<Mutex<Ledger>> {
        Arc::clone(&self.ledger.lock())
    }

    /// At a session start: a backend replaced in the config since the task
    /// started gets its own ledger (a D5 release point), and the interest
    /// still counted takes keys there.
    pub(super) fn refresh_ledger(&self) {
        let Some(fresh) = (self.resolve)() else {
            return;
        };
        let need = self.need.lock();
        let mut slot = self.ledger.lock();
        if !Arc::ptr_eq(&slot, &fresh) {
            // The snapshot was read from the instance this ledger replaces:
            // cleared first, so no reader sees the new ledger with it.
            self.snapshot.lock().clear();
            fresh.lock().want_all(need.filter().1);
            *slot = fresh;
        }
    }

    /// Nothing is watched and no pass can release anything more: the task
    /// ends (D5 cleanup outlives interest only while it has work).
    pub(super) fn is_idle(&self) -> bool {
        self.need.lock().is_empty() && !self.ledger().lock().needs_cleanup()
    }

    /// The task's own stop once idle, decided under `need` so a concurrent
    /// admission either lands first (not idle) or sees the stop.
    pub(super) fn cancel_if_idle(&self) {
        let need = self.need.lock();
        if need.is_empty() && !self.ledger().lock().needs_cleanup() {
            self.stop.cancel();
        }
    }
}

/// An ended entry for `backend` (its task stopped, or never started, while the
/// backend could not be listened to) is replaced, not reused, when it is
/// listened to again. The replacement inherits the interest still counted
/// (the `tools_changed` keys kept meanwhile), so their removal later balances
/// against it.
fn take_ended(map: &mut HashMap<ListenerKey, Arc<Shared>>, key: &ListenerKey) -> Need {
    match map.get(key).filter(|s| s.stop.is_cancelled()) {
        Some(ended) => {
            let carried = std::mem::take(&mut *ended.need.lock());
            map.remove(key);
            carried
        }
        None => Need::default(),
    }
}

/// A backend's ledger and the `Backend` it was made for.
type LedgerSlot = (Weak<Backend>, Arc<Mutex<Ledger>>);

/// The per-backend listeners of one hub.
pub(crate) struct UpstreamListeners {
    registry: Arc<BackendRegistry>,
    hub: Weak<EventsHub>,
    backends: Mutex<HashMap<ListenerKey, Arc<Shared>>>,
    ineligible: super::backend_source::Ineligible,
    gates: Mutex<HashMap<ListenerKey, Arc<tokio::sync::Mutex<()>>>>,
    /// Per backend, kept while the registry holds the same `Backend`: a
    /// backend removed from (or replaced in) the config, or a restart, is
    /// the only thing that drops a ledger (D5 release points).
    ledgers: Mutex<HashMap<ListenerKey, LedgerSlot>>,
    stop: CancellationToken,
    /// Tasks `start` has spawned: a task started wrongly for a refused
    /// backend cancels itself at once, so its entry alone cannot show it.
    #[cfg(test)]
    pub(super) starts: std::sync::atomic::AtomicUsize,
    /// Shared by every entry: the first task to park stops there (T35).
    #[cfg(test)]
    pub(super) before_park: Arc<crate::test_pause::Slot>,
    me: Weak<UpstreamListeners>,
    /// When each listener's last confirming read began (`CONFIRM_EVERY`).
    confirmed: Mutex<HashMap<ListenerKey, tokio::time::Instant>>,
}

impl Drop for UpstreamListeners {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl EventsHub {
    /// A complete read of `backend`'s catalogue lacks some watched URIs: end
    /// those `resource_updated` subscriptions now, freeing their interest
    /// and URI budget instead of waiting for an occurrence (parent F9, §7).
    /// Only rows granted by `granted_by` (the generation when the read
    /// began) are judged: a later grant was not covered by this read.
    pub(super) async fn revoke_absent_uris(
        self: &Arc<Self>,
        key: &ListenerKey,
        listed: &std::collections::HashSet<String>,
        granted_by: u64,
    ) {
        let name = format!("backend.{}.resource_updated", key.backend);
        // A 1969 `now` reads expired rows live and would revoke them, dropping
        // their records with no expiry burial. Skipped: the next complete read
        // revokes again, and delivery is idle on such a clock (MIK-8202).
        let Ok(now) = crate::clock::utc_now() else {
            tracing::warn!(
                clock_unreadable = true,
                "events: absent resources not revoked; the host clock reads before 1970"
            );
            return;
        };
        let gone: Vec<_> = self
            .store
            .subscriptions()
            .into_iter()
            .filter(|s| s.name == name && s.live(now) && s.incarnation <= granted_by)
            // One subscriber's catalogue read judges only their own rows.
            .filter(|s| self.listens_as(s, key))
            .filter(|s| {
                s.arguments
                    .get("uri")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|u| !listed.contains(u))
            })
            .collect();
        for sub in gone {
            self.revoke(&sub).await;
        }
    }
}

impl EventsHub {
    /// Whether `sub` is served by listener `key`: a shared row by the
    /// backend's shared listener, a per-user row by the listener of the
    /// observation its stored identity derives now.
    pub(super) fn listens_as(&self, sub: &super::records::Subscription, key: &ListenerKey) -> bool {
        match &key.obs {
            None => sub.obs_basis.is_none(),
            Some(obs) => self.runtime.services.get().is_some_and(|services| {
                super::observation::observe_row(&services.live.get(), &key.backend, sub)
                    .ok()
                    .flatten()
                    .as_deref()
                    == Some(obs.as_str())
            }),
        }
    }
}

tokio::task_local! {
    /// Set inside an events delivery attempt once a catalogue lookup failed
    /// or timed out; outside an attempt it is unset and every call reads.
    pub(super) static FAILED_LOOKUP: std::cell::Cell<bool>;
}

impl UpstreamListeners {
    /// Whether the listener predicate refuses `backend` now.
    pub(crate) fn refuses(&self, backend: &str) -> bool {
        (self.ineligible)().contains(backend)
    }

    pub(crate) fn new(
        registry: Arc<BackendRegistry>,
        hub: Weak<EventsHub>,
        ineligible: super::backend_source::Ineligible,
    ) -> Arc<Self> {
        let listeners = Arc::new_cyclic(|me| Self {
            me: me.clone(),
            registry,
            hub,
            ineligible,
            backends: Mutex::new(HashMap::new()),
            gates: Mutex::new(HashMap::new()),
            ledgers: Mutex::new(HashMap::new()),
            confirmed: Mutex::new(HashMap::new()),
            stop: CancellationToken::new(),
            #[cfg(test)]
            starts: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            before_park: Arc::default(),
        });
        // Weak: a strong reference here would keep `Drop` from ever
        // cancelling the listeners. No runtime (a plain unit test): no sweep.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let (weak, stop) = (Arc::downgrade(&listeners), listeners.stop.clone());
            runtime.spawn(async move {
                loop {
                    tokio::select! {
                        () = stop.cancelled() => return,
                        () = tokio::time::sleep(REVIVE_EVERY) => {}
                    }
                    let Some(listeners) = weak.upgrade() else {
                        return;
                    };
                    listeners.revive();
                }
            });
        }
        listeners
    }

    /// One revive pass: start every ended entry whose backend can be
    /// listened to again. Eligibility is read once, before the map lock; a
    /// backend refused again before its task runs is stopped at that task's
    /// loop head. Collect and replace share one hold of the map lock that
    /// `add` and `remove` take, so no key changes in between.
    fn revive(&self) {
        self.revive_where(|_| true);
    }

    /// Revive every listener of backend `name` now rather than at the
    /// sweep: its registration changed (design r3 L2).
    pub(crate) fn revive_backend(&self, name: &str) {
        self.revive_where(|of| of.backend == name);
        // A task parked while its backend was gone retries now, not in 30 s.
        for (key, shared) in self.backends.lock().iter() {
            if key.backend == name {
                shared.wake.send_modify(|n| *n += 1);
            }
        }
    }

    fn revive_where(&self, only: impl Fn(&ListenerKey) -> bool) {
        let refused = (self.ineligible)();
        let mut map = self.backends.lock();
        let due: Vec<ListenerKey> = map
            .iter()
            .filter(|(key, shared)| only(key) && self.revivable(key, shared, &refused))
            .map(|(key, _)| key.clone())
            .collect();
        // Logged once `map` is released.
        let mut revived = Vec::with_capacity(due.len());
        for key in due {
            let carried = take_ended(&mut map, &key);
            revived.push(key.backend.clone());
            let shared = self.start(&key, carried, self.ledger(&key));
            map.insert(key, shared);
        }
        drop(map);
        for backend in revived {
            tracing::debug!(backend = %backend, "upstream listener: revived");
        }
    }

    /// An ended entry, of a registered backend that is not refused.
    fn revivable(
        &self,
        key: &ListenerKey,
        shared: &Shared,
        refused: &std::collections::BTreeSet<String>,
    ) -> bool {
        shared.stop.is_cancelled()
            && self.knows(&key.backend)
            && !refused.contains(&key.backend)
            && self.may_run(key)
    }

    /// The entry whose snapshot may answer for `backend`: none when its
    /// ledger was made for an instance the registry no longer holds, so a
    /// replaced backend is judged live (design r3 L4, MIK-7897 LIFE.3b).
    fn answering(&self, key: &ListenerKey) -> Option<Arc<Shared>> {
        let entry = self.backends.lock().get(key).cloned()?;
        #[allow(
            clippy::disallowed_methods,
            reason = "Background: the events source watches backends; no caller request"
        )]
        let now = self.registry.get(&key.backend);
        let current = entry.ledger();
        // Replaced: the ledgers map holds another instance, or the entry has
        // not yet taken the map's ledger (a swap in progress).
        let replaced = self
            .ledgers
            .lock()
            .get(key)
            .is_some_and(|(made_for, ledger)| {
                !Arc::ptr_eq(ledger, &current)
                    || now
                        .as_ref()
                        .is_none_or(|b| !std::ptr::eq(made_for.as_ptr(), Arc::as_ptr(b)))
            });
        (!replaced).then_some(entry)
    }

    /// The entry for `backend`, so a session-level test can drive it.
    #[cfg(test)]
    pub(super) fn entry_of(&self, backend: &str) -> Option<Arc<Shared>> {
        self.entry_for(&ListenerKey::shared(backend))
    }

    /// The entry for `key`, so a test can drive a per-user listener.
    #[cfg(test)]
    pub(super) fn entry_for(&self, key: &ListenerKey) -> Option<Arc<Shared>> {
        self.backends.lock().get(key).cloned()
    }

    /// The hub these listeners serve, while it lives.
    pub(super) fn hub(&self) -> Option<Arc<EventsHub>> {
        self.hub.upgrade()
    }

    /// The live config, to re-derive a row's observation;
    /// `None` before the events services are wired.
    pub(super) fn live_config(&self) -> Option<Arc<crate::config::Config>> {
        let hub = self.hub.upgrade()?;
        Some(hub.runtime.services.get()?.live.get())
    }

    /// Whether `backend` may take a confirming read now; records it if so.
    pub(super) fn may_confirm(&self, key: &ListenerKey) -> bool {
        let now = tokio::time::Instant::now();
        let mut confirmed = self.confirmed.lock();
        // Only windows still open are kept, so the map never outgrows them.
        confirmed.retain(|_, at| now.duration_since(*at) < CONFIRM_EVERY);
        if confirmed
            .get(key)
            .is_some_and(|at| now.duration_since(*at) < CONFIRM_EVERY)
        {
            return false;
        }
        confirmed.insert(key.clone(), now);
        true
    }

    /// The listener's ledger, fresh when the registry holds another
    /// `Backend` than the one it was made for. One per key: one subscriber's
    /// legacy holders never keep another's (ISO-T4c).
    fn ledger(&self, key: &ListenerKey) -> Arc<Mutex<Ledger>> {
        #[allow(
            clippy::disallowed_methods,
            reason = "Background: the events source watches backends; no caller request"
        )]
        let current = self
            .registry
            .get(&key.backend)
            .map_or_else(Weak::new, |b| Arc::downgrade(&b));
        let mut ledgers = self.ledgers.lock();
        if current.strong_count() == 0 {
            // Removed from the config: its charges are released with it.
            ledgers.remove(key);
            return Arc::new(Mutex::new(Ledger::default()));
        }
        if let Some((made_for, ledger)) = ledgers.get(key)
            && Weak::ptr_eq(made_for, &current)
        {
            return Arc::clone(ledger);
        }
        let ledger = Arc::new(Mutex::new(Ledger::default()));
        ledgers.insert(key.clone(), (current, Arc::clone(&ledger)));
        ledger
    }

    fn start(&self, key: &ListenerKey, need: Need, ledger: Arc<Mutex<Ledger>>) -> Arc<Shared> {
        #[cfg(test)]
        self.starts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let shared = self.entry(key, need, ledger);
        // Background upkeep never opens a browser (MIK-8269): every bounded
        // open, refill and subscription the session sends would otherwise lead
        // a login and end it `Cancelled` when its bound fires.
        tokio::spawn(crate::oauth::login_gate::non_interactive(
            super::upstream_session::run(
                Arc::clone(&shared),
                Arc::clone(&self.registry),
                self.hub.clone(),
            ),
        ));
        shared
    }

    fn entry(&self, key: &ListenerKey, need: Need, ledger: Arc<Mutex<Ledger>>) -> Arc<Shared> {
        // Interest carried into a fresh ledger takes its keys there.
        ledger.lock().want_all(need.filter().1);
        let (wake, _) = watch::channel(0);
        Arc::new(Shared {
            name: key.backend.clone(),
            key: key.clone(),
            need: Mutex::new(need),
            ledger: Mutex::new(ledger),
            resolve: {
                let (me, key) = (self.me.clone(), key.clone());
                Box::new(move || me.upgrade().map(|l| l.ledger(&key)))
            },
            recycle: super::upstream_session::RECYCLE,
            snapshot: Mutex::new(Snapshot::default()),
            wake,
            stop: self.stop.child_token(),
            gate: Arc::clone(self.gates.lock().entry(key.clone()).or_default()),
            ineligible: Arc::clone(&self.ineligible),
            tools: Mutex::default(),
            #[cfg(test)]
            before_park: Arc::clone(&self.before_park),
            #[cfg(test)]
            before_backoff: Arc::default(),
            #[cfg(test)]
            waits: super::upstream_session::WaitProbe::default(),
            #[cfg(test)]
            ran_interactive: Mutex::default(),
        })
    }
}

/// Count `interest`; a URI new to the need must first find room in the
/// ledger, the admission authority (D5).
fn admit(shared: &Shared, need: &mut Need, interest: &Interest) -> Result<bool, Full> {
    let new_uri = match interest {
        Interest::ResourceUpdated(uri) if !need.watches(uri) => Some(uri),
        _ => None,
    };
    if let Some(uri) = new_uri {
        shared.ledger().lock().want(uri)?;
    }
    let outcome = need.add(interest);
    if let (Err(_), Some(uri)) = (&outcome, new_uri) {
        shared.ledger().lock().unwant(uri);
    }
    outcome
}

#[cfg(test)]
#[path = "upstream_listener_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "upstream_charge_tests.rs"]
mod charge_tests;

#[cfg(test)]
#[path = "upstream_listener_keys_tests.rs"]
mod keys_tests;
