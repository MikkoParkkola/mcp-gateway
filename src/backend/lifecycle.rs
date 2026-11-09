// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend construction and connection lifecycle: creation, starting pool
//! slots (stdio/HTTP transport launch, OAuth client setup, runtime-provider
//! policy enforcement), stopping, and health-probe-driven recovery.

use std::sync::Arc;

use std::sync::atomic::{AtomicU64, Ordering};

use std::time::Duration;

use dashmap::DashMap;

use tokio::sync::Semaphore;

use tracing::{debug, warn};

use super::pool::{PoolKey, PooledEntry};

use super::Backend;
use crate::config::{BackendConfig, TransportConfig};
use crate::runtime::RuntimePlan;
use crate::transport::Transport;

use crate::{Error, Result};

/// A transport start, erased to `dyn Future`: the start future is deep enough
/// that proving the dispatch future `Send` through it overflows the trait
/// solver (E0275). The erasure restarts that proof.
type StartFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Arc<dyn Transport>>> + Send + 'a>>;

/// Consecutive unserved probe answers the gateway tolerates before it treats
/// the peer as faulty (MIK-7217, OUTBOUND.2).
///
/// Three rather than one because a single refusal is the normal answer of a
/// peer whose era the cache has just got wrong, and that case corrects itself
/// on the next tick. Three rather than many because the escalation is the only
/// thing standing between "declines the probe" and "declines everything".
pub(super) const UNSERVED_ESCALATION: u64 = 3;

/// Clears [`Backend::probe_in_flight`] however the probe leaves - the arms
/// return from five places and a flag left set would stop every later tick.
pub(super) struct ProbeInFlight<'a>(pub(super) &'a std::sync::atomic::AtomicBool);

impl Drop for ProbeInFlight<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Backend {
    /// Create a new backend
    #[must_use]
    pub fn new(
        name: &str,
        config: BackendConfig,
        failsafe_config: &crate::config::FailsafeConfig,
        cache_ttl: Duration,
    ) -> Self {
        Self::new_with_runtime_plan(name, config, failsafe_config, cache_ttl, None)
    }

    /// Create a new backend with an optional precompiled runtime plan.
    #[must_use]
    pub fn new_with_runtime_plan(
        name: &str,
        config: BackendConfig,
        failsafe_config: &crate::config::FailsafeConfig,
        cache_ttl: Duration,
        runtime_plan: Option<RuntimePlan>,
    ) -> Self {
        let sign_in = super::sign_in_state::SignInState::for_config(&config);
        Self {
            name: name.to_string(),
            metric_label: Arc::<str>::from(name).into(),
            notify_origin: Arc::from(name),
            config,
            runtime_plan,
            pool: Arc::new({
                let pool = DashMap::new();
                pool.insert(
                    PoolKey::Shared,
                    Arc::new(PooledEntry::new(name, failsafe_config)),
                );
                pool
            }),
            caller_slots: DashMap::new(),
            caller_slot_stored: tokio::sync::Notify::new(),
            failsafe_config: failsafe_config.clone(),
            #[cfg(all(test, feature = "webui"))]
            server_state_evaluations: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            after_reprobe_lookup: crate::test_pause::Slot::default(),
            #[cfg(test)]
            before_lease_lookup: crate::test_pause::Slot::default(),
            #[cfg(test)]
            before_listing_prepass: crate::test_pause::Slot::default(),
            #[cfg(test)]
            cold_winner: crate::test_pause::Slot::default(),
            #[cfg(test)]
            after_warm_capture: crate::test_pause::Slot::default(),
            #[cfg(test)]
            skip_account_prepass: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            unfilled_outcome_reads: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            lend_refusals: parking_lot::Mutex::default(),
            unserved_consecutive: AtomicU64::new(0),
            unserved_total: AtomicU64::new(0),
            probe_in_flight: std::sync::atomic::AtomicBool::new(false),
            cache_ttl,
            last_used: std::sync::atomic::AtomicU64::new(0),
            semaphore: Semaphore::new(100),
            request_count: std::sync::atomic::AtomicU64::new(0),
            list_fills: AtomicU64::new(0),
            replaced_transport_cleanups: parking_lot::Mutex::new(super::CleanupState::default()),
            identity_slots: Arc::default(),
            lifecycle: tokio::sync::RwLock::new(()),
            descriptor_gate: super::descriptor_gate::DescriptorGate::default(),
            stop_once: tokio::sync::Mutex::new(()),
            stopped: std::sync::atomic::AtomicBool::new(false),
            budgets: super::ShutdownBudgets::default(),
            starts_in_flight: std::sync::atomic::AtomicUsize::new(0),
            events_resolution: parking_lot::Mutex::new(None),
            #[cfg(test)]
            events_resolutions: std::sync::atomic::AtomicUsize::new(0),
            connected_unpinned: std::sync::atomic::AtomicBool::new(false),
            login_gate: Arc::default(),
            sign_in,
            destination: std::sync::OnceLock::new(),
            secret_resolver: std::sync::OnceLock::new(),
            needles: std::sync::OnceLock::new(),
            configured: std::sync::OnceLock::new(),
            started: std::sync::OnceLock::new(),
            #[cfg(test)]
            mark_window_gate: parking_lot::Mutex::new(None),
            #[cfg(test)]
            era_decision_gate: parking_lot::Mutex::new(None),
            #[cfg(test)]
            publish_gate: parking_lot::Mutex::new(None),
            #[cfg(test)]
            restart_take_gate: parking_lot::Mutex::new(None),
            #[cfg(test)]
            probe_error_gate: parking_lot::Mutex::new(None),
            #[cfg(test)]
            rebuilds_attempted: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            last_oauth_client: parking_lot::Mutex::new(None),
            #[cfg(test)]
            between_install_and_write: parking_lot::Mutex::new(None),
            #[cfg(test)]
            between_listen_and_transport: parking_lot::Mutex::new(None),
            #[cfg(test)]
            era_at_publish: parking_lot::Mutex::new(Vec::new()),
            #[cfg(test)]
            oauth_test_seam: parking_lot::Mutex::new(None),
            instance: super::tools_nudge::next_instance(),
            nudge_feed: std::sync::OnceLock::new(),
            stop_deadline: std::sync::OnceLock::new(),
            views_dirty: std::sync::Arc::default(),
            #[cfg(test)]
            snapshot_seam: parking_lot::Mutex::new(None),
            #[cfg(test)]
            shared_read_seam: parking_lot::Mutex::new(None),
        }
    }

    /// Ensure backend is started
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails to start.
    pub async fn ensure_started(&self) -> Result<()> {
        self.ensure_entry_started(&PoolKey::Shared).await?;
        Ok(())
    }

    /// Wait until no start of the shared slot is in flight; nothing is held
    /// after (MIK-8269). For one-shot upkeep that a non-interactive scope
    /// would otherwise refuse while a start holds the slot, often only to
    /// reconnect with a stored token. Waiting never begins or joins a login:
    /// the start's own login runs in its own task.
    pub(crate) async fn start_settled(&self) {
        drop(self.shared_entry().start_lock.lock().await);
    }

    /// Start the pooled entry for `key` if needed; return its live transport.
    ///
    /// Double-checked under the entry's own start lock so concurrent callers for
    /// the same slot never spawn duplicate connections, while different slots
    /// (distinct users) start independently and in parallel.
    ///
    /// TOCTOU guard against `evict_idle_per_user_entries` (MIK-6735 POOL race
    /// fix): the idle evictor can `remove_if` a per-user slot from `pool`
    /// concurrently with this method building that same slot's transport —
    /// the slot was cloned out via `pooled_entry` before it was touched, so
    /// the evictor's idleness re-check still sees it as stale and wins the
    /// race. If that happens, `entry` becomes orphaned: no longer reachable
    /// via `self.pool`, and `PooledEntry` has no async `Drop` to close a
    /// transport stored on an orphaned instance, so it would otherwise leak
    /// the connection until OS teardown. After `start_entry` returns, this
    /// method re-checks (by `Arc::ptr_eq`) that `key` still maps to the exact
    /// entry it started; if the evictor won, it closes the just-built
    /// transport itself — the side that loses the race owns the close — and
    /// retries once against a fresh entry (bounded so a hypothetical
    /// coincidence of repeated evictions cannot spin forever).
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails to start, or if the entry is
    /// repeatedly evicted out from under every start attempt.
    pub(super) async fn ensure_entry_started(&self, key: &PoolKey) -> Result<Arc<dyn Transport>> {
        const MAX_RACE_RETRIES: u8 = 3;

        // MIK-7982 C1: the login this caller would wait behind, captured
        // before it queues on the start lock.
        let cohort = self.login_gate.cohort();
        // The cancel epoch it set out at, captured with the cohort: a restart
        // that cancels while this start queues or discovers refuses its login.
        let set_out = self.login_gate.epoch();

        for _attempt in 0..MAX_RACE_RETRIES {
            let entry = self.pooled_entry(key)?;
            // NOTE: deliberately does NOT touch the idle clocks. `last_used` means
            // "when did a CLIENT last use this backend", and is written only by the
            // request/notify paths in `ops.rs`. Touching it here is what made idle
            // stopping unreachable in an earlier attempt: `health_probe` ->
            // `ensure_started` -> here, on a 10s default health interval against a
            // 300s deadline, refreshed the clock forever. The health loop kept every
            // backend permanently warm and the feature was a silent no-op.

            {
                let transport = entry.transport.read();
                if let Some(t) = transport.as_ref()
                    && t.is_connected()
                {
                    return Ok(Arc::clone(t));
                }
            }

            // MIK-7982 C2: a non-interactive caller (the health probe) never
            // queues behind a start in flight, which may be a login holding
            // this lock for minutes; it answers at once instead.
            let start_guard = if crate::oauth::login_gate::interactive() {
                entry.start_lock.lock().await
            } else {
                entry
                    .start_lock
                    .try_lock()
                    .map_err(|_| Error::AuthorizationRequired {
                        backend: self.name.clone(),
                    })?
            };

            {
                let transport = entry.transport.read();
                if let Some(t) = transport.as_ref()
                    && t.is_connected()
                {
                    return Ok(Arc::clone(t));
                }
            }

            // The login this caller queued behind ended without a token: it
            // shares that end rather than opening a login of its own.
            if let Some(outcome) = cohort.outcome() {
                return Err(outcome.to_error(&self.name));
            }

            // Start transport for this slot, erased (see `StartFuture`).
            let start: StartFuture<'_> = Box::pin(self.start_entry(key, &entry));
            // The start's login carries the cohort captured before it queued,
            // so a failure recorded after the check above is still shared at
            // `begin` (MIK-8339).
            let transport =
                crate::oauth::login_gate::set_out_with_cohort(set_out, Arc::clone(&cohort), start)
                    .await?;

            // Reconcile: did the evictor remove this exact entry while we
            // were building its transport?
            if let Some(transport) = self.reconcile_after_start(key, &entry, transport).await {
                // Resolve the peer's protocol era on the start path, so the
                // first request already knows which dialect to speak. Runs
                // under this slot's `start_lock`; see `Backend::resolve_era`
                // for the lock order that imposes.
                self.resolve_era_after_start(&transport, &entry).await;
                // Announced only after the slot is free, so a listener that
                // acts on it (a pending upstream cancel, MIK-8347) is not
                // refused by this very start.
                drop(start_guard);
                if matches!(key, PoolKey::Shared) {
                    self.announce_started();
                }
                return Ok(transport);
            }
            // Lost the race: `reconcile_after_start` already closed the
            // orphaned transport. Loop and re-derive a fresh entry for `key`.
        }

        Err(Error::BackendUnavailable(self.name.clone()))
    }

    /// After [`Backend::start_entry`] builds and stores a transport into
    /// `entry` for `key`, verify `entry` is still the exact instance the pool
    /// has registered under `key` (by `Arc::ptr_eq`) -- i.e. that
    /// [`Backend::evict_idle_per_user_entries`] did not `remove_if` it out
    /// from under this in-flight start.
    ///
    /// Returns `Some(transport)` when `entry` is still live: the transport is
    /// visible to every future caller of `pooled_entry(key)` and callers here
    /// own nothing extra to clean up. Returns `None` when the race was lost:
    /// `entry` is orphaned (unreachable via `self.pool`), so nothing else will
    /// ever call `close()` on the transport just stored into it -- there is no
    /// async `Drop` for `PooledEntry` -- which would otherwise leak the
    /// underlying connection until OS teardown. In that case this method
    /// takes the transport back out and closes it itself before returning
    /// `None`, so the side that loses the race is the side that owns the
    /// close.
    pub(super) async fn reconcile_after_start(
        &self,
        key: &PoolKey,
        entry: &Arc<PooledEntry>,
        transport: Arc<dyn Transport>,
    ) -> Option<Arc<dyn Transport>> {
        let still_registered = self
            .pool
            .get(key)
            .is_some_and(|slot| Arc::ptr_eq(slot.value(), entry));
        if still_registered {
            return Some(transport);
        }

        warn!(
            backend = %self.name,
            "Pooled entry evicted mid-start; closing the orphaned transport \
             we just built to avoid a connection leak"
        );
        // Bind the taken value before awaiting: `if let Some(x) = guard.take() {
        // ... x.await ... }` would extend the `parking_lot::RwLockWriteGuard`
        // temporary's lifetime across the `.await` (not `Send`), so the guard
        // must be dropped by the end of this `let` statement first.
        let orphaned = entry.transport.write().take();
        if let Some(orphaned) = orphaned {
            let _ = orphaned.close().await;
        }
        None
    }

    /// Resolve the era for a transport that did not resolve it while starting.
    ///
    /// HTTP resolves it inside [`Backend::start_entry`], because that is where
    /// RFC-0061 §2.4's handshake decision is taken and the decision needs the
    /// answer. Probing again here would not merely duplicate a request: the
    /// start path probes through `restart_with`, which discards first, so a
    /// second call would throw away a verdict the peer has already given and
    /// re-derive it — and the transport shapes requests from that cache while
    /// it is empty. Every other transport still resolves here, unchanged.
    pub(super) async fn resolve_era_after_start(
        &self,
        transport: &Arc<dyn Transport>,
        entry: &PooledEntry,
    ) {
        if matches!(self.config.transport, TransportConfig::Http { .. }) {
            return;
        }
        self.resolve_era(transport, entry).await;
    }

    /// Start the backend's canonical (shared) transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails to connect or initialize.
    pub async fn start(&self) -> Result<()> {
        let entry = self.shared_entry();
        self.start_entry(&PoolKey::Shared, &entry).await?;
        Ok(())
    }

    /// Mark the backend as having a start that may connect, and read the policy
    /// it builds under, in one step under the lock a pairing holds from its
    /// check to its stamp: either this start reads the stamp, or it marks the
    /// backend so that pairing refuses it. For a transport that connects as it
    /// is built.
    fn mark_connecting(&self) -> crate::security::ssrf::DestinationPolicy {
        let _pairing = self.replaced_transport_cleanups.lock();
        if self.destination.get().is_none() {
            self.connected_unpinned
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        self.destination()
    }

    /// Wait at a test's [`super::MarkWindowGate`], when one is set.
    #[cfg(test)]
    async fn hold_in_mark_window(&self) {
        hold_at(&self.mark_window_gate).await;
    }

    /// Wait at a test's era-decision gate, when one is set (MIK-8056).
    #[cfg(test)]
    async fn hold_at_era_decision(&self) {
        hold_at(&self.era_decision_gate).await;
    }

    /// The same marking for a transport built under `built_under` before it
    /// connects. A pairing that stamped a policy in between would leave the
    /// connection about to be made unpinned, so the start is refused instead.
    fn begin_connecting(
        &self,
        built_under: crate::security::ssrf::DestinationPolicy,
    ) -> Result<()> {
        let pairing = self.replaced_transport_cleanups.lock();
        if self.destination.get().is_none() {
            self.connected_unpinned
                .store(true, std::sync::atomic::Ordering::SeqCst);
            return Ok(());
        }
        if self.destination() == built_under {
            return Ok(());
        }
        drop(pairing);
        debug!(backend = %self.name, "Not connecting: the destination policy changed while it was starting");
        Err(Error::BackendUnavailable(self.name.clone()))
    }

    /// A per-user listener's own HTTP transport, unstarted: the backend's URL,
    /// timeout, flavour and protocol version under its live destination
    /// policy, and nothing of the gateway's own credential (no static
    /// headers, no OAuth). Built per run, so the shared slot is never started
    /// or read for a listener that observes as one subscriber.
    ///
    /// # Errors
    /// The backend is not reached over HTTP, its URL cannot be sent to, or
    /// its destination policy changed while the transport was built.
    pub(crate) fn listener_transport(&self) -> Result<Arc<crate::transport::HttpTransport>> {
        let crate::config::TransportConfig::Http {
            http_url,
            streamable_http,
            protocol_version,
        } = &self.config.transport
        else {
            return Err(Error::Transport(
                "a per-user listener needs an HTTP backend".to_owned(),
            ));
        };
        http_target(http_url)?;
        let built_under = self.destination();
        let transport = crate::transport::HttpTransport::with_destination(
            http_url,
            std::collections::HashMap::new(),
            self.config.timeout,
            *streamable_http,
            None,
            protocol_version.clone(),
            built_under,
        )?;
        transport.mark_single_tenant();
        self.attach_needles_to(&transport);
        // The same pairing check a slot's start runs: refused when the
        // policy changed since it was read, and recorded when none is pinned.
        self.begin_connecting(built_under)?;
        Ok(transport)
    }
}

/// Wait at the test gate held in `slot`, when one is set: signal `reached`,
/// then wait for `release`.
#[cfg(test)]
pub(super) async fn hold_at(slot: &parking_lot::Mutex<Option<Arc<super::MarkWindowGate>>>) {
    let gate = slot.lock().clone();
    if let Some(gate) = gate {
        gate.reached.notify_one();
        gate.release.notified().await;
    }
}

/// Refuse an HTTP backend URL no request can be sent to (a scheme other than
/// `http`/`https`, or no host). Such a start fails without connecting, so it
/// is refused before anything is built or marked (MIK-7855).
fn http_target(http_url: &str) -> Result<()> {
    if url::Url::parse(http_url)
        .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.has_host())
    {
        return Ok(());
    }
    Err(Error::TransportPermanent(
        "Invalid transport base URL: not an http:// or https:// URL with a host".into(),
    ))
}

/// A start that failed before the request was sent (MIK-7979). The transport
/// reports a failed spawn, handshake or `initialize` as `Transport` or
/// `BackendTimeout`, which on the dispatch path would read as a lost round and
/// burn the caller's idempotency key for work that never ran. It is a pre-send
/// refusal, so it becomes `BackendUnavailable`, which frees the key and stays
/// retryable. `TransportPermanent` (a command that does not exist) and the
/// gateway's own refusals pass through unchanged.
pub(super) fn pre_send_start_error(backend: &str, error: Error) -> Error {
    match error {
        Error::Transport(_) | Error::BackendTimeout(_) => {
            Error::BackendUnavailable(format!("{backend}: could not start: {error}"))
        }
        other => other,
    }
}

mod entry_start;
