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

use tracing::{debug, info, warn};

use super::pool::{PoolKey, PooledEntry};

use super::Backend;
use crate::config::{BackendConfig, TransportConfig};
use crate::runtime::RuntimePlan;
use crate::transport::{HttpTransport, Transport};

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
        Self {
            name: name.to_string(),
            metric_label: Arc::<str>::from(name).into(),
            config,
            runtime_plan,
            pool: {
                let pool = DashMap::new();
                pool.insert(
                    PoolKey::Shared,
                    Arc::new(PooledEntry::new(name, failsafe_config)),
                );
                pool
            },
            failsafe_config: failsafe_config.clone(),
            #[cfg(test)]
            after_reprobe_lookup: crate::test_pause::Slot::default(),
            unserved_consecutive: AtomicU64::new(0),
            unserved_total: AtomicU64::new(0),
            probe_in_flight: std::sync::atomic::AtomicBool::new(false),
            cache_ttl,
            last_used: std::sync::atomic::AtomicU64::new(0),
            semaphore: Semaphore::new(100),
            request_count: std::sync::atomic::AtomicU64::new(0),
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
            destination: std::sync::OnceLock::new(),
            #[cfg(test)]
            mark_window_gate: parking_lot::Mutex::new(None),
            #[cfg(test)]
            era_decision_gate: parking_lot::Mutex::new(None),
            #[cfg(test)]
            publish_gate: parking_lot::Mutex::new(None),
            #[cfg(test)]
            rebuilds_attempted: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            last_oauth_client: parking_lot::Mutex::new(None),
            #[cfg(test)]
            between_install_and_write: parking_lot::Mutex::new(None),
            #[cfg(test)]
            era_at_publish: parking_lot::Mutex::new(Vec::new()),
            #[cfg(test)]
            oauth_test_seam: parking_lot::Mutex::new(None),
            instance: super::tools_nudge::next_instance(),
            nudge_feed: std::sync::OnceLock::new(),
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
            let _start_guard = if crate::oauth::login_gate::interactive() {
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
            let transport = crate::oauth::login_gate::set_out(set_out, start).await?;

            // Reconcile: did the evictor remove this exact entry while we
            // were building its transport?
            if let Some(transport) = self.reconcile_after_start(key, &entry, transport).await {
                // Resolve the peer's protocol era on the start path, so the
                // first request already knows which dialect to speak. Runs
                // under this slot's `start_lock`; see `Backend::resolve_era`
                // for the lock order that imposes.
                self.resolve_era_after_start(&transport, &entry).await;
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
            ?key,
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
        let _pairing = self.replaced_transport_cleanups.lock();
        if self.destination.get().is_none() {
            self.connected_unpinned
                .store(true, std::sync::atomic::Ordering::SeqCst);
            return Ok(());
        }
        if self.destination() == built_under {
            return Ok(());
        }
        debug!(backend = %self.name, "Not connecting: the destination policy changed while it was starting");
        Err(Error::BackendUnavailable(self.name.clone()))
    }

    /// Build a fresh transport for the pooled `entry`, store it, and return a
    /// clone. Per-user slots build the same transport shape as the shared slot;
    /// end-user identity is carried per-request via headers, not baked into the
    /// connection, so each user simply gets an independent session lifecycle.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails to connect or initialize.
    pub(super) async fn start_entry(
        &self,
        key: &PoolKey,
        entry: &PooledEntry,
    ) -> Result<Arc<dyn Transport>> {
        self.start_entry_as(key, entry, EraResolution::Shared).await
    }

    /// [`Self::start_entry`], resolving the slot's era as `era` says.
    pub(super) async fn start_entry_as(
        &self,
        key: &PoolKey,
        entry: &PooledEntry,
        era: EraResolution,
    ) -> Result<Arc<dyn Transport>> {
        let era_mode = era;
        let mut deferred = None;
        // Held for the whole start. From the moment a process is spawned until
        // it is either published or closed, shutdown must not consider itself
        // finished - the process is alive either way.
        let _in_flight = super::StartGuard::new(&self.starts_in_flight);

        // Cheap early-out. The publish below is the authoritative check - it is
        // ordered against shutdown's pool traversal, and this one is not - but
        // spawning a process only to close it moments later is pure waste, and
        // a caller that starts a backend after `stop()` has already returned
        // would otherwise leave a child running for the length of a handshake.
        if self.replaced_transport_cleanups.lock().stopping {
            debug!(backend = %self.name, ?key, "Not starting: backend is stopped");
            // NotFound, not Unavailable: the stopped instance is retired and a
            // retry re-resolves through the registry, so nothing was sent and
            // the refusal is pre-dispatch (it frees an idempotency key).
            return Err(Error::BackendNotFound(self.name.clone()));
        }

        info!(backend = %self.name, ?key, "Starting backend transport");
        // The policy this start builds under. The backend is marked for a
        // pairing to refuse only once the start can connect (`mark_connecting`,
        // `begin_connecting`): a start refused before that built nothing that
        // could be unpinned, so it must not block a later hardened pairing
        // (MIK-7855).
        let built_under: crate::security::ssrf::DestinationPolicy;

        // Whatever the reason for starting - a client request, a health-driven
        // force_restart, warm start - this slot is no longer stopped-for-idleness.
        // Clearing here rather than in `ensure_entry_started` is deliberate:
        // `force_restart` calls this directly, and clearing only in the former
        // left a restarted backend flagged dormant while actually running.
        entry.stopped_when_idle.store(false, Ordering::SeqCst);

        let listen: Option<super::listen::ListenHandle>;
        let transport: Arc<dyn Transport> = match &self.config.transport {
            TransportConfig::Stdio {
                command,
                cwd,
                protocol_version,
            } => {
                // A stdio child reaches no network destination of its own.
                built_under = self.destination();
                let transport = self
                    .start_stdio_transport(command, cwd.as_ref(), protocol_version.as_ref())
                    .await?;
                listen = Some(super::listen::handle_of(&transport));
                transport
            }
            TransportConfig::Http {
                http_url,
                streamable_http,
                protocol_version,
            } => {
                http_target(http_url)?;
                // One read, before anything is built: the OAuth client and the
                // transport are both built under it, and `begin_connecting`
                // refuses the start if a pairing stamped another policy since.
                built_under = self.destination();
                #[cfg(test)]
                self.hold_in_mark_window().await;
                let oauth_client = self.create_oauth_client(http_url, built_under)?;
                let transport = HttpTransport::with_destination(
                    http_url,
                    self.config.headers.clone(),
                    self.config.timeout,
                    *streamable_http,
                    oauth_client,
                    protocol_version.clone(),
                    built_under,
                )?;
                // MIK-6735 fix 2: a per-user pool slot's transport serves
                // exactly one caller identity for its whole lifetime, which
                // is what makes the transport's internal session-map
                // single-tenant debug_assert provably safe -- tell it so.
                if matches!(key, PoolKey::PerUser { .. }) {
                    transport.mark_single_tenant();
                }
                #[cfg(test)]
                {
                    *self.last_oauth_client.lock() = transport.oauth_client_for_test();
                }
                // RFC-0061 §2.4 startup: ask first, handshake only if the
                // answer is not modern. Attached before anything reaches the
                // wire, deliberately — the probe below is itself a request, and
                // it reads this cache to know it is the one message that may
                // not wait for a verdict.
                transport.attach_era(Arc::clone(&entry.era));
                // Connect without handshaking: the probe needs the credential
                // and the message endpoint, and nothing else.
                self.begin_connecting(built_under)?;
                transport.connect().await?;
                // The probe, its deadline and the meaning of its answer stay in
                // `Backend::resolve_era` and `EraCache`. This path chooses when
                // to ask, never what the answer means.
                let peer: Arc<dyn Transport> = transport.clone();
                let era = match era_mode {
                    EraResolution::Shared => self.resolve_era(&peer, entry).await,
                    EraResolution::Deferred => {
                        let probe = self.probe_candidate_era(&peer).await;
                        let era = probe.era();
                        deferred = Some(probe);
                        era
                    }
                };
                #[cfg(test)]
                self.hold_at_era_decision().await;
                // Only a determined `Modern` skips the handshake. A legacy
                // answer, an unrecognised error and silence all read as
                // `Legacy`, the fallback the RFC requires. The era is this
                // start's own probe result, not the shared cache: another
                // slot's start or re-probe may have written that since, and
                // its verdict is about a different peer (MIK-8056).
                transport.finish_startup(era).await?;
                warn_if_configured_transport_refused(&self.name, *streamable_http, &transport);
                listen = Some(super::listen::handle_of(&transport));
                transport
            }
            TransportConfig::WebSocket {
                ws_url,
                protocol_version,
            } => {
                // A target the upgrade request cannot be built for is refused
                // before the mark: such a start never connects (MIK-7855).
                crate::transport::websocket::WebSocketTransport::upgrade_request(
                    ws_url,
                    &self.config.headers,
                )?;
                built_under = self.mark_connecting();
                let transport = self
                    .start_websocket(ws_url, protocol_version.clone(), built_under)
                    .await?;
                listen = Some(super::listen::handle_of(&transport));
                transport
            }
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { .. } => {
                built_under = self.mark_connecting();
                self.begin_connecting(built_under)?;
                listen = None;
                self.start_a2a(built_under).await?
            }
        };

        self.publish_started(entry, &transport, listen, built_under, deferred)
            .await?;

        // Note: Tools are fetched lazily on first get_tools() call
        // We can't pre-cache here because get_tools() -> ensure_started() -> start()
        // would create infinite async recursion

        Ok(transport)
    }

    /// Publish a started transport over `entry`, or close it when the backend
    /// shut down or its destination policy moved while it started. A
    /// `deferred` era probe is installed with the publish (MIK-8012).
    async fn publish_started(
        &self,
        entry: &PooledEntry,
        transport: &Arc<dyn Transport>,
        listen: Option<super::listen::ListenHandle>,
        built_under: crate::security::ssrf::DestinationPolicy,
        deferred: Option<crate::protocol::era::DetachedProbe>,
    ) -> Result<()> {
        // Publishing is where shutdown has to be enforced, because this is the
        // ONE place a transport becomes reachable - `ensure_entry_started`,
        // warm start and `force_restart` all land here. Checking in the callers
        // instead left the ordinary request path unguarded: a client could
        // start a backend after `stop()` had walked the pool, and nothing would
        // ever close that child.
        //
        // The check and the publish happen under the cleanup lock, which
        // `stop()` also holds while it latches and takes every transport out.
        // So the two are ordered: either this publishes first and shutdown's
        // traversal finds it, or shutdown latches first and this refuses. There
        // is no third case, which is what the previous check-then-publish could
        // not say.
        // A deferred era is installed under the cache's lock taken BEFORE the
        // publish, inside the publish's own step, so no reader sees the new
        // transport with the old verdict.
        let install = match deferred {
            Some(probe) => Some((entry.era.lock_for_install().await, probe)),
            None => None,
        };
        let on_publish = move || {
            install.map(|(mut install, probe)| {
                install.install(probe);
                install
            })
        };
        if let Err(refusal) = self.publish(entry, (transport, listen), built_under, on_publish) {
            warn!(
                backend = %self.name,
                %refusal,
                "Closing a transport instead of publishing it"
            );
            let _ = transport.close().await;
            // A shutdown that won the race retired this instance, as above.
            if self.replaced_transport_cleanups.lock().stopping {
                return Err(Error::BackendNotFound(self.name.clone()));
            }
            return Err(Error::BackendUnavailable(self.name.clone()));
        }
        #[cfg(test)]
        hold_at(&self.publish_gate).await;

        Ok(())
    }
}

/// The configured transport was refused and the other one answered; say which
/// value would skip the refused try.
/// Wait at the test gate held in `slot`, when one is set: signal `reached`,
/// then wait for `release`.
#[cfg(test)]
async fn hold_at(slot: &parking_lot::Mutex<Option<Arc<super::MarkWindowGate>>>) {
    let gate = slot.lock().clone();
    if let Some(gate) = gate {
        gate.reached.notify_one();
        gate.release.notified().await;
    }
}

fn warn_if_configured_transport_refused(
    backend: &str,
    configured: Option<bool>,
    transport: &HttpTransport,
) {
    if let Some(configured) = configured
        && transport.streamable() == Some(!configured)
    {
        warn!(
            backend = %backend,
            "`streamable_http: {configured}` was refused with a 4xx and the other HTTP transport answered; set `streamable_http: {}` for this backend, or remove the key to detect it",
            !configured
        );
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

/// How a start resolves its slot's era (MIK-8012).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EraResolution {
    /// Discard and probe under the slot cache's lock: nothing else serves
    /// from the slot while it starts.
    Shared,
    /// Probe without the lock and install at the publish: the transport being
    /// replaced still serves from the slot (a build-first restart).
    Deferred,
}
