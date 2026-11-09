// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Starting one pool entry, from the build through the publish: the one path
//! every start runs through (lazy, `start()`, restart and revive, warm start),
//! and the publish where shutdown and a moved destination policy are enforced.
//! Moved from `lifecycle.rs`; the code is unchanged, and the comments state
//! their rules without ticket references.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tracing::{debug, info, warn};

use super::super::Backend;
use super::super::era::EraResolution;
use super::super::pool::{PoolKey, PooledEntry};
#[cfg(test)]
use super::hold_at;
use super::http_target;
use crate::config::TransportConfig;
use crate::transport::{HttpTransport, Transport};
use crate::{Error, Result};

impl Backend {
    /// Build a fresh transport for the pooled `entry`, store it, and return a
    /// clone. Per-user slots build the same transport shape as the shared slot;
    /// end-user identity is carried per-request via headers, not baked into the
    /// connection, so each user simply gets an independent session lifecycle.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails to connect or initialize.
    pub(in crate::backend) async fn start_entry(
        &self,
        key: &PoolKey,
        entry: &PooledEntry,
    ) -> Result<Arc<dyn Transport>> {
        self.start_entry_as(key, entry, EraResolution::Shared).await
    }

    /// [`Self::start_entry`], resolving the slot's era as `era` says.
    ///
    /// Every start runs through here (lazy, `start()`, restart and revive,
    /// warm start), so this is where the slot's start outcome is recorded for
    /// the operator's state view (`server_state`).
    pub(in crate::backend) async fn start_entry_as(
        &self,
        key: &PoolKey,
        entry: &PooledEntry,
        era: EraResolution,
    ) -> Result<Arc<dyn Transport>> {
        self.refuse_shared_start(key)?;
        let started = self.start_entry_inner(key, entry, era).await;
        match &started {
            Ok(_) => {
                entry.ever_started.store(true, Ordering::Relaxed);
                entry.start_failed.store(false, Ordering::Relaxed);
                entry.auth_wait.clear();
            }
            Err(e) if e.is_authorization_wait() => entry.set_auth_wait(),
            Err(_) => entry.start_failed.store(true, Ordering::Relaxed),
        }
        started
    }

    async fn start_entry_inner(
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
        let _in_flight = super::super::StartGuard::new(&self.starts_in_flight);

        // Cheap early-out. The publish below is the authoritative check - it is
        // ordered against shutdown's pool traversal, and this one is not - but
        // spawning a process only to close it moments later is pure waste, and
        // a caller that starts a backend after `stop()` has already returned
        // would otherwise leave a child running for the length of a handshake.
        if self.replaced_transport_cleanups.lock().stopping {
            debug!(backend = %self.name, "Not starting: backend is stopped");
            // NotFound, not Unavailable: the stopped instance is retired and a
            // retry re-resolves through the registry, so nothing was sent and
            // the refusal is pre-dispatch (it frees an idempotency key).
            return Err(Error::BackendNotFound(self.name.clone()));
        }

        info!(backend = %self.name, "Starting backend transport");
        // The policy this start builds under. The backend is marked for a
        // pairing to refuse only once the start can connect (`mark_connecting`,
        // `begin_connecting`): a start refused before that built nothing that
        // could be unpinned, so it must not block a later hardened pairing.
        let built_under: crate::security::ssrf::DestinationPolicy;

        // Whatever the reason for starting - a client request, a health-driven
        // force_restart, warm start - this slot is no longer stopped-for-idleness.
        // Clearing here rather than in `ensure_entry_started` is deliberate:
        // `force_restart` calls this directly, and clearing only in the former
        // left a restarted backend flagged dormant while actually running.
        entry.stopped_when_idle.store(false, Ordering::SeqCst);

        let listen: Option<super::super::listen::ListenHandle>;
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
                listen = Some(super::super::listen::handle_of(&transport));
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
                let (slot, statics, oauth_client) =
                    self.slot_gateway_credentials(key, http_url, built_under)?;
                let transport = HttpTransport::with_destination(
                    http_url,
                    statics,
                    self.config.timeout,
                    *streamable_http,
                    oauth_client,
                    protocol_version.clone(),
                    built_under,
                )?;
                // A per-user pool slot's transport serves one caller identity
                // for life: tell it so, with the slot's
                // lender its dispatches lend through. It marks itself single
                // tenant only when lent-only, the one kind holding a single
                // session.
                if let Some(slot) = slot {
                    transport.mark_per_user_slot(slot, Arc::clone(&entry.lender));
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
                self.attach_needles_to(&transport);
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
                        let probe = self.probe_candidate_era(&peer, entry).await;
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
                // its verdict is about a different peer.
                transport.finish_startup(era).await?;
                warn_if_configured_transport_refused(&self.name, *streamable_http, &transport);
                listen = Some(super::super::listen::handle_of(&transport));
                transport
            }
            TransportConfig::WebSocket {
                ws_url,
                protocol_version,
            } => {
                // A target the upgrade request cannot be built for is refused
                // before the mark: such a start never connects.
                crate::transport::websocket::WebSocketTransport::upgrade_request(
                    ws_url,
                    &self.config.headers,
                )?;
                built_under = self.mark_connecting();
                let transport = self
                    .start_websocket(ws_url, protocol_version.clone(), built_under)
                    .await?;
                listen = Some(super::super::listen::handle_of(&transport));
                transport
            }
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { .. } => {
                built_under = self.mark_connecting();
                self.begin_connecting(built_under)?;
                listen = None;
                self.start_a2a(key, entry, built_under).await?
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
    /// `deferred` era probe is installed with the publish.
    async fn publish_started(
        &self,
        entry: &PooledEntry,
        transport: &Arc<dyn Transport>,
        listen: Option<super::super::listen::ListenHandle>,
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
