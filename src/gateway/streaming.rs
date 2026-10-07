// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Streaming and Notification Multiplexer for MCP Gateway
//!
//! Implements MCP Streamable HTTP spec (2025-03-26):
//! - GET /mcp → SSE stream for server→client notifications
//! - POST /mcp → JSON-RPC requests (may upgrade to SSE for streaming responses)
//! - Session management via Mcp-Session-Id header
//! - Notification multiplexing from multiple backends

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::broadcast;
use tracing::{debug, info, trace, warn};
use uuid::Uuid;

use crate::Result;
use crate::backend::BackendRegistry;
use crate::config::StreamingConfig;
use crate::gateway::auth::AuthState;
use crate::gateway::auth::live::{Audience, Delivery, HeldCredential, delivery};
use crate::gateway::session_id::{SessionId, SessionOwner, session_fp};
use crate::gateway::session_lifecycle::{SessionLifecycle, now_unix};

/// A tagged notification event from a backend
#[derive(Debug, Clone, Serialize)]
pub struct TaggedNotification {
    /// Source backend name
    pub source: String,
    /// Event type (e.g., "notification", "result", "error")
    pub event_type: String,
    /// The notification data (JSON-RPC notification or result)
    pub data: Value,
    /// Optional event ID for resumability
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
}

/// One session's copy of a [`TaggedNotification`] on its stream, with the
/// cross-tenant read judgement made for that session's caller when it was
/// queued (MIK-7116.MIN.2, H7). The stream commits it when it writes it; a
/// copy dropped unwritten (a lagging subscriber) commits nothing.
#[derive(Debug, Clone)]
pub struct SessionFrame {
    note: TaggedNotification,
    /// Boxed: every session's ring buffer holds `buffer_size` of these up
    /// front, so the verdict-off default pays one pointer per slot, not a
    /// whole judged frame.
    mark: Option<Box<crate::gateway::outbound::StreamMark>>,
    /// Set on a server-to-client request: how its copies fared on the streams.
    watch: Option<Arc<DeliveryWatch>>,
}

/// How a server-to-client request's queued copies fared on their streams
/// (MIK-7975 WAIT.1). A copy written anywhere delivers it; when every copy the
/// send reached was withheld at write, its waiter can stop at once instead of
/// at its timeout. A copy a lagging stream skips never reports, so that
/// request keeps its timeout.
#[derive(Debug, Default)]
pub(crate) struct DeliveryWatch {
    /// Copies sent minus copies reported. The sender adds after its send and
    /// each stream subtracts, in either order, so only the step that brings
    /// it to exactly zero has seen every copy.
    outstanding: std::sync::atomic::AtomicIsize,
    written: std::sync::atomic::AtomicBool,
    failed: tokio::sync::Notify,
    /// A bridged prompt's relay receipt (MIK-7939): committed by the first
    /// copy written, never for a copy withheld, skipped or dropped.
    commit: parking_lot::Mutex<Option<crate::gateway::input_bridge::DeliveryCommit>>,
}

impl DeliveryWatch {
    fn sent(&self, copies: usize) {
        use std::sync::atomic::Ordering::AcqRel;
        let copies = isize::try_from(copies).unwrap_or(isize::MAX);
        self.settle(
            self.outstanding
                .fetch_add(copies, AcqRel)
                .saturating_add(copies),
        );
    }

    /// A stream wrote its copy (`true`) or withheld it (`false`).
    pub(crate) fn report(&self, written: bool) {
        use std::sync::atomic::Ordering::{AcqRel, Release};
        if written {
            self.written.store(true, Release);
            // Held while the work runs: another copy's stream waits here and
            // cannot write the prompt before its receipt is recorded. The
            // work is an in-memory record that never touches this watch.
            let mut slot = self.commit.lock();
            if let Some(commit) = slot.take() {
                commit.commit();
            }
        }
        self.settle(self.outstanding.fetch_sub(1, AcqRel).saturating_sub(1));
    }

    fn settle(&self, outstanding: isize) {
        if outstanding == 0 && !self.written.load(std::sync::atomic::Ordering::Acquire) {
            // A stored permit: a waiter that starts waiting later still sees it.
            self.failed.notify_one();
        }
    }

    /// Resolves once every copy the send reached was withheld.
    pub(crate) async fn failed(&self) {
        self.failed.notified().await;
    }
}

impl std::ops::Deref for SessionFrame {
    type Target = TaggedNotification;

    fn deref(&self) -> &TaggedNotification {
        &self.note
    }
}

impl SessionFrame {
    /// The notification, without its judgement.
    #[must_use]
    pub fn into_inner(self) -> TaggedNotification {
        self.note
    }

    /// Report this copy written, as the SSE stream does past its gates.
    #[cfg(test)]
    pub(crate) fn written(&self) {
        if let Some(watch) = &self.watch {
            watch.report(true);
        }
    }
}

/// Client session state
#[derive(Debug)]
struct ClientSession {
    /// Session ID; prints as its fingerprint.
    id: SessionId,
    /// Notification sender, opened by the first subscribe and by nothing else:
    /// a send, fan-out included, to an unopened sender is refused as a send
    /// with no receiver is. A POST-only session therefore never allocates the
    /// channel or its buffer (NFR.WORKLOAD.1). The session is in the store
    /// before this is set; every reader treats an unset sender as one with
    /// no receiver, and `OnceLock` gives concurrent subscribers one channel
    /// (MIK-7853.RACE.1).
    tx: OnceLock<broadcast::Sender<SessionFrame>>,
    /// Capacity the sender opens with.
    capacity: usize,
    /// The `caller_key` this session's stream writes to, bound when the
    /// stream opens (MIK-7116.MIN.2); every queued copy is judged for it.
    read_key: RwLock<Option<String>>,
    /// Last event ID received (for resumability)
    last_event_id: RwLock<Option<String>>,
    /// Subscribed backends
    subscribed_backends: RwLock<Vec<String>>,
    /// Timestamp of session creation (for TTL-based reaping)
    /// Last time a request resumed this session. The reaper goes by this, not
    /// by creation: a session that only POSTs holds no stream, so age alone
    /// would reap it mid-use and the next request would start a fresh one.
    last_active: RwLock<Instant>,
    /// The identity that created this session.
    ///
    /// A session id arrives in a header the caller controls, so without this a
    /// per-session check compares one caller-supplied value against another. A
    /// caller presenting an id it does not own gets a session of its own rather
    /// than the owner's, which keeps resumption working for the owner and
    /// leaks nothing to anyone else.
    owner: SessionOwner,
    /// The credential the session was opened with, re-validated at every
    /// scoped delivery. Never a resolved client: a snapshot would outlive a
    /// revoked or expired token.
    // ci-allow-secret-debug: HeldCredential's own Debug prints only <redacted>
    credential: RwLock<Option<HeldCredential>>,
}

impl ClientSession {
    /// The sender, opened now if nothing has needed it yet.
    fn sender(&self) -> &broadcast::Sender<SessionFrame> {
        self.tx.get_or_init(|| broadcast::channel(self.capacity).0)
    }

    fn subscribe(&self) -> broadcast::Receiver<SessionFrame> {
        self.sender().subscribe()
    }

    fn receiver_count(&self) -> usize {
        self.tx.get().map_or(0, broadcast::Sender::receiver_count)
    }

    /// Send as `broadcast::Sender::send` does; an unopened sender has no
    /// receiver, so it refuses exactly as an open one with none would.
    fn send(
        &self,
        notification: SessionFrame,
    ) -> std::result::Result<usize, broadcast::error::SendError<SessionFrame>> {
        match self.tx.get() {
            Some(tx) => tx.send(notification),
            None => Err(broadcast::error::SendError(notification)),
        }
    }
}

/// Notification Multiplexer
///
/// Routes notifications from multiple streaming backends to connected clients.
/// Implements the server-side of MCP Streamable HTTP.
///
/// There is no "first session" accessor: any session is not the caller's
/// session (F9). This compiles:
///
/// ```
/// # use std::sync::Arc;
/// # use mcp_gateway::{backend::BackendRegistry, config::StreamingConfig};
/// # use mcp_gateway::gateway::streaming::NotificationMultiplexer;
/// let x = NotificationMultiplexer::new(Arc::new(BackendRegistry::new()), StreamingConfig::default());
/// assert_eq!(x.session_count(), 0);
/// ```
///
/// and this does not:
///
/// ```compile_fail
/// # use std::sync::Arc;
/// # use mcp_gateway::{backend::BackendRegistry, config::StreamingConfig};
/// # use mcp_gateway::gateway::streaming::NotificationMultiplexer;
/// let x = NotificationMultiplexer::new(Arc::new(BackendRegistry::new()), StreamingConfig::default());
/// let _ = x.first_session_id();
/// ```
pub struct NotificationMultiplexer {
    /// Client sessions by session ID
    sessions: RwLock<HashMap<SessionId, Arc<ClientSession>>>,
    /// Backend registry for subscriptions
    backends: Arc<BackendRegistry>,
    /// Configuration
    config: StreamingConfig,
    /// Event ID counter (global, for uniqueness)
    event_counter: std::sync::atomic::AtomicU64,
    /// The live authorizer scoped delivery asks; unset means no delivery.
    authorizer: RwLock<Option<AuthState>>,
    /// The cross-tenant read judge of every session stream (MIK-7116.MIN.2);
    /// unset when the verdict is off, which is the plain fast path.
    reads: std::sync::OnceLock<crate::gateway::outbound::SessionJudge>,
}

impl NotificationMultiplexer {
    /// Create a new notification multiplexer.
    ///
    /// Spawns a background session-reaper task that periodically removes
    /// sessions idle for `config.session_ttl` that have no active receivers,
    /// preventing FD exhaustion from dropped SSE connections.
    #[must_use]
    pub fn new(backends: Arc<BackendRegistry>, config: StreamingConfig) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            backends,
            config,
            event_counter: std::sync::atomic::AtomicU64::new(1),
            authorizer: RwLock::new(None),
            reads: std::sync::OnceLock::new(),
        }
    }

    /// Install the cross-tenant read judge (once; the router does it).
    pub(crate) fn set_read_judge(&self, judge: crate::gateway::outbound::SessionJudge) {
        let _ = self.reads.set(judge);
    }

    /// Whether session streams are judged at all.
    pub(crate) fn judges_reads(&self) -> bool {
        self.reads.get().is_some()
    }

    /// Bind the caller session `session_id`'s stream writes to.
    pub(crate) fn bind_session_reader(&self, session_id: &str, key: String) {
        if let Some(session) = self.sessions.read().get(session_id) {
            *session.read_key.write() = Some(key);
        }
    }

    /// Queue one copy of `notification` on `session`'s stream, judged for
    /// the session's caller. `false` when it is withheld or nobody is
    /// listening; a session with no open stream is not judged at all.
    fn enqueue(
        &self,
        session: &ClientSession,
        notification: TaggedNotification,
        hidden: Option<&crate::security::tenant_reads::ReadAttribution>,
        watch: Option<Arc<DeliveryWatch>>,
    ) -> std::result::Result<usize, broadcast::error::SendError<SessionFrame>> {
        // No open stream: nothing to deliver, so nothing to judge, and nothing
        // is sent either, so a stream that subscribes meanwhile cannot get an
        // unjudged copy (a send with no receiver delivers nothing anyway).
        if session.tx.get().is_none_or(|tx| tx.receiver_count() == 0) {
            return Err(broadcast::error::SendError(SessionFrame {
                note: notification,
                mark: None,
                watch: None,
            }));
        }
        let key = session.read_key.read().clone();
        let key = key.as_deref();
        let mark = match self.reads.get() {
            None => None,
            Some(judge) => match judge.judge(key, &notification, hidden) {
                Ok(mark) => mark.map(Box::new),
                Err(()) => {
                    return Err(broadcast::error::SendError(SessionFrame {
                        note: notification,
                        mark: None,
                        watch: None,
                    }));
                }
            },
        };
        let copies = session.send(SessionFrame {
            note: notification,
            mark,
            watch: watch.clone(),
        })?;
        if let Some(watch) = watch {
            watch.sent(copies);
        }
        Ok(copies)
    }

    /// Install the authorizer that scoped delivery re-validates sessions against.
    pub(crate) fn set_authorizer(&self, authorizer: AuthState) {
        *self.authorizer.write() = Some(authorizer);
    }

    /// Start the background session-reaper task.
    ///
    /// Must be called once after the multiplexer has been placed in an `Arc`.
    /// The single call site is `server::build_app`, which does this
    /// immediately, so the reaper always runs in production.
    ///
    /// The same tick drives two reclaims that must not diverge: the stream
    /// sessions owned by this multiplexer, and the lifecycle deadlines that
    /// fire registered cleanup callbacks. A second timer would let one sweep
    /// run while the other is wedged, and the divergence is invisible —
    /// nothing errors when a callback is simply never called.
    pub fn spawn_reaper_on(self: &Arc<Self>, lifecycle: Arc<SessionLifecycle>) {
        let weak = Arc::downgrade(self);
        let ttl = self.config.session_ttl;
        let interval = self.config.session_reaper_interval;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                ticker.tick().await;

                let Some(mux) = weak.upgrade() else {
                    // Multiplexer has been dropped — stop the reaper.
                    break;
                };

                for id in mux.reap_expired_sessions(ttl) {
                    // A reaped id is dead; state keyed by it goes with it.
                    lifecycle.on_disconnect(&id);
                }

                let reclaimed = lifecycle.reap(now_unix());
                if reclaimed > 0 {
                    info!(reclaimed, "Session lifecycle reaper completed");
                }
                // Emitted LAST, so every line a sweep produces falls before its
                // own marker and the markers partition the log into sweeps. An
                // empty sweep is otherwise indistinguishable from a sweep that
                // never ran, which leaves "no reclaim line was logged" unable
                // to fail. Not compiled out under test: a log line that exists
                // only in one build is a different program.
                trace!("Session lifecycle sweep complete");
            }
        });
    }

    /// Remove all sessions that are both expired and have no active receivers.
    ///
    /// Returns the ids it removed, so the caller can announce their end.
    fn reap_expired_sessions(&self, ttl: Duration) -> Vec<String> {
        let now = Instant::now();
        let mut sessions = self.sessions.write();

        let mut reaped_ids = Vec::new();
        sessions.retain(|id, session| {
            let expired = now.duration_since(*session.last_active.read()) >= ttl;
            let abandoned = session.receiver_count() == 0;

            if expired && abandoned {
                info!(session_id = %id, "Reaping expired streaming session (no active receivers)");
                reaped_ids.push(id.expose_secret().to_string());
                false
            } else {
                true
            }
        });

        let reaped = reaped_ids.len();
        if reaped > 0 {
            info!(
                reaped,
                remaining = sessions.len(),
                "Session reaper completed"
            );
        }
        reaped_ids
    }

    /// Create or get a session
    pub fn get_or_create_session(
        &self,
        session_id: Option<&str>,
    ) -> (String, broadcast::Receiver<SessionFrame>) {
        self.get_or_create_session_for(session_id, &SessionOwner::Anonymous)
    }

    /// Resume `owner`'s live session named `session_id`, or open a new one
    /// under a freshly minted id.
    ///
    /// A presented id is never adopted. Adoption let a caller pick an id
    /// before its victim did and then share the victim's stream, because every
    /// anonymous caller has the same owner (F9). An id that names someone
    /// else's session gets a fresh one too: joining it would hand over their
    /// stream, and refusing would break a client that legitimately collides.
    pub(crate) fn get_or_create_session_for(
        &self,
        session_id: Option<&str>,
        owner: &SessionOwner,
    ) -> (String, broadcast::Receiver<SessionFrame>) {
        let session = self.open_session_for(session_id, owner);
        (session.id.expose_secret().to_string(), session.subscribe())
    }

    /// Resume or open as [`Self::get_or_create_session_for`] does, without
    /// subscribing.
    fn open_session_for(
        &self,
        session_id: Option<&str>,
        owner: &SessionOwner,
    ) -> Arc<ClientSession> {
        let mut sessions = self.sessions.write();
        if let Some(session) = session_id.and_then(|id| sessions.get(id))
            && session.owner == *owner
        {
            *session.last_active.write() = Instant::now();
            return Arc::clone(session);
        }
        let id = format!("gw-{}", Uuid::new_v4());
        let session = self.insert_session(&mut sessions, &id, owner.clone());
        info!(session_id = %session_fp(&id), "Created new streaming session");
        session
    }

    /// The one place a session enters the store.
    fn insert_session(
        &self,
        sessions: &mut HashMap<SessionId, Arc<ClientSession>>,
        id: &str,
        owner: SessionOwner,
    ) -> Arc<ClientSession> {
        let id = SessionId::new(id);
        let session = Arc::new(ClientSession {
            id: id.clone(),
            tx: OnceLock::new(),
            capacity: self.config.buffer_size,
            read_key: RwLock::new(None),
            last_event_id: RwLock::new(None),
            subscribed_backends: RwLock::new(Vec::new()),
            last_active: RwLock::new(Instant::now()),
            owner,
            credential: RwLock::new(None),
        });
        sessions.insert(id, Arc::clone(&session));
        session
    }

    /// Create or resume a session for `owner`, holding the credential it
    /// presented, and subscribe to it (tests; the GET handler binds the
    /// stream's caller before it subscribes).
    #[cfg(test)]
    pub(crate) fn get_or_create_session_scoped(
        &self,
        session_id: Option<&str>,
        owner: &SessionOwner,
        credential: Option<HeldCredential>,
    ) -> (String, broadcast::Receiver<SessionFrame>) {
        let session = self.open_session_scoped(session_id, owner, credential);
        (session.id.expose_secret().to_string(), session.subscribe())
    }

    /// As [`Self::get_or_create_session_scoped`], for a caller that only needs
    /// the id: it opens no notification channel (NFR.WORKLOAD.1).
    pub(crate) fn get_or_create_session_id_scoped(
        &self,
        session_id: Option<&str>,
        owner: &SessionOwner,
        credential: Option<HeldCredential>,
    ) -> String {
        let session = self.open_session_scoped(session_id, owner, credential);
        session.id.expose_secret().to_string()
    }

    fn open_session_scoped(
        &self,
        session_id: Option<&str>,
        owner: &SessionOwner,
        credential: Option<HeldCredential>,
    ) -> Arc<ClientSession> {
        let session = self.open_session_for(session_id, owner);
        *session.credential.write() = credential;
        session
    }

    /// Test seam: an anonymous session under a chosen id, which production
    /// never creates (every production id is minted, F9).
    #[cfg(test)]
    pub(crate) fn seed_session(&self, id: &str) -> broadcast::Receiver<SessionFrame> {
        self.insert_session(&mut self.sessions.write(), id, SessionOwner::Anonymous)
            .subscribe()
    }

    /// Deliver to every session whose caller may access `backend` now; returns the count.
    ///
    /// Each session's credential is re-validated at delivery, so a revoked or
    /// expired token receives nothing even on a stream opened while it was valid.
    pub(crate) async fn broadcast_to_backend(
        &self,
        notification: &TaggedNotification,
        backend: &str,
    ) -> usize {
        self.broadcast_to_backend_raw(notification, backend, None)
            .await
    }

    /// [`Self::broadcast_to_backend`] for an item transformed from a raw
    /// inbound value (a webhook body): each copy is also judged on what
    /// `raw` named before the transform dropped it (MIK-7116.MIN.2, §4.4).
    pub(crate) async fn broadcast_to_backend_raw(
        &self,
        notification: &TaggedNotification,
        backend: &str,
        raw: Option<&Value>,
    ) -> usize {
        let hidden = raw.and_then(|raw| self.reads.get().and_then(|judge| judge.raw(raw)));
        let Some(authorizer) = self.authorizer.read().clone() else {
            return 0;
        };
        // Copied out so no lock is held across the re-validation awaits. The
        // session itself is held, not its sender, so an unopened one stays
        // unopened and a stream that subscribes meanwhile is still reached.
        let targets: Vec<_> = self
            .sessions
            .read()
            .values()
            .map(|s| (Arc::clone(s), s.credential.read().clone()))
            .collect();
        let mut reached = 0;
        for (session, credential) in targets {
            let verdict =
                delivery(&authorizer, credential.as_ref(), Audience::Backend(backend)).await;
            if verdict == Delivery::Deliver
                && self
                    .enqueue(&session, notification.clone(), hidden.as_ref(), None)
                    .is_ok()
            {
                reached += 1;
            }
        }
        reached
    }

    /// Remove a session
    pub fn remove_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write();
        if sessions.remove(session_id).is_some() {
            info!(session_id = %session_fp(session_id), "Removed streaming session");
        }
    }

    /// Remove only a matching owner, with lookup and removal under one write lock.
    pub(crate) fn remove_session_for(&self, session_id: &str, owner: &SessionOwner) -> bool {
        let mut sessions = self.sessions.write();
        match sessions.entry(SessionId::new(session_id)) {
            std::collections::hash_map::Entry::Occupied(entry) if entry.get().owner == *owner => {
                entry.remove();
                true
            }
            _ => false,
        }
    }

    /// Check if a session exists
    pub fn has_session(&self, session_id: &str) -> bool {
        self.sessions.read().contains_key(session_id)
    }

    /// The event id stored for `session_id`, if that session exists.
    ///
    /// Read-only, and it exists because the absence of a write is what MIK-7272
    /// SUB.3 asserts: a refused modern GET must leave resumption state alone.
    /// Inferring that from "no session was created" tests a weaker claim.
    ///
    /// Supported public API, alongside `session_count`: both report multiplexer
    /// state without changing it. Named as an addition rather than hidden --
    /// `#[doc(hidden)]` withholds the documentation, never the symbol, and an
    /// accessor a consumer can call is API whatever its doc attribute says.
    #[must_use]
    pub fn last_event_id(&self, session_id: &str) -> Option<String> {
        self.sessions
            .read()
            .get(session_id)
            .and_then(|session| session.last_event_id.read().clone())
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    /// Send a notification to a specific session
    ///
    /// The empty id is the router's "no session" and is never delivered to (F9).
    pub fn send_to_session(&self, session_id: &str, notification: TaggedNotification) -> bool {
        if session_id.is_empty() {
            return false;
        }
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(session_id) {
            match self.enqueue(session, notification, None, None) {
                Ok(_) => true,
                Err(e) => {
                    debug!(session_id = %session_fp(session_id), error = %e, "Failed to send notification");
                    false
                }
            }
        } else {
            false
        }
    }

    /// [`Self::send_to_session`] for a server-to-client request: the watch
    /// reports whether any queued copy is written (MIK-7975 WAIT.1), and runs
    /// `commit` when one is (MIK-7939). `None` when nothing was queued.
    pub(crate) fn send_request_to_session(
        &self,
        session_id: &str,
        notification: TaggedNotification,
        commit: Option<crate::gateway::input_bridge::DeliveryCommit>,
    ) -> Option<Arc<DeliveryWatch>> {
        if session_id.is_empty() {
            return None;
        }
        let sessions = self.sessions.read();
        let session = sessions.get(session_id)?;
        let watch = Arc::new(DeliveryWatch {
            commit: parking_lot::Mutex::new(commit),
            ..DeliveryWatch::default()
        });
        self.enqueue(session, notification, None, Some(Arc::clone(&watch)))
            .ok()
            .map(|_| watch)
    }

    /// Broadcast a notification to all sessions
    #[allow(clippy::needless_pass_by_value)] // public API: caller may have owned value
    pub fn broadcast(&self, notification: TaggedNotification) {
        let sessions = self.sessions.read();
        for session in sessions.values() {
            let _ = self.enqueue(session, notification.clone(), None, None);
        }
    }

    /// Generate a unique event ID
    pub fn next_event_id(&self) -> String {
        let id = self
            .event_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("evt-{id}")
    }

    /// Subscribe a session to a backend's notifications
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is not found in the registry.
    #[allow(unknown_lints, clippy::unused_async, clippy::unused_async_trait_impl)] // async for future streaming implementation
    pub async fn subscribe_backend(&self, session_id: &str, backend_name: &str) -> Result<()> {
        // Verify backend exists
        let _backend = self
            .backends
            .get(backend_name)
            .ok_or_else(|| crate::Error::BackendNotFound(backend_name.to_string()))?;

        // Record subscription
        {
            let sessions = self.sessions.read();
            if let Some(session) = sessions.get(session_id) {
                let mut subs = session.subscribed_backends.write();
                if !subs.contains(&backend_name.to_string()) {
                    subs.push(backend_name.to_string());
                }
            }
        }

        // If backend supports streaming, start forwarding notifications
        // For now, we'll handle this via the invoke path
        debug!(session_id = %session_fp(session_id), backend = %backend_name, "Subscribed to backend notifications");

        Ok(())
    }

    /// Auto-subscribe a session to configured backends
    pub async fn auto_subscribe(&self, session_id: &str) {
        for backend_name in &self.config.auto_subscribe {
            if let Err(e) = self.subscribe_backend(session_id, backend_name).await {
                warn!(
                    session_id = %session_fp(session_id),
                    backend = %backend_name,
                    error = %e,
                    "Failed to auto-subscribe to backend"
                );
            }
        }
    }
}
/// The `tracing` target of the events this module raises, its `sse` child
/// included: code moved into a child module keeps the target a log filter
/// already names.
const STREAMING_TARGET: &str = module_path!();

#[path = "streaming_sse.rs"]
mod sse;
pub use sse::{TaskFrame, TaskFrameDelivery, TaskFrames, create_sse_response};
pub(crate) use sse::{first_event_wins_stream, subscription_stream};
// Kept at the crate-visible path it had before the move; only the tests
// and the `sse` module call it today.
#[allow(unused_imports)]
pub(crate) use sse::request_scoped_event_stream;
// Names the test modules reach through `use super::*`, which the code moved
// into `sse` no longer needs here.
#[cfg(test)]
use crate::gateway::outbound::{OutboundFrame, StreamJudge};
#[cfg(test)]
use axum::response::IntoResponse;
#[cfg(test)]
use serde_json::json;

#[cfg(test)]
#[path = "streaming_session_ownership_tests.rs"]
mod session_ownership_tests;

#[cfg(test)]
#[path = "streaming_tests.rs"]
mod tests;

#[path = "streaming_ownership.rs"]
mod ownership;
#[cfg(test)]
#[path = "streaming_request_scoped_tests.rs"]
mod request_scoped_stream_tests;
