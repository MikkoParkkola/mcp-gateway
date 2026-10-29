// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use tokio::sync::broadcast;
use tokio::time::Instant;
use tracing::{debug, warn};

use super::{
    HeldCredential, Result, SessionFrame, SessionId, SessionOwner, Unsent, session_fp, told,
};

/// Client session state
#[derive(Debug)]
pub(super) struct ClientSession {
    /// Session ID; prints as its fingerprint.
    pub(super) id: SessionId,
    /// Notification sender, opened by the first subscribe and by nothing else:
    /// a send, fan-out included, to an unopened sender is refused as a send
    /// with no receiver is. A POST-only session therefore never allocates the
    /// channel or its buffer (NFR.WORKLOAD.1). The session is in the store
    /// before this is set; every reader treats an unset sender as one with
    /// no receiver, and `OnceLock` gives concurrent subscribers one channel
    /// (MIK-7853.RACE.1).
    pub(super) tx: OnceLock<broadcast::Sender<SessionFrame>>,
    /// Capacity the sender opens with.
    pub(super) capacity: usize,
    /// The `caller_key` this session's stream writes to, bound when the
    /// stream opens (MIK-7116.MIN.2); every queued copy is judged for it.
    pub(super) read_key: RwLock<Option<String>>,
    /// Last event ID received (for resumability)
    pub(super) last_event_id: RwLock<Option<String>>,
    /// Subscribed backends
    pub(super) subscribed_backends: RwLock<Vec<String>>,
    /// Timestamp of session creation (for TTL-based reaping)
    /// Last time a request resumed this session. The reaper goes by this, not
    /// by creation: a session that only POSTs holds no stream, so age alone
    /// would reap it mid-use and the next request would start a fresh one.
    pub(super) last_active: RwLock<Instant>,
    /// The wall-clock time of the same touch as `last_active`, for display:
    /// `last_active` is monotonic and cannot be shown. Set only by
    /// [`ClientSession::touch`], so the two never disagree about which
    /// request was the last. `None` when the clock could not be read.
    pub(super) last_seen: RwLock<Option<DateTime<Utc>>>,
    /// What the peer says it is. Display only; see [`ReportedName`].
    pub(super) reported_name: ReportedName,
    /// The identity that created this session.
    ///
    /// A session id arrives in a header the caller controls, so without this a
    /// per-session check compares one caller-supplied value against another. A
    /// caller presenting an id it does not own gets a session of its own rather
    /// than the owner's, which keeps resumption working for the owner and
    /// leaks nothing to anyone else.
    pub(super) owner: SessionOwner,
    /// The credential the session was opened with, re-validated at every
    /// scoped delivery. Never a resolved client: a snapshot would outlive a
    /// revoked or expired token.
    // ci-allow-secret-debug: HeldCredential's own Debug prints only <redacted>
    pub(super) credential: RwLock<Option<HeldCredential>>,
    /// One record per distinct view held on this session (MIK-8350): what
    /// each was last told, keyed by the subject its stream opened under.
    pub(super) records: RwLock<Vec<told::ViewEntry>>,
    /// Minted by a request that is not `initialize` and not yet presented
    /// again: reaped after the short provisional idle limit, and counted
    /// against the provisional cap until promoted or removed (MIK-8504).
    pub(super) provisional: std::sync::atomic::AtomicBool,
    /// Requests running under this session now. A provisional session with
    /// one in flight is never reaped (MIK-8504).
    pub(super) in_flight: std::sync::atomic::AtomicUsize,
    /// Whether a provisional session was minted by a GET stream, and so
    /// counts against the stream share rather than the POST share
    /// (MIK-8533). Read only while `provisional` is set.
    pub(super) provisional_stream: std::sync::atomic::AtomicBool,
}

/// Characters kept of a client's self-reported name.
const REPORTED_NAME_CAP: usize = 64;

/// The name the client gave in `initialize` (`clientInfo.name`), cleaned.
///
/// Self-asserted and unverified: the peer picks it, so it is display text and
/// never an identity. Nothing that decides access, routing, audit or
/// attribution may read it. The inner value is private to this module and its
/// one getter is called by the listing in `streaming_roster.rs` alone, so a
/// new reader has to come through that door.
#[derive(Debug, Default)]
pub(super) struct ReportedName(RwLock<Option<String>>);

impl ReportedName {
    /// Replace the name with `raw`, cleaned as display text and capped. A
    /// name that cleans to nothing clears it.
    pub(super) fn set(&self, raw: &str) {
        *self.0.write() =
            crate::cli_support::display_text(raw, REPORTED_NAME_CAP).map(|(text, _cut)| text);
    }

    /// The cleaned name, for the listing.
    pub(super) fn get(&self) -> Option<String> {
        self.0.read().clone()
    }
}

impl ClientSession {
    /// A request used this session now: the idle clock restarts and the
    /// wall-clock `last_seen` moves with it, under the one write lock.
    pub(super) fn touch(&self) {
        let mut active = self.last_active.write();
        *active = Instant::now();
        *self.last_seen.write() = crate::clock::utc_now().ok();
    }

    /// Hold `credential`. A different credential is a different caller, so
    /// what the session was last told no longer describes it: every record is
    /// cleared under a new floor and the next attach takes a fresh baseline
    /// (MIK-8350). The same credential keeps its records, so a frame withheld
    /// at write stays owed.
    pub(super) fn replace_credential(&self, credential: Option<HeldCredential>) {
        let mut held = self.credential.write();
        let changed = held.as_ref().map(HeldCredential::digest)
            != credential.as_ref().map(HeldCredential::digest);
        *held = credential;
        drop(held);
        if changed {
            for entry in self.records.read().iter() {
                entry.record.clear();
            }
        }
    }

    /// The sender, opened now if nothing has needed it yet.
    fn sender(&self) -> &broadcast::Sender<SessionFrame> {
        self.tx.get_or_init(|| broadcast::channel(self.capacity).0)
    }

    pub(super) fn subscribe(&self) -> broadcast::Receiver<SessionFrame> {
        self.sender().subscribe()
    }

    pub(super) fn receiver_count(&self) -> usize {
        self.tx.get().map_or(0, broadcast::Sender::receiver_count)
    }

    /// Send as `broadcast::Sender::send` does; an unopened sender has no
    /// receiver, so it refuses exactly as an open one with none would. The
    /// refused frame is dropped, not returned: no caller reads it.
    pub(super) fn send(&self, notification: SessionFrame) -> std::result::Result<usize, Unsent> {
        match self.tx.get() {
            Some(tx) => tx.send(notification).map_err(|_| Unsent),
            None => Err(Unsent),
        }
    }
}

impl super::NotificationMultiplexer {
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
        #[allow(
            clippy::disallowed_methods,
            reason = "Background: auto-subscribe over the operator's configured names; logged, never answered to a caller"
        )]
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
        debug!(target: super::STREAMING_TARGET, session_id = %session_fp(session_id), backend = %backend_name, "Subscribed to backend notifications");

        Ok(())
    }

    /// Auto-subscribe a session to configured backends
    pub async fn auto_subscribe(&self, session_id: &str) {
        for backend_name in &self.config.auto_subscribe {
            if let Err(e) = self.subscribe_backend(session_id, backend_name).await {
                warn!(target: super::STREAMING_TARGET,
                    session_id = %session_fp(session_id),
                    backend = %backend_name,
                    error = %e,
                    "Failed to auto-subscribe to backend"
                );
            }
        }
    }
}
