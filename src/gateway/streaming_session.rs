// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::sync::OnceLock;

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
}

impl ClientSession {
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
            for (_, _, record) in self.records.read().iter() {
                record.clear();
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
