// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where a streaming session is resumed or minted.
//!
//! Its own file because `streaming.rs` is over the 800-line ceiling and the
//! gate ratchets.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use tokio::sync::broadcast;
use tracing::info;
use uuid::Uuid;

use super::{ClientSession, NotificationMultiplexer, TaggedNotification};
use crate::gateway::auth::live::HeldCredential;
use crate::gateway::session_id::{SessionId, SessionOwner, session_fp};

impl NotificationMultiplexer {
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
    ) -> (String, broadcast::Receiver<TaggedNotification>) {
        let (session, rx) = self.session_for(session_id, owner);
        (session.id.expose_secret().to_string(), rx)
    }

    /// Resume under the read lock; the map is written only to mint. Nothing
    /// is re-checked under the write lock: a miss never adopts the presented id.
    fn session_for(
        &self,
        session_id: Option<&str>,
        owner: &SessionOwner,
    ) -> (Arc<ClientSession>, broadcast::Receiver<TaggedNotification>) {
        let resumed = session_id.and_then(|id| {
            let sessions = self.sessions.read();
            let session = sessions.get(id)?;
            Some((Arc::clone(session), session.tx.subscribe()))
        });
        resumed.unwrap_or_else(|| {
            let id = format!("gw-{}", Uuid::new_v4());
            info!(session_id = %session_fp(&id), "Created new streaming session");
            self.insert_session(&mut self.sessions.write(), &id, owner.clone())
        })
    }

    /// The one place a session enters the store.
    pub(super) fn insert_session(
        &self,
        sessions: &mut HashMap<SessionId, Arc<ClientSession>>,
        id: &str,
        owner: SessionOwner,
    ) -> (Arc<ClientSession>, broadcast::Receiver<TaggedNotification>) {
        let (tx, rx) = broadcast::channel(self.config.buffer_size);
        let id = SessionId::new(id);
        let session = ClientSession {
            id: id.clone(),
            tx,
            last_event_id: RwLock::new(None),
            subscribed_backends: RwLock::new(Vec::new()),
            created_at: Instant::now(),
            owner,
            credential: RwLock::new(None),
        };
        let session = Arc::new(session);
        sessions.insert(id, Arc::clone(&session));
        (session, rx)
    }

    /// Create or resume a session for `owner`, holding the credential it presented.
    pub(crate) fn get_or_create_session_scoped(
        &self,
        session_id: Option<&str>,
        owner: &SessionOwner,
        credential: Option<HeldCredential>,
    ) -> (String, broadcast::Receiver<TaggedNotification>) {
        // On the session itself: a second map lookup cost every request a
        // global lock acquisition (NFR.WORKLOAD.1).
        let (session, rx) = self.session_for(session_id, owner);
        *session.credential.write() = credential;
        (session.id.expose_secret().to_string(), rx)
    }
}
