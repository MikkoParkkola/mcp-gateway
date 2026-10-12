// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Session ownership, for routes that act under a presented session without
//! creating one.

use std::sync::Arc;

#[cfg(test)]
use tokio::sync::broadcast;

#[cfg(test)]
use super::SessionFrame;
use super::{ClientSession, NotificationMultiplexer};
use crate::gateway::auth::live::HeldCredential;
use crate::gateway::session_id::{SessionId, SessionOwner};

impl NotificationMultiplexer {
    /// Whether `session_id` names a live session `owner` holds. A request that
    /// acts under it counts as activity, so the reaper leaves it alone.
    pub(crate) fn touch_if_owned(&self, session_id: &str, owner: &SessionOwner) -> bool {
        let sessions = self.sessions.read();
        let Some(session) = sessions.get(session_id).filter(|s| s.owner == *owner) else {
            return false;
        };
        *session.last_active.write() = tokio::time::Instant::now();
        true
    }

    /// Resume `owner`'s live session named `session_id`, holding the
    /// credential it presented; `None` when there is no such session. Never
    /// opens one: under `hardened` only a declaring `initialize` may.
    #[cfg(test)]
    pub(crate) fn resume_session_scoped(
        &self,
        session_id: Option<&str>,
        owner: &SessionOwner,
        credential: Option<HeldCredential>,
    ) -> Option<(String, broadcast::Receiver<SessionFrame>)> {
        let session = self.resume_owned(session_id, owner, credential)?;
        Some((session.id.expose_secret().to_string(), session.subscribe()))
    }

    /// As [`Self::resume_session_scoped`], for a caller that only needs the
    /// id: it opens no notification channel (NFR.WORKLOAD.1).
    pub(crate) fn resume_session_id_scoped(
        &self,
        session_id: Option<&str>,
        owner: &SessionOwner,
        credential: Option<HeldCredential>,
    ) -> Option<SessionId> {
        let session = self.resume_owned(session_id, owner, credential)?;
        Some(session.id.clone())
    }

    fn resume_owned(
        &self,
        session_id: Option<&str>,
        owner: &SessionOwner,
        credential: Option<HeldCredential>,
    ) -> Option<Arc<ClientSession>> {
        let sessions = self.sessions.read();
        let session = sessions
            .get(session_id?)
            .filter(|session| session.owner == *owner)?;
        *session.credential.write() = credential;
        *session.last_active.write() = tokio::time::Instant::now();
        Some(Arc::clone(session))
    }
}
