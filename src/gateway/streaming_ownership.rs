// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Session ownership, for routes that act under a presented session without
//! creating one.

use tokio::sync::broadcast;

use super::{NotificationMultiplexer, TaggedNotification};
use crate::gateway::auth::live::HeldCredential;
use crate::gateway::session_id::SessionOwner;

impl NotificationMultiplexer {
    /// Whether `session_id` names a live session `owner` holds. A request that
    /// acts under it counts as activity, so the reaper leaves it alone.
    pub(crate) fn touch_if_owned(&self, session_id: &str, owner: &SessionOwner) -> bool {
        self.sessions
            .read()
            .get(session_id)
            .is_some_and(|session| session.owner == *owner)
    }

    /// Resume `owner`'s live session named `session_id`, holding the
    /// credential it presented; `None` when there is no such session. Never
    /// opens one: under `hardened` only a declaring `initialize` may.
    pub(crate) fn resume_session_scoped(
        &self,
        session_id: Option<&str>,
        owner: &SessionOwner,
        credential: Option<HeldCredential>,
    ) -> Option<(String, broadcast::Receiver<TaggedNotification>)> {
        let sessions = self.sessions.read();
        let session = sessions
            .get(session_id?)
            .filter(|session| session.owner == *owner)?;
        *session.credential.write() = credential;
        Some((
            session.id.expose_secret().to_string(),
            session.tx.subscribe(),
        ))
    }
}
