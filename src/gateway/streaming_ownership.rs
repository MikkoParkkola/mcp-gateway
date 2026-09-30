// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Read-only session ownership, for routes that act under a presented session
//! without creating one.

use super::NotificationMultiplexer;
use crate::gateway::session_id::SessionOwner;

impl NotificationMultiplexer {
    /// Whether `session_id` names a live session `owner` holds.
    pub(crate) fn is_owned_by(&self, session_id: &str, owner: &SessionOwner) -> bool {
        self.sessions
            .read()
            .get(session_id)
            .is_some_and(|session| session.owner == *owner)
    }
}
