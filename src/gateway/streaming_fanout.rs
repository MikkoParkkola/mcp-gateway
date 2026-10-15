// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Holds the seeding seam.

use super::NotificationMultiplexer;
#[cfg(test)]
use super::{SessionFrame, SessionOwner, broadcast};

impl NotificationMultiplexer {
    /// Test seam: an anonymous session under a chosen id, which production
    /// never creates (every production id is minted, F9).
    #[cfg(test)]
    pub(crate) fn seed_session(&self, id: &str) -> broadcast::Receiver<SessionFrame> {
        self.insert_session(&mut self.sessions.write(), id, SessionOwner::Anonymous)
            .subscribe()
    }
}
