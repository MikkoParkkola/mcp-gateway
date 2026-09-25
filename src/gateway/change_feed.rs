// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The change notifications a server mode can deliver, and so may advertise.

/// Which change notifications a server mode can deliver (F24).
///
/// `Http` drains every tool-set change into `announce_tools_changed`; stdio
/// has no channel for an unsolicited notification, so it is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChangeFeed {
    /// The HTTP server: `notifications/tools/list_changed` reaches both eras.
    Http,
    /// No producer is wired to the client; advertise no change notification.
    #[default]
    None,
}

impl super::meta_mcp::MetaMcp {
    /// Bind the server mode once, when the HTTP server is built.
    pub(crate) fn set_change_feed(&self, feed: ChangeFeed) {
        let _ = self.change_feed.set(feed);
    }

    pub(crate) fn change_feed(&self) -> ChangeFeed {
        self.change_feed.get().copied().unwrap_or_default()
    }
}
