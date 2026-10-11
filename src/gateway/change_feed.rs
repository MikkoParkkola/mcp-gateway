// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The change notifications a server mode can deliver, and so may advertise.

/// Which change notifications a server mode can deliver (F24).
///
/// `Http` drains every tool-set change into `announce_tools_changed`, which
/// reaches both eras. stdio drains the same changes to its one client, but
/// can only reach an initialize-era session: a 2026-07-28 client is told
/// through `subscriptions/listen`, which stdio does not serve (MIK-8345).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChangeFeed {
    /// The HTTP server: `notifications/tools/list_changed` reaches both eras.
    Http,
    /// The stdio server: `notifications/tools/list_changed` reaches a legacy
    /// (initialize-era) session only (MIK-8278).
    StdioLegacy,
    /// No producer is wired to the client; advertise no change notification.
    #[default]
    None,
}

impl ChangeFeed {
    /// Whether this mode delivers `notifications/tools/list_changed` to a
    /// client that asked through `initialize`.
    pub(crate) fn announces_tools(self) -> bool {
        matches!(self, Self::Http | Self::StdioLegacy)
    }

    /// The feed as `server/discover` (the 2026-07-28 surface) may state it:
    /// stdio delivers nothing to a modern client, so it advertises nothing.
    pub(crate) fn for_discover(self) -> Self {
        match self {
            Self::StdioLegacy => Self::None,
            other => other,
        }
    }
}

impl super::meta_mcp::MetaMcp {
    /// Bind the server mode once, when the server is built.
    pub(crate) fn set_change_feed(&self, feed: ChangeFeed) {
        let _ = self.change_feed.set(feed);
    }

    pub(crate) fn change_feed(&self) -> ChangeFeed {
        self.change_feed.get().copied().unwrap_or_default()
    }
}
