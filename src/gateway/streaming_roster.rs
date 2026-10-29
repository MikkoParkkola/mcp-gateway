// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The connected clients, listed by the name each reported in `initialize`.
//!
//! The one reader of [`ClientSession`]'s reported name. The listing carries a
//! name and a last-seen time and nothing else: no session id, no fingerprint,
//! no owner, so it cannot be used to find or name a session.
#![cfg_attr(
    not(any(test, feature = "webui")),
    allow(
        dead_code,
        reason = "the listing is read by the web UI's gateway route"
    )
)]

use std::sync::atomic::Ordering;

use chrono::{DateTime, Utc};
use serde::Serialize;

use super::NotificationMultiplexer;
use crate::gateway::session_id::SessionOwner;

/// Named clients one listing carries; the rest are counted in `named_total`.
pub(crate) const MAX_NAMED_CLIENTS: usize = 100;

/// One connected client as it described itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct NamedClient {
    /// The name the client reported; not an identity.
    pub reported_name: String,
    /// The last time a request used its session; `None` when the clock could
    /// not be read.
    pub last_seen: Option<DateTime<Utc>>,
}

/// The listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ClientRoster {
    /// At most [`MAX_NAMED_CLIENTS`], newest `last_seen` first, then by name.
    pub named: Vec<NamedClient>,
    /// Every named client, before the cap.
    pub named_total: usize,
    /// Whether `named` was cut at the cap.
    pub truncated: bool,
    /// Clients that reported no name, or none that survives cleaning.
    pub unnamed: usize,
}

impl NotificationMultiplexer {
    /// The clients with a session now. A provisional session is not a client
    /// yet (its owner has not presented it again), so it is in neither count.
    pub(crate) fn client_roster(&self) -> ClientRoster {
        // Only Arc clones are taken under the sessions lock; reading and
        // ordering the names happens after it is released. The cap cannot stop
        // the collection early: the order (and `named_total`) needs every row.
        let live: Vec<_> = self
            .sessions
            .read()
            .values()
            .filter(|session| !session.provisional.load(Ordering::SeqCst))
            .cloned()
            .collect();
        let mut named = Vec::new();
        let mut unnamed = 0;
        for session in &live {
            match session.reported_name.get() {
                Some(reported_name) => named.push(NamedClient {
                    reported_name,
                    last_seen: *session.last_seen.read(),
                }),
                None => unnamed += 1,
            }
        }
        named.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| a.reported_name.cmp(&b.reported_name))
        });
        let named_total = named.len();
        named.truncate(MAX_NAMED_CLIENTS);
        ClientRoster {
            named,
            named_total,
            truncated: named_total > MAX_NAMED_CLIENTS,
            unnamed,
        }
    }

    /// Keep `raw` as the reported name of `session_id`, when `owner` holds that
    /// session. The owner check repeats the one that resolved the session, so
    /// a name can only ever be set by the caller the session belongs to.
    pub(crate) fn record_reported_name(&self, session_id: &str, owner: &SessionOwner, raw: &str) {
        let sessions = self.sessions.read();
        if let Some(session) = sessions
            .get(session_id)
            .filter(|session| session.owner == *owner)
        {
            session.reported_name.set(raw);
        }
    }
}

#[cfg(test)]
#[path = "streaming_roster_tests.rs"]
mod tests;
