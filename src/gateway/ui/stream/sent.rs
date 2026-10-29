// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What one connection has delivered, and the ids that say so.
//!
//! Every id-bearing frame carries the full composite of what this connection
//! delivered and changes only its own part. `hello` carries no id.

use serde_json::{Value, json};

use super::conn::{Conn, End, frame};
use super::guard::{Snapshot, same_ignoring_uptime};
use super::id::StreamId;

/// The delivered state of the snapshot kinds.
pub(super) struct Sent {
    id: StreamId,
    status: Option<Value>,
}

impl Sent {
    pub(super) fn new(boot: u64) -> Self {
        Self {
            id: StreamId {
                boot: Some(boot),
                ..StreamId::default()
            },
            status: None,
        }
    }

    /// The composite at the head, for `hello`: a client with no id yet keeps
    /// this as its position.
    pub(super) fn head(&self, snap: &Snapshot, admin: bool) -> String {
        StreamId {
            status: Some(snap.status_gen_for(admin)),
            reload: admin.then_some(snap.reload_gen),
            ..self.id.clone()
        }
        .render()
    }

    /// This caller's own status payload from the shared snapshot.
    fn projected(conn: &Conn, snap: &Snapshot) -> Value {
        let mut body = if conn.admin { &snap.full } else { &snap.counts }.clone();
        body["auth"] = conn.facts.clone();
        body
    }

    /// Send whatever differs from what was delivered. A counts-only caller
    /// gets nothing when only admin fields moved.
    pub(super) async fn deliver(&mut self, conn: &Conn, snap: &Snapshot) -> Result<(), End> {
        let payload = Self::projected(conn, snap);
        let changed = self
            .status
            .as_ref()
            .is_none_or(|last| !same_ignoring_uptime(last, &payload));
        if changed {
            self.id.status = Some(snap.status_gen_for(conn.admin));
            conn.send(frame("status", Some(&self.id), &payload)).await?;
            self.status = Some(payload);
        }
        if conn.kinds.contains(&"reload") && self.id.reload != Some(snap.reload_gen) {
            self.id.reload = Some(snap.reload_gen);
            let data = json!({ "generation": snap.reload_gen });
            conn.send(frame("reload", Some(&self.id), &data)).await?;
        }
        Ok(())
    }
}
