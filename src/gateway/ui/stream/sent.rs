// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What one connection has delivered, and the ids that say so.
//!
//! Every id-bearing frame carries the full composite of what this connection
//! delivered and changes only its own part. `hello` carries no id.

use serde_json::{Value, json};

use super::conn::{Conn, End, frame};
use super::guard::{Snapshot, same_ignoring_uptime};
use super::id::{LogCursor, StreamId};
use crate::gateway::authz::BackendGrant;
use crate::gateway::ui::status::{StatusView, status_body};

/// The delivered state of the snapshot kinds.
pub(super) struct Sent {
    id: StreamId,
    status: Option<Value>,
    /// Status frames sent so far: a scoped connection's status id part. Its
    /// counts are its own, so the shared generation would move with change
    /// outside its scope.
    status_frames: u64,
}

impl Sent {
    pub(super) fn new(boot: u64) -> Self {
        Self {
            id: StreamId {
                boot: Some(boot),
                ..StreamId::default()
            },
            status: None,
            status_frames: 0,
        }
    }

    /// The composite at the head, for `hello`: a client with no id yet keeps
    /// this as its position.
    pub(super) fn head(&self, snap: &Snapshot, conn: &Conn) -> String {
        StreamId {
            status: Some(self.status_part(snap, conn)),
            reload: conn.admin.then_some(snap.reload_gen),
            ..self.id.clone()
        }
        .render()
    }

    /// The log positions every later id carries, before `hello`: the head
    /// for a fresh connect, the resumed position for a reconnect.
    pub(super) fn set_cursor(&mut self, cursor: LogCursor) {
        self.id.cursor = cursor;
    }

    /// Send one log event (`activity`, `config` or `reset`) whose id carries
    /// `cursor`, the connection's delivered positions including this frame.
    pub(super) async fn log_event(
        &mut self,
        conn: &Conn,
        event: &str,
        cursor: LogCursor,
        data: &Value,
    ) -> Result<(), End> {
        self.id.cursor = cursor;
        conn.send(frame(event, Some(&self.id), data)).await
    }

    /// The status part of this connection's ids.
    fn status_part(&self, snap: &Snapshot, conn: &Conn) -> u64 {
        if conn.scope.is_some() {
            self.status_frames
        } else {
            snap.status_gen_for(conn.admin)
        }
    }

    /// This caller's own status payload. The scope decides first, as on the
    /// status route: a scoped caller, admin or not, gets the counts of its
    /// own backends, built afresh; an unscoped one the shared snapshot's view.
    fn projected(conn: &Conn, snap: &Snapshot) -> Value {
        let mut body = match &conn.scope {
            Some(backends) => status_body(
                &conn.state,
                StatusView::CountsOnly,
                BackendGrant::of_list(backends),
            ),
            None if conn.admin => snap.full.clone(),
            None => snap.counts.clone(),
        };
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
            self.status_frames += 1;
            self.id.status = Some(self.status_part(snap, conn));
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
