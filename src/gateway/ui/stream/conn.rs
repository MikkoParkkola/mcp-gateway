// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One connection's task: it owns the guard, so every exit gives the slots back.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::time::{Instant, interval_at};

use super::guard::{Guard, Snapshot};
use super::id::StreamId;
use super::sent::Sent;
use crate::gateway::auth::AuthState;
use crate::gateway::auth::live::{HeldCredential, current_caller};
use crate::gateway::router::AppState;

/// A comment frame this often keeps proxies from closing an idle stream.
pub(super) const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// Each stream re-checks its credential this often, changed state or not.
pub(super) const RECHECK: Duration = Duration::from_secs(1);
/// A write not finished in this long closes the stream; the client resumes.
pub(super) const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// A stream ends cleanly after this; it bounds a half-open peer.
pub(super) const MAX_LIFETIME: Duration = Duration::from_secs(3600);

pub(super) type Tx = mpsc::Sender<Result<Bytes, Infallible>>;

/// What the connection was admitted with.
pub(super) struct Conn {
    pub(super) state: Arc<AppState>,
    pub(super) auth: AuthState,
    pub(super) held: Option<HeldCredential>,
    pub(super) kinds: Vec<&'static str>,
    pub(super) admin: bool,
    /// The caller's `auth` member of the status payload, fixed at connect.
    pub(super) facts: Value,
    pub(super) tx: Tx,
    pub(super) guard: Guard,
}

/// Why the loop ended; logged at debug level.
#[derive(Clone, Copy, Debug)]
pub(super) enum End {
    ClientGone,
    WriteStalled,
    CredentialChanged,
    Lifetime,
}

/// One SSE frame as bytes.
pub(super) fn frame(event: &str, id: Option<&StreamId>, data: &Value) -> Bytes {
    let id = id.map_or(String::new(), |i| format!("id: {}\n", i.render()));
    Bytes::from(format!("event: {event}\n{id}data: {data}\n\n"))
}

impl Conn {
    /// Send one frame, giving up after [`WRITE_TIMEOUT`].
    pub(super) async fn send(&self, bytes: Bytes) -> Result<(), End> {
        match tokio::time::timeout(WRITE_TIMEOUT, self.tx.send(Ok(bytes))).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(End::ClientGone),
            Err(_) => Err(End::WriteStalled),
        }
    }

    /// Whether the held credential still gives this connection what it had.
    async fn still_entitled(&self) -> bool {
        match current_caller(&self.auth, self.held.as_ref()).await {
            Some(caller) => super::kinds_for(&caller.client) == self.kinds,
            None => false,
        }
    }
}

/// Run the connection until it ends; `resumed` is for the debug log only,
/// because snapshot kinds always resend their latest state.
pub(super) async fn run(conn: Conn, boot: u64, resumed: bool) {
    let hub = conn.state.dashboard_bootstrap.stream_hub();
    let mut rx = hub.subscribe();
    tracing::debug!(resumed, kinds = ?conn.kinds, "ui stream: open");
    let end = drive(&conn, boot, &mut rx).await.unwrap_or_else(|end| end);
    tracing::debug!(?end, "ui stream: closed");
    drop(conn.guard);
}

async fn drive(
    conn: &Conn,
    boot: u64,
    rx: &mut tokio::sync::watch::Receiver<Snapshot>,
) -> Result<End, End> {
    let mut sent = Sent::new(boot);
    let fresh = rx.wait_for(|s| s.fresh);
    let first = tokio::select! {
        r = fresh => r.map(|s| s.clone()).map_err(|_| End::ClientGone)?,
        () = conn.tx.closed() => return Err(End::ClientGone),
    };
    conn.send(frame(
        "hello",
        None,
        &json!({"kinds": conn.kinds, "head": sent.head(&first, conn.admin)}),
    ))
    .await?;
    sent.deliver(conn, &first).await?;
    let start = Instant::now();
    let mut keep = interval_at(start + KEEP_ALIVE, KEEP_ALIVE);
    let mut recheck = interval_at(start + RECHECK, RECHECK);
    let deadline = start + MAX_LIFETIME;
    loop {
        tokio::select! {
            () = conn.tx.closed() => return Ok(End::ClientGone),
            () = tokio::time::sleep_until(deadline) => return Ok(End::Lifetime),
            _ = recheck.tick() => {
                if !conn.still_entitled().await { return Ok(End::CredentialChanged); }
            }
            _ = keep.tick() => conn.send(Bytes::from_static(b": keep-alive\n\n")).await?,
            changed = rx.changed() => {
                changed.map_err(|_| End::ClientGone)?;
                let snap = rx.borrow_and_update().clone();
                sent.deliver(conn, &snap).await?;
            }
        }
    }
}
