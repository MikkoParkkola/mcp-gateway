// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One connection's task: it owns the guard, so every exit gives the slots back.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior, interval_at};

use super::guard::{Guard, Snapshot};
use super::id::StreamId;
use super::sent::Sent;
use super::watcher;
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

/// One credential check may take this long; OIDC discovery or a key-server
/// fetch can stall. A miss ends the stream and the reconnect is judged afresh.
pub(super) const ENTITLEMENT_DEADLINE: Duration = Duration::from_secs(2);

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
    ValidationTimeout,
    Lifetime,
}

/// One SSE frame as bytes.
pub(super) fn frame(event: &str, id: Option<&StreamId>, data: &Value) -> Bytes {
    let id = id.map_or(String::new(), |i| format!("id: {}\n", i.render()));
    Bytes::from(format!("event: {event}\n{id}data: {data}\n\n"))
}

/// The `hello` frame with a `retry:` hint of 3 s plus up to 2 s of jitter, so
/// the browsers of a restarted gateway do not all reconnect at one instant.
fn hello_frame(data: &Value) -> Bytes {
    let jitter = crate::jitter::full_jitter(Duration::from_secs(2));
    let retry = (Duration::from_secs(3) + jitter).as_millis();
    let body = frame("hello", None, data);
    Bytes::from([format!("retry: {retry}\n").as_bytes(), &body].concat())
}

impl Conn {
    /// Send one frame, giving up after [`WRITE_TIMEOUT`]. The credential is
    /// checked before waiting for room, every [`RECHECK`] while waiting, and
    /// once more with room in hand, so a frame that waited never outlives a
    /// revocation.
    pub(super) async fn send(&self, bytes: Bytes) -> Result<(), End> {
        self.require_entitled().await?;
        let room = tokio::time::timeout(WRITE_TIMEOUT, self.tx.reserve());
        tokio::pin!(room);
        // A fixed cadence: a slow lookup delays one tick, never the schedule.
        let mut recheck = interval_at(Instant::now() + RECHECK, RECHECK);
        recheck.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let permit = {
            // Counted (test builds) only while the reservation is outstanding.
            #[cfg(test)]
            let _waiting = self
                .state
                .dashboard_bootstrap
                .stream_hub()
                .room_wait_started();
            loop {
                tokio::select! {
                    done = &mut room => match done {
                        Ok(Ok(permit)) => break permit,
                        Ok(Err(_)) => return Err(End::ClientGone),
                        Err(_) => return Err(End::WriteStalled),
                    },
                    _ = recheck.tick() => self.upkeep().await?,
                }
            }
        };
        self.require_entitled().await?;
        permit.send(Ok(bytes));
        Ok(())
    }

    /// What a stream does each time it wakes to check on itself, wherever it
    /// waits: re-check the credential, and revive a watcher that ended.
    async fn upkeep(&self) -> Result<(), End> {
        self.require_entitled().await?;
        let hub = self.state.dashboard_bootstrap.stream_hub();
        hub.ensure_watcher(|| watcher::spawn(&self.state));
        Ok(())
    }

    async fn require_entitled(&self) -> Result<(), End> {
        match tokio::time::timeout(ENTITLEMENT_DEADLINE, self.still_entitled()).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(End::CredentialChanged),
            Err(_) => Err(End::ValidationTimeout),
        }
    }

    /// Whether the held credential still gives this connection what it had.
    async fn still_entitled(&self) -> bool {
        #[cfg(test)]
        if self
            .state
            .dashboard_bootstrap
            .stream_hub()
            .validation_hangs()
        {
            std::future::pending::<()>().await;
        }
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
    let start = Instant::now();
    let deadline = start + MAX_LIFETIME;
    let mut recheck = interval_at(start + RECHECK, RECHECK);
    recheck.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let first = first_snapshot(conn, rx, &mut recheck, deadline).await?;
    let hello = json!({"kinds": conn.kinds, "head": sent.head(&first, conn.admin)});
    conn.send(hello_frame(&hello)).await?;
    sent.deliver(conn, &first).await?;
    let mut keep = interval_at(Instant::now() + KEEP_ALIVE, KEEP_ALIVE);
    loop {
        tokio::select! {
            () = conn.tx.closed() => return Ok(End::ClientGone),
            () = tokio::time::sleep_until(deadline) => return Ok(End::Lifetime),
            _ = recheck.tick() => {
                if let Err(end) = conn.upkeep().await { return Ok(end); }
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

/// Wait for the first fresh snapshot, with the same upkeep and lifetime limit
/// as the main loop: a revoked viewer ends and a dead watcher is replaced.
async fn first_snapshot(
    conn: &Conn,
    rx: &mut tokio::sync::watch::Receiver<Snapshot>,
    recheck: &mut tokio::time::Interval,
    deadline: Instant,
) -> Result<Snapshot, End> {
    // Clone inside the future: a `Ref` holds a lock and must not cross an await.
    let fresh = async { rx.wait_for(|s| s.fresh).await.map(|s| s.clone()) };
    tokio::pin!(fresh);
    loop {
        tokio::select! {
            r = &mut fresh => return r.map_err(|_| End::ClientGone),
            () = conn.tx.closed() => return Err(End::ClientGone),
            () = tokio::time::sleep_until(deadline) => return Err(End::Lifetime),
            _ = recheck.tick() => conn.upkeep().await?,
        }
    }
}
