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

use super::activity_source::ActivitySource;
use super::guard::{Guard, Snapshot};
use super::id::{LogCursor, StreamId};
use super::merge::{LogMerge, Out};
use super::sent::Sent;
use super::watcher;
use crate::config_reload::Generation;
use crate::gateway::auth::live::{HeldCredential, current_caller};
use crate::gateway::auth::{AuthState, AuthenticatedClient};
use crate::gateway::router::AppState;
use crate::gateway::ui::activity::access::{self, Access};
use crate::gateway::ui::activity::forward::StreamKind;
use crate::key_server::oidc::VerifiedIdentity;

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
    /// The caller's Activity access at connect, `None` when Activity refuses
    /// it. Every entitlement check resolves it again and ends the stream when
    /// it differs.
    pub(super) access: Option<Access>,
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
    /// A log source closed or failed, or a reset's replay reset again: the
    /// client reconnects with its id.
    LogEnded,
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
        let Some(caller) = current_caller(&self.auth, self.held.as_ref()).await else {
            return false;
        };
        let access = activity_access(&caller.client, caller.identity.as_ref(), &caller.generation);
        super::kinds_for(&caller.client, access.as_ref(), &self.state) == self.kinds
            && access == self.access
    }
}

/// The caller's Activity access under the role mapping of the generation it
/// was judged by, as the list resolves it: `None` when Activity refuses the
/// caller. A scoped key's backend list is sorted, so reordering it in the
/// config is no change.
pub(super) fn activity_access(
    client: &AuthenticatedClient,
    identity: Option<&VerifiedIdentity>,
    generation: &Generation,
) -> Option<Access> {
    let mapping = &generation.config().control_plane.role_mapping;
    let mut access = access::resolve(Some(client), identity, mapping).ok()?;
    if let Access::Scoped { backends, .. } = &mut access {
        backends.sort();
        backends.dedup();
    }
    Some(access)
}

/// The log kinds a merge serves, by index: activity (invocation log), config
/// (governance log).
const LOG_KINDS: [&str; 2] = ["activity", "config"];

type Merge = LogMerge<ActivitySource>;

/// A merge per advertised log kind, each over its own log and its own half of
/// the cursor. A reconnect resumes a half it carries; a half it does not
/// carry starts at that log's head, never at its oldest record.
async fn merges(conn: &Conn, resume: Option<&LogCursor>) -> [Option<Merge>; 2] {
    let mut out = [None, None];
    let Some(access) = conn.access.clone() else {
        return out;
    };
    let paths = advertised(
        &conn.kinds,
        [
            conn.state.transparency_log.as_ref().map(|l| l.path()),
            conn.state.governance_log.as_ref().map(|l| l.path()),
        ],
    );
    let kinds = [StreamKind::Activity, StreamKind::Config];
    for (i, path) in paths.into_iter().enumerate() {
        let Some(path) = path else {
            continue;
        };
        let source = Arc::new(ActivitySource::new(Arc::clone(&conn.state), kinds[i], path));
        let half = resume.and_then(|c| match i {
            0 => c.inv.clone().map(|m| LogCursor {
                inv: Some(m),
                gov: None,
            }),
            _ => c.gov.clone().map(|m| LogCursor {
                inv: None,
                gov: Some(m),
            }),
        });
        out[i] = Some(LogMerge::connect(source, access.clone(), half).await);
    }
    out
}

/// Each log, kept only where the connection advertised its kind: a log the
/// caller was not offered gets no merge, whatever its access would admit.
/// The first guard of a scoped admin's config: its access admits no config
/// row either, so no stream row can see this one alone.
fn advertised<T>(kinds: &[&str], [inv, gov]: [Option<T>; 2]) -> [Option<T>; 2] {
    [
        inv.filter(|_| kinds.contains(&LOG_KINDS[0])),
        gov.filter(|_| kinds.contains(&LOG_KINDS[1])),
    ]
}

/// What the connection has delivered across both logs.
fn delivered(logs: &[Option<Merge>; 2]) -> LogCursor {
    LogCursor {
        inv: logs[0].as_ref().and_then(|m| m.delivered().inv.clone()),
        gov: logs[1].as_ref().and_then(|m| m.delivered().gov.clone()),
    }
}

/// One live step of a merge, or never when the kind has none.
async fn live(merge: &mut Option<Merge>) -> Option<Vec<Out>> {
    match merge {
        Some(m) => m.step().await,
        None => std::future::pending().await,
    }
}

/// Write one step's outputs, oldest first. Each is acknowledged before it is
/// framed, so its id carries the position that includes it; a write that
/// fails ends the connection, whose client resumes from its last id.
async fn write(
    conn: &Conn,
    sent: &mut Sent,
    logs: &mut [Option<Merge>; 2],
    i: usize,
    outs: Vec<Out>,
) -> Result<(), End> {
    for out in outs {
        if let Some(m) = logs[i].as_mut() {
            m.ack(&out);
        }
        let cursor = delivered(logs);
        match out {
            Out::Row(row) => {
                sent.log_event(conn, LOG_KINDS[i], cursor, &row.data)
                    .await?;
            }
            Out::Reset => {
                let data = json!({ "kind": LOG_KINDS[i] });
                sent.log_event(conn, "reset", cursor, &data).await?;
            }
        }
    }
    Ok(())
}

/// Run the connection until it ends. `resume` is the log position a
/// reconnect carried; snapshot kinds always resend their latest state.
pub(super) async fn run(conn: Conn, boot: u64, resume: Option<LogCursor>) {
    let hub = conn.state.dashboard_bootstrap.stream_hub();
    let mut rx = hub.subscribe();
    tracing::debug!(resumed = resume.is_some(), kinds = ?conn.kinds, "ui stream: open");
    let end = drive(&conn, boot, &mut rx, resume.as_ref())
        .await
        .unwrap_or_else(|end| end);
    tracing::debug!(?end, "ui stream: closed");
    drop(conn.guard);
}

async fn drive(
    conn: &Conn,
    boot: u64,
    rx: &mut tokio::sync::watch::Receiver<Snapshot>,
    resume: Option<&LogCursor>,
) -> Result<End, End> {
    let mut sent = Sent::new(boot);
    // Subscribed and their heads read before `hello`: a row written after
    // this is delivered.
    let mut logs = merges(conn, resume).await;
    sent.set_cursor(delivered(&logs));
    let start = Instant::now();
    let deadline = start + MAX_LIFETIME;
    let mut recheck = interval_at(start + RECHECK, RECHECK);
    recheck.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let first = first_snapshot(conn, rx, &mut recheck, deadline).await?;
    let hello = json!({"kinds": conn.kinds, "head": sent.head(&first, conn.admin)});
    conn.send(hello_frame(&hello)).await?;
    sent.deliver(conn, &first).await?;
    let mut keep = interval_at(Instant::now() + KEEP_ALIVE, KEEP_ALIVE);
    keep.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        // Biased: whatever is already due (the client gone, the lifetime, a
        // check, a keep-alive, a snapshot) is served first, one per pass, and
        // with a scan pending a page is read only on a pass where nothing was
        // due, so a catch-up delays upkeep by one page at most. The page is
        // read after the race, never cancelled; the live receives wait until
        // the scan ends.
        let scan = (0..2).find(|&i| logs[i].as_ref().is_some_and(LogMerge::scanning));
        let [activity, config] = &mut logs;
        let pass = tokio::select! {
            biased;
            () = conn.tx.closed() => return Ok(End::ClientGone),
            () = tokio::time::sleep_until(deadline) => return Ok(End::Lifetime),
            _ = recheck.tick() => {
                if let Err(end) = conn.upkeep().await { return Ok(end); }
                Pass::Upkept
            }
            _ = keep.tick() => {
                conn.send(Bytes::from_static(b": keep-alive\n\n")).await?;
                Pass::Upkept
            }
            changed = rx.changed() => {
                changed.map_err(|_| End::ClientGone)?;
                let snap = rx.borrow_and_update().clone();
                sent.deliver(conn, &snap).await?;
                Pass::Upkept
            }
            () = std::future::ready(()), if scan.is_some() => Pass::Page,
            (i, out) = live_either(activity, config), if scan.is_none() => Pass::Live(i, out),
        };
        if let (Pass::Page, Some(i)) = (&pass, scan) {
            conn.require_entitled().await?;
            let step = match logs[i].as_mut() {
                Some(m) => m.step().await,
                None => None,
            };
            let Some(outs) = step else {
                return Ok(End::LogEnded);
            };
            write(conn, &mut sent, &mut logs, i, outs).await?;
            continue;
        }
        match pass {
            Pass::Live(_, None) => return Ok(End::LogEnded),
            Pass::Live(i, Some(outs)) => write(conn, &mut sent, &mut logs, i, outs).await?,
            // Served what was due; the next pass serves the next due one, or
            // the page.
            Pass::Upkept | Pass::Page => {}
        }
    }
}

/// What one pass of the connection's race did.
enum Pass {
    /// Served one due upkeep: a check, a keep-alive or a snapshot.
    Upkept,
    /// Nothing was due and a scan is pending: read its next page.
    Page,
    /// A live announcement from this log, or `None` when it closed.
    Live(usize, Option<Vec<Out>>),
}

/// The next live announcement from either log, the two raced fairly: a run
/// on one log never holds back the other.
async fn live_either(
    activity: &mut Option<Merge>,
    config: &mut Option<Merge>,
) -> (usize, Option<Vec<Out>>) {
    tokio::select! {
        out = live(activity) => (0, out),
        out = live(config) => (1, out),
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

#[cfg(test)]
#[path = "conn_tests.rs"]
mod tests;
