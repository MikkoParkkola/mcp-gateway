// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/decisions`: the decisions an admin has open, and the wiring
//! that keeps the set current.
//!
//! The set is built once, when the HTTP server starts. Grant-decision notes
//! reach it as the log writes them; a startup replay reads the ones already
//! kept; a short tick re-checks the live grant rows, their expiry, the
//! capability backend's pin mismatches and the log's retention edge. A read
//! never scans anything: the route answers from memory.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use rand::RngExt as _;
use serde_json::{Map, Value, json};

use super::activity::replay;
use super::errors::admin_auth_required;
use super::is_admin;
use crate::capability::CapabilityBackend;
use crate::decisions::{
    CapabilityChange, Fold, GRANT_DECISION_KIND, Health, LogPos, Shared, Source, denial_from_record,
};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::router::AppState;
use crate::gateway::routes;
use crate::identity_grants::IdentityGrantAuditEvent;

/// How often the tick re-checks grants, expiry and capability changes.
const TICK: Duration = Duration::from_secs(2);

/// Every this many ticks the tick also reads the log's retention edge.
const EDGE_EVERY: u32 = 30;

/// The decisions route.
pub(super) fn decisions_router() -> Router<Arc<AppState>> {
    Router::new().route(routes::UI_DECISIONS, get(list_decisions))
}

async fn list_decisions(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
) -> Response {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return admin_auth_required().into_response();
    }
    let Some(decisions) = state.meta_mcp.decisions() else {
        return unavailable(&[]);
    };
    match decisions.view() {
        Ok(view) => Json(json!({
            "decisions": view.decisions,
            "revision": view.revision,
            "missing_kinds": view.missing_kinds,
            "partial_kinds": view.partial_kinds,
        }))
        .into_response(),
        Err(sources) => unavailable(&sources),
    }
}

/// 503 naming each source not yet readable and why.
fn unavailable(sources: &[(&'static str, &'static str)]) -> Response {
    let sources: Vec<Value> = sources
        .iter()
        .map(|(source, state)| json!({"source": source, "state": state}))
        .collect();
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": "decisions_unavailable", "sources": sources})),
    )
        .into_response()
}

fn grant_pos(entry_hash: &str) -> LogPos {
    LogPos {
        log: Source::Access,
        entry: entry_hash.to_string(),
    }
}

/// Notes handed from the log to the set and not yet applied. A burst past
/// this is dropped and recovered by a replay; the log is never held up.
const LIVE_QUEUE: usize = 4096;

/// Build the decision set for `meta`, start its replay and its tick, and
/// attach it. The tick ends on `shutdown`.
pub(in crate::gateway) fn start(
    meta: &Arc<MetaMcp>,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    start_with(meta, shutdown, LIVE_QUEUE)
}

/// [`start`] with a hand-off queue of `queue` notes.
fn start_with(
    meta: &Arc<MetaMcp>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    queue: usize,
) -> tokio::task::JoinHandle<()> {
    let shared = Arc::new(Shared::with_key(rand::rng().random()));
    meta.set_decisions(Arc::clone(&shared));
    // UI decisions (a decline, a consumed allow) are first written by the
    // resolve routes; this build writes none, so there is none to read.
    shared.update(|set| set.set_health(Source::ControlPlane, Health::Ready));

    match meta.transparency_logger.as_ref() {
        None => shared.update(|set| set.set_health(Source::Access, Health::Absent)),
        Some(log) => {
            let (sender, receiver) = tokio::sync::mpsc::channel(queue.max(1));
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            // Subscribed before the replay starts: a note written meanwhile
            // is held until the replay ends, and one the replay also reads
            // is the same record by its entry hash. The reader runs under
            // the log's lock, so it only hands off: no lock, no wait.
            let full = Arc::clone(&dropped);
            log.subscribe(
                GRANT_DECISION_KIND,
                Arc::new(move |record: &Map<String, Value>, hash: &str| {
                    if let Some(event) = denial_from_record(record)
                        && sender.try_send((hash.to_string(), event)).is_err()
                    {
                        full.store(true, std::sync::atomic::Ordering::Release);
                    }
                }),
            );
            let path = log.path();
            tokio::spawn(replay_until_ready(path.clone(), Arc::clone(&shared)));
            tokio::spawn(apply_live(receiver, dropped, path, Arc::clone(&shared)));
        }
    }

    let meta = Arc::clone(meta);
    tokio::spawn(async move {
        let mut ticks = 0_u32;
        loop {
            let (meta, shared) = (Arc::clone(&meta), Arc::clone(&shared));
            let read_edge = ticks.is_multiple_of(EDGE_EVERY);
            ticks = ticks.wrapping_add(1);
            let _ = tokio::task::spawn_blocking(move || tick(&meta, &shared, read_edge)).await;
            tokio::select! {
                _ = shutdown.recv() => return,
                () = tokio::time::sleep(TICK) => {}
            }
        }
    })
}

/// Apply handed-off notes to the set. A note dropped on a full queue would
/// make the count wrong, so the source reads unavailable (the snapshot
/// answers `None`) until a replay has read the log again.
async fn apply_live(
    mut receiver: tokio::sync::mpsc::Receiver<(String, IdentityGrantAuditEvent)>,
    dropped: Arc<std::sync::atomic::AtomicBool>,
    path: std::path::PathBuf,
    shared: Arc<Shared>,
) {
    while let Some((hash, event)) = receiver.recv().await {
        shared.update(|set| set.live(grant_pos(&hash), Fold::Denial(event)));
        if dropped.swap(false, std::sync::atomic::Ordering::AcqRel) {
            tracing::warn!(
                "decisions: notes arrived faster than they were applied; replaying the log"
            );
            shared.update(|set| set.set_health(Source::Access, Health::Unavailable));
            replay_until_ready(path.clone(), Arc::clone(&shared)).await;
        }
    }
}

/// The longest wait between two replays of a log that could not be read.
const REPLAY_RETRY_MAX: Duration = Duration::from_secs(60);

/// Replay until the source is ready: a read that fails, or a replay that
/// lost a held note, runs again after a wait that doubles up to
/// [`REPLAY_RETRY_MAX`]. The source reads unavailable until then. Async, so
/// shutdown drops it between attempts.
async fn replay_until_ready(path: std::path::PathBuf, shared: Arc<Shared>) {
    let mut wait = Duration::from_secs(1);
    loop {
        let (attempt, set) = (path.clone(), Arc::clone(&shared));
        let ready = tokio::task::spawn_blocking(move || replay_grant_decisions(&attempt, &set))
            .await
            .unwrap_or(false);
        if ready {
            return;
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(REPLAY_RETRY_MAX);
    }
}

/// Read every kept grant-decision record into the set, then mark the
/// source ready, which applies the notes held meanwhile. Whether it became
/// ready: not if the read failed or a held note was dropped meanwhile.
fn replay_grant_decisions(path: &Path, shared: &Shared) -> bool {
    let started = std::time::Instant::now();
    let read = replay::records(path, GRANT_DECISION_KIND, |record, hash| {
        if let Some(event) = denial_from_record(record) {
            shared.update(|set| set.replayed(grant_pos(hash), Fold::Denial(event)));
        }
    });
    match read {
        Ok(replayed) => {
            tracing::info!(
                records = replayed.records,
                unreadable = replayed.unreadable,
                elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                "decisions: grant-decision replay finished"
            );
            shared.update(|set| set.replay_done(Source::Access))
        }
        Err(error) => {
            tracing::warn!(%error, "decisions: the grant-decision log could not be replayed");
            shared.update(|set| set.set_health(Source::Access, Health::Unavailable));
            false
        }
    }
}

/// One tick: the live grant rows at the current time, the capability
/// backend's changes, and every `read_edge` tick the log's retention edge.
fn tick(meta: &MetaMcp, shared: &Shared, read_edge: bool) {
    // A clock before 1970 judges no expiry: the tick waits for a readable one.
    let Ok(now) = crate::clock::utc_now() else {
        return;
    };
    let grants = meta.grant_rows();
    let backend = meta.capabilities.read().clone();
    let changes = backend.map(|backend| {
        let name = backend.name.clone();
        (name, capability_changes(&backend))
    });
    let edge = read_edge
        .then(|| {
            meta.transparency_logger
                .as_ref()
                .and_then(|log| retention_edge(&log.path()))
        })
        .flatten();
    shared.update(|set| {
        set.set_grants(grants, now);
        match changes {
            Some((backend, Some(changes))) => set.set_capability_changes(&backend, changes, now),
            // A recorded file could not be read: never a list missing it.
            Some((_, None)) => set.set_health(Source::Capability, Health::Unavailable),
            None => set.set_health(Source::Capability, Health::Absent),
        }
        if let Some(edge) = edge {
            set.evict_before(edge);
        }
    });
}

/// The backend's pin mismatches as decisions, each from one read of its
/// bytes, or `None` when a recorded file could not be read.
fn capability_changes(backend: &CapabilityBackend) -> Option<Vec<CapabilityChange>> {
    let mismatches = backend.current_mismatches();
    if mismatches.incomplete {
        return None;
    }
    let changes = mismatches
        .changes
        .into_iter()
        .map(|(record, content, actual)| CapabilityChange {
            file: record.file,
            actual,
            loaded_as: record.loaded_as,
            content,
        })
        .collect();
    Some(changes)
}

/// When the oldest kept segment of the log at `path` was opened: no record
/// older than this is kept.
fn retention_edge(path: &Path) -> Option<DateTime<Utc>> {
    use crate::security::transparency_log::segments::{list_segments, read_first_line};
    let oldest = list_segments(path)
        .ok()?
        .into_iter()
        .min_by_key(|s| s.seq)?;
    let first: Value = serde_json::from_str(&read_first_line(&oldest.path).ok()??).ok()?;
    let opened = first.get("segment_opened_at")?.as_u64()?;
    DateTime::from_timestamp(i64::try_from(opened).ok()?, 0)
}

#[cfg(test)]
#[path = "decisions_tests.rs"]
mod tests;
