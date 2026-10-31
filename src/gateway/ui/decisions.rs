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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rand::RngExt as _;
use serde_json::{Map, Value, json};

use super::activity::replay;
use super::guard::Guard;
use crate::capability::CapabilityBackend;
use crate::decisions::{
    CapabilityChange, DecisionSet, Fold, GRANT_DECISION_KIND, Health, LogPos, Shared, Source,
    denial_from_record,
};
use crate::discovery::config_scanner::ConfigScanner;
use crate::discovery::listing::{CACHE_WINDOW, ClientFiles, DiscoveryCache, Listing, ScanSource};
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
    Router::new()
        .route(routes::UI_DECISIONS, get(list_decisions))
        .route(routes::UI_DECISIONS_COUNT, get(count_decisions))
}

async fn list_decisions(State(state): State<Arc<AppState>>, guard: Guard) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
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

/// `GET /ui/api/decisions/count`: the open count and its revision, read in
/// memory under the set's read lock, copying no item. The same 503 as the
/// list while a source is not yet readable: never a partial count.
async fn count_decisions(State(state): State<Arc<AppState>>, guard: Guard) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let Some(decisions) = state.meta_mcp.decisions() else {
        return unavailable(&[]);
    };
    match decisions.snapshot() {
        Some((count, revision)) => {
            Json(json!({"count": count, "revision": revision})).into_response()
        }
        None => unavailable(&decisions.view().err().unwrap_or_default()),
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

fn grant_pos(entry_hash: &str, counter: u64) -> LogPos {
    LogPos {
        log: Source::Access,
        entry: entry_hash.to_string(),
        counter,
    }
}

/// Notes handed from the log to the set and not yet applied. A burst past
/// this is dropped and recovered by a replay; the log is never held up.
const LIVE_QUEUE: usize = 4096;

/// Build the decision set for `meta`, start its replay, its tick and the
/// client-file discovery cache's refresh, and attach both. Each ends on
/// `shutdown`. `config_path` is the gateway.yaml the discovery route reads,
/// so the set judges adopt eligibility against the same file.
pub(in crate::gateway) fn start(
    meta: &Arc<MetaMcp>,
    config_path: Option<PathBuf>,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    let files: Arc<dyn ScanSource> = Arc::new(ClientFiles(ConfigScanner::new()));
    start_with(meta, config_path, shutdown, LIVE_QUEUE, files)
}

/// [`start`] over a given client-file scan source.
#[cfg(test)]
pub(in crate::gateway) fn start_with_source(
    meta: &Arc<MetaMcp>,
    config_path: Option<PathBuf>,
    shutdown: tokio::sync::broadcast::Receiver<()>,
    source: Arc<dyn ScanSource>,
) -> tokio::task::JoinHandle<()> {
    start_with(meta, config_path, shutdown, LIVE_QUEUE, source)
}

/// [`start`] with a hand-off queue of `queue` notes, over `files`.
fn start_with(
    meta: &Arc<MetaMcp>,
    config_path: Option<PathBuf>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    queue: usize,
    files: Arc<dyn ScanSource>,
) -> tokio::task::JoinHandle<()> {
    let config_path: Option<Arc<Path>> = config_path.map(Arc::from);
    let shared = Arc::new(Shared::with_key(rand::rng().random()));
    meta.set_decisions(Arc::clone(&shared));
    // UI decisions (a decline, a consumed allow) are first written by the
    // resolve routes; this build writes none, so there is none to read.
    shared.update(|set| set.set_health(Source::ControlPlane, Health::Ready));
    let latest = start_discovery(
        meta,
        &shared,
        files,
        config_path.clone(),
        shutdown.resubscribe(),
    );

    match meta.transparency_logger.as_ref() {
        None => shared.update(|set| set.set_health(Source::Access, Health::Absent)),
        Some(log) => {
            let (sender, receiver) = tokio::sync::mpsc::channel(queue.max(1));
            let dropped = Arc::new(Dropped::default());
            // Subscribed before the replay starts: a note written meanwhile
            // is held until the replay ends, and one the replay also reads
            // is the same record by its entry hash. The reader runs under
            // the log's lock, so it only hands off: no lock, no wait.
            let full = Arc::clone(&dropped);
            log.subscribe(
                GRANT_DECISION_KIND,
                Arc::new(
                    move |record: &Map<String, Value>, hash: &str, counter: u64| {
                        if let Some(event) = denial_from_record(record)
                            && sender.try_send((grant_pos(hash, counter), event)).is_err()
                        {
                            full.mark();
                        }
                    },
                ),
            );
            let path = log.path();
            let replays = Arc::new(Replays {
                path,
                shared: Arc::clone(&shared),
                one_at_a_time: tokio::sync::Mutex::new(()),
            });
            tokio::spawn(replay_until_ready(Arc::clone(&replays)));
            tokio::spawn(apply_live(receiver, dropped, replays));
        }
    }

    let meta = Arc::clone(meta);
    tokio::spawn(async move {
        let mut ticks = 0_u32;
        loop {
            let (meta, shared) = (Arc::clone(&meta), Arc::clone(&shared));
            let read_edge = ticks.is_multiple_of(EDGE_EVERY);
            ticks = ticks.wrapping_add(1);
            let (latest, config) = (Arc::clone(&latest), config_path.clone());
            let _ = tokio::task::spawn_blocking(move || {
                tick(&meta, &shared, &latest, config.as_deref(), read_edge);
            })
            .await;
            tokio::select! {
                _ = shutdown.recv() => return,
                () = tokio::time::sleep(TICK) => {}
            }
        }
    })
}

/// That a handed-off note was dropped on a full queue, and a wake for the
/// consumer: it may be waiting on an empty queue when the drop happens.
#[derive(Default)]
struct Dropped {
    any: std::sync::atomic::AtomicBool,
    wake: tokio::sync::Notify,
}

impl Dropped {
    /// Called by the reader under the log's lock: neither call waits.
    fn mark(&self) {
        self.any.store(true, std::sync::atomic::Ordering::Release);
        // A permit is kept if no one waits yet, so the wake is never lost.
        self.wake.notify_one();
    }
}

/// Apply handed-off notes to the set. A note dropped on a full queue would
/// make the count wrong, so the source reads unavailable (the snapshot
/// answers `None`) until a replay has read the log again.
async fn apply_live(
    mut receiver: tokio::sync::mpsc::Receiver<(LogPos, IdentityGrantAuditEvent)>,
    dropped: Arc<Dropped>,
    replays: Arc<Replays>,
) {
    let shared = Arc::clone(&replays.shared);
    loop {
        tokio::select! {
            note = receiver.recv() => {
                let Some((pos, event)) = note else { return };
                shared.update(|set| set.live(pos, Fold::Denial(event)));
            }
            () = dropped.wake.notified() => {}
        }
        if dropped.any.swap(false, std::sync::atomic::Ordering::AcqRel) {
            tracing::warn!(
                "decisions: notes arrived faster than they were applied; replaying the log"
            );
            shared.update(|set| set.set_health(Source::Access, Health::Unavailable));
            replay_until_ready(Arc::clone(&replays)).await;
        }
    }
}

/// What a replay reads, and the lock that keeps replays one at a time.
struct Replays {
    path: std::path::PathBuf,
    shared: Arc<Shared>,
    one_at_a_time: tokio::sync::Mutex<()>,
}

/// The longest wait between two replays of a log that could not be read.
const REPLAY_RETRY_MAX: Duration = Duration::from_secs(60);

/// Replay until the source is ready: a read that fails, or a replay that
/// lost a held note, runs again after a wait that doubles up to
/// [`REPLAY_RETRY_MAX`]. The source reads unavailable until then. Async, so
/// shutdown drops it between attempts.
async fn replay_until_ready(replays: Arc<Replays>) {
    // One replay at a time: two folding at once would let the first to end
    // mark the source ready while the other is still reading.
    let _one = replays.one_at_a_time.lock().await;
    // A replay that ended while this one waited may have marked the source
    // ready without what this one is here to read back: unavailable again.
    replays
        .shared
        .update(|set| set.set_health(Source::Access, Health::Unavailable));
    let mut wait = Duration::from_secs(1);
    loop {
        let (attempt, set) = (replays.path.clone(), Arc::clone(&replays.shared));
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
        // Every chained record carries its counter; one without is skipped.
        if let (Some(event), Some(counter)) = (
            denial_from_record(record),
            record.get("counter").and_then(Value::as_u64),
        ) {
            shared.update(|set| set.replayed(grant_pos(hash, counter), Fold::Denial(event)));
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
fn tick(
    meta: &MetaMcp,
    shared: &Shared,
    latest: &Latest,
    config_path: Option<&Path>,
    read_edge: bool,
) {
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
    // Re-judged every pass against the gateway.yaml now on disk: an adopt
    // writes a disabled backend no reload registers, and a hand edit nudges
    // nothing, so only this sees either (R5).
    if let Some(listing) = latest.lock().clone() {
        publish_discovery(config_path, shared, &listing);
    }
}

/// The last listing the discovery cache published, for the tick.
type Latest = parking_lot::Mutex<Option<Arc<Listing>>>;

/// Build the shared client-file discovery cache, attach it to `meta`, and
/// keep the set current from it: every rescan is published to the set while
/// the cache holds its lock, and the cache refreshes itself every window, so
/// an edited client file reaches the set with no GET (R4).
fn start_discovery(
    meta: &Arc<MetaMcp>,
    shared: &Arc<Shared>,
    files: Arc<dyn ScanSource>,
    config_path: Option<Arc<Path>>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> Arc<Latest> {
    let cache = Arc::new(DiscoveryCache::with_record_key(
        files,
        meta.record_key_shared(),
    ));
    let latest: Arc<Latest> = Arc::default();
    let (set, last) = (Arc::clone(shared), Arc::clone(&latest));
    cache.set_publisher(Arc::new(move |listing: &Arc<Listing>| {
        *last.lock() = Some(Arc::clone(listing));
        publish_discovery(config_path.as_deref(), &set, listing);
    }));
    meta.set_discovery_cache(Arc::clone(&cache));
    let set = Arc::clone(shared);
    tokio::spawn(async move {
        loop {
            // A timed-out scan with a listing cached serves it, and the set
            // keeps its items; only one with nothing cached takes them away.
            if cache.listing().await.is_err() {
                set.update(DecisionSet::discovery_down);
            }
            tokio::select! {
                _ = shutdown.recv() => return,
                () = tokio::time::sleep(CACHE_WINDOW) => {}
            }
        }
    });
    latest
}

/// Hand one listing to the set: its adopt decisions under the gateway.yaml
/// the discovery route reads, and its unreadable files.
fn publish_discovery(config_path: Option<&Path>, shared: &Shared, listing: &Listing) {
    let Ok(now) = crate::clock::utc_now() else {
        return;
    };
    let finds = super::discovery::adopt_finds(listing, config_path);
    let unreadable = listing.unreadable.clone();
    shared.update(|set| set.set_discovery(finds, unreadable, now));
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

/// The chain counter of the oldest record the log at `path` still keeps: a
/// refusal whose record's counter is below it has left the log. Counters, not times: a refusal is timed when it is
/// evaluated, which can be long before the append that places it.
fn retention_edge(path: &Path) -> Option<u64> {
    use std::io::BufRead as _;

    use crate::security::transparency_log::{pager, segments::list_segments};
    // With every sealed segment expired (disk-full recovery does that), the
    // active file holds the oldest kept record. Opened through the pager, so
    // a rotation between the listing and the open reads the segment it named;
    // retention removing it meanwhile answers `None`, an edge not known.
    let oldest = match list_segments(path).ok()?.into_iter().map(|s| s.seq).min() {
        Some(seq) => seq,
        None => pager::position(path, None).ok()?.segment,
    };
    let file = pager::open_segment(path, oldest, || {}).ok()??;
    let line = std::io::BufReader::new(file).lines().next()?.ok()?;
    let first: Value = serde_json::from_str(&line).ok()?;
    first.get("counter")?.as_u64()
}

#[cfg(test)]
#[path = "decisions_tests.rs"]
mod tests;
