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

/// Build the decision set for `meta`, start its replay and its tick, and
/// attach it. The tick ends on `shutdown`.
pub(in crate::gateway) fn start(
    meta: &Arc<MetaMcp>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    let shared = Arc::new(Shared::with_key(rand::rng().random()));
    meta.set_decisions(Arc::clone(&shared));
    // UI decisions (a decline, a consumed allow) are first written by the
    // resolve routes; this build writes none, so there is none to read.
    shared.update(|set| set.set_health(Source::ControlPlane, Health::Ready));

    match meta.transparency_logger.as_ref() {
        None => shared.update(|set| set.set_health(Source::Access, Health::Absent)),
        Some(log) => {
            // Subscribed before the replay starts: a note written meanwhile
            // is held until the replay ends, and one the replay also reads
            // is the same record by its entry hash.
            let live = Arc::clone(&shared);
            log.subscribe(
                GRANT_DECISION_KIND,
                Arc::new(move |record: &Map<String, Value>, hash: &str| {
                    if let Some(event) = denial_from_record(record) {
                        live.update(|set| set.live(grant_pos(hash), Fold::Denial(event)));
                    }
                }),
            );
            let path = log.path();
            let replaying = Arc::clone(&shared);
            tokio::task::spawn_blocking(move || replay_grant_decisions(&path, &replaying));
        }
    }

    let meta = Arc::clone(meta);
    tokio::spawn(async move {
        let mut ticks = 0_u32;
        loop {
            let (meta, shared) = (Arc::clone(&meta), Arc::clone(&shared));
            let read_edge = ticks % EDGE_EVERY == 0;
            ticks = ticks.wrapping_add(1);
            let _ = tokio::task::spawn_blocking(move || tick(&meta, &shared, read_edge)).await;
            tokio::select! {
                _ = shutdown.recv() => return,
                () = tokio::time::sleep(TICK) => {}
            }
        }
    })
}

/// Read every kept grant-decision record into the set, then mark the
/// source ready, which applies the notes held meanwhile.
fn replay_grant_decisions(path: &Path, shared: &Shared) {
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
            shared.update(|set| set.replay_done(Source::Access));
        }
        Err(error) => {
            tracing::warn!(%error, "decisions: the grant-decision log could not be replayed");
            shared.update(|set| set.set_health(Source::Access, Health::Unavailable));
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
            Some((backend, changes)) => set.set_capability_changes(&backend, changes, now),
            None => set.set_health(Source::Capability, Health::Absent),
        }
        if let Some(edge) = edge {
            set.evict_before(edge);
        }
    });
}

/// Each pin mismatch still on disk, read once. A file that is gone, or whose
/// bytes match their pin again, closes its decision and clears its record,
/// only while that record is the one read.
fn capability_changes(backend: &CapabilityBackend) -> Vec<CapabilityChange> {
    let mut changes = Vec::new();
    for record in backend.rug_pull_records() {
        let content = match std::fs::read_to_string(&record.file) {
            Ok(content) => content,
            Err(_) => {
                backend.clear_rug_pull_if(&record.file, &record.actual);
                continue;
            }
        };
        let actual = crate::capability::hash::compute_capability_hash(&content);
        if actual.eq_ignore_ascii_case(&record.expected) {
            backend.clear_rug_pull_if(&record.file, &record.actual);
            continue;
        }
        changes.push(CapabilityChange {
            file: record.file,
            actual,
            loaded_as: record.loaded_as,
            content,
        });
    }
    changes
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
