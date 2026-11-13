// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decisions route over a real transparency log: the replay of notes
//! already kept, a note written live, the admin rule, and eviction at the
//! log's retention edge.

use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::extract::State;
use axum::http::{Method, StatusCode};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use super::super::errors::admin_auth_required;
use super::*;
use crate::config::AuthConfig;
use crate::gateway::auth::AuthenticatedClient;
use crate::security::audit::AuditEnvelope;
use crate::security::audit_rotation_config::{OnDiskFull, RotationConfig};
use crate::security::{TransparencyLogConfig, TransparencyLogger};

fn log_in(dir: &tempfile::TempDir, max_segment_bytes: u64, retain: u32) -> Arc<TransparencyLogger> {
    let config = TransparencyLogConfig {
        enabled: true,
        path: dir
            .path()
            .join("transparency.jsonl")
            .to_string_lossy()
            .into_owned(),
        key_id: "test".into(),
        shared_secret: String::new(),
        rotation: RotationConfig {
            max_segment_bytes,
            max_segment_age_secs: 0,
            retain_segments: retain,
            on_disk_full: OnDiskFull::ExpireOldest,
        },
    };
    Arc::new(TransparencyLogger::open(Arc::new(config)).expect("the log opens"))
}

/// A missing-grant note for Alice's agent on `capability`, as the dispatch
/// writes one.
fn note(capability: &str, at: DateTime<Utc>) -> Map<String, Value> {
    let Value::Object(fields) = json!({
        "kind": GRANT_DECISION_KIND,
        "timestamp": at.to_rfc3339(),
        "reason": "missing_grant",
        "capability": capability,
        "scope": "execute",
        "agent_id": "mtls:runner",
        "subject": {"authority": "https://idp.example", "subject": "alice"},
    }) else {
        unreachable!("a JSON object literal")
    };
    fields
}

fn write(log: &TransparencyLogger, fields: Map<String, Value>) {
    log.append_event(fields, &AuditEnvelope::gateway())
        .expect("the record is written");
}

/// A gateway state whose `MetaMcp` writes `log`, and the store dir it keeps.
async fn state_with(
    log: &Arc<TransparencyLogger>,
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let log = Arc::clone(log);
    crate::gateway::router::tests::audience_state(
        &AuthConfig::default(),
        (None, None),
        move |mut meta| {
            meta.transparency_logger = Some(log);
            meta
        },
    )
    .await
}

fn client(admin: bool) -> AuthenticatedClient {
    AuthenticatedClient {
        name: "decisions-route".to_owned(),
        rate_limit: 0,
        backends: vec!["*".to_owned()],
        allowed_tools: None,
        denied_tools: None,
        admin,
        principal: crate::gateway::auth::principal_of("decisions-route-secret"),
        quota_principal: None,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    }
}

async fn get(state: &Arc<AppState>, admin: bool) -> (StatusCode, Value) {
    let guard = Guard::for_route(routes::UI_DECISIONS, &Method::GET, Some(client(admin)));
    let response = list_decisions(State(Arc::clone(state)), guard).await;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The admin's answer once `ready` holds, waiting for the replay and the
/// first tick; fails after a generous bound, never on a slow machine first.
async fn served_when(state: &Arc<AppState>, ready: impl Fn(&Value) -> bool) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let (status, body) = get(state, true).await;
        if status == StatusCode::OK && ready(&body) {
            return body;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "never served: {status} {body}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn scope_len(body: &Value) -> usize {
    body["decisions"][0]["scope"].as_array().map_or(0, Vec::len)
}

#[tokio::test]
async fn an_admin_is_served_the_open_decisions_and_no_one_else() {
    let dir = tempfile::tempdir().expect("dir");
    let log = log_in(&dir, 1 << 20, 12);
    let now = crate::clock::utc_now().expect("a readable clock");
    write(&log, note("stripe.charges", now));
    let (state, _store) = state_with(&log).await;

    let (status, body) = get(&state, true).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "before start: {body}"
    );
    assert_eq!(body["error"], "decisions_unavailable", "{body}");

    let (_stop, shutdown) = tokio::sync::broadcast::channel(1);
    let _tick = start(&state.meta_mcp, None, shutdown);

    // The note kept before start is replayed.
    let body = served_when(&state, |body| scope_len(body) == 1).await;
    assert_eq!(body["decisions"][0]["kind"], "access_request", "{body}");
    assert_eq!(body["missing_kinds"], json!([]), "{body}");
    assert_eq!(
        body["partial_kinds"],
        json!(["capability_changed"]),
        "{body}"
    );
    let revision = body["revision"].as_u64().expect("a revision");

    let (status, _) = get(&state, false).await;
    assert_eq!(status, admin_auth_required().0, "a non-admin is refused");

    // A note written now arrives live, and the revision rises.
    write(&log, note("stripe.refunds", now));
    let body = served_when(&state, |body| scope_len(body) == 2).await;
    assert!(body["revision"].as_u64() > Some(revision), "{body}");
}

#[tokio::test]
async fn a_request_whose_refusals_left_the_log_is_closed() {
    let dir = tempfile::tempdir().expect("dir");
    // Small segments, one kept: the fillers below expire the first one.
    let log = log_in(&dir, 2048, 1);
    let (state, _store) = state_with(&log).await;
    let (_stop, shutdown) = tokio::sync::broadcast::channel(1);
    let _tick = start(&state.meta_mcp, None, shutdown);
    let now = crate::clock::utc_now().expect("a readable clock");

    write(
        &log,
        note(
            "stripe.charges",
            now - crate::duration_bound::delta!(seconds, 1200),
        ),
    );
    served_when(&state, |body| scope_len(body) == 1).await;
    for n in 0..64 {
        let Value::Object(filler) = json!({"kind": "filler", "n": n, "pad": "x".repeat(200)})
        else {
            unreachable!("a JSON object literal")
        };
        write(&log, filler);
    }
    assert!(
        retention_edge(&log.path()).is_some(),
        "the first refusal's segment has expired"
    );
    // Written after the edge, so kept, though timed an hour ago: a refusal
    // is timed when evaluated, long before a slow call's append.
    write(
        &log,
        note(
            "stripe.refunds",
            now - crate::duration_bound::delta!(seconds, 3600),
        ),
    );

    // Both are open (the hand-off is asynchronous) before the edge is read.
    served_when(&state, |body| scope_len(body) == 2).await;
    let decisions = state.meta_mcp.decisions().expect("attached");
    tick(&state.meta_mcp, decisions, &Latest::default(), None, true);

    let body = served_when(&state, |body| scope_len(body) == 1).await;
    let scope = body["decisions"][0]["scope"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(scope.len(), 1, "{body}");
    assert_eq!(scope[0]["capability"], "stripe.refunds", "{body}");
}

/// Hold the set's write lock on another thread until `release` is sent: the
/// state a slow consumer leaves the set in.
async fn hold_the_set(decisions: Arc<Shared>) -> std::sync::mpsc::Sender<()> {
    let (held, is_held) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        decisions.update(|_| {
            let _ = held.send(());
            let _ = released.recv();
        });
    });
    is_held.await.expect("the lock is taken");
    release
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_that_cannot_take_the_set_does_not_hold_up_an_append() {
    let dir = tempfile::tempdir().expect("dir");
    let log = log_in(&dir, 1 << 20, 12);
    let (state, _store) = state_with(&log).await;
    let (_stop, shutdown) = tokio::sync::broadcast::channel(1);
    let _tick = start(&state.meta_mcp, None, shutdown);
    served_when(&state, |_| true).await;

    let release = hold_the_set(Arc::clone(state.meta_mcp.decisions().expect("attached"))).await;
    let now = crate::clock::utc_now().expect("a readable clock");
    let writer = Arc::clone(&log);
    let append = tokio::task::spawn_blocking(move || write(&writer, note("stripe.charges", now)));
    let finished = tokio::time::timeout(Duration::from_secs(30), append).await;
    let _ = release.send(());
    finished
        .expect("the append finished while the set was held")
        .expect("the append task ran");

    served_when(&state, |body| scope_len(body) == 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_burst_past_the_queue_is_replayed_not_lost() {
    let dir = tempfile::tempdir().expect("dir");
    let log = log_in(&dir, 1 << 20, 12);
    let (state, _store) = state_with(&log).await;
    let (_stop, shutdown) = tokio::sync::broadcast::channel(1);
    let files = tempfile::tempdir().expect("tempdir");
    let none = super::super::discovery_wiring_tests::Scripted::new(files.path(), &[]);
    let _tick = start_with(&state.meta_mcp, None, shutdown, 1, none);
    served_when(&state, |_| true).await;

    let release = hold_the_set(Arc::clone(state.meta_mcp.decisions().expect("attached"))).await;
    let now = crate::clock::utc_now().expect("a readable clock");
    for capability in ["a.one", "a.two", "a.three", "a.four", "a.five"] {
        write(&log, note(capability, now));
    }
    let _ = release.send(());

    // Past the one-note queue, notes were dropped; the replay reads them back.
    served_when(&state, |body| scope_len(body) == 5).await;
}

/// The replay's cost over a log at the default retention cap (twelve sealed
/// 64 MiB segments and the active one, 832 MiB; one record in twenty a grant
/// decision, from 500 subjects): run by hand, in a release build, with
/// `--ignored --nocapture`; the PR states its numbers. The reader parses lines only, so the segment is
/// written directly rather than through the chained logger.
#[test]
#[ignore = "a measurement, run by hand"]
fn measure_the_replay_at_the_retention_cap() {
    use std::io::Write as _;

    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("transparency.jsonl");
    let mut file = std::io::BufWriter::new(std::fs::File::create(&path).expect("file"));
    let (mut bytes, mut notes) = (0_u64, 0_u64);
    let at = crate::clock::utc_now()
        .expect("a readable clock")
        .to_rfc3339();
    let mut n = 0_u64;
    while bytes < 13 * 64 * 1024 * 1024 {
        let line = if n.is_multiple_of(20) {
            notes += 1;
            json!({
                "kind": GRANT_DECISION_KIND, "timestamp": at, "reason": "missing_grant",
                "capability": format!("cap.{}", n % 50), "scope": "execute",
                "agent_id": "mtls:runner",
                "subject": {"authority": "https://idp.example", "subject": format!("user-{}", notes % 500)},
                "counter": n, "entry_hash": format!("h{n}"),
            })
        } else {
            json!({"kind": "invocation", "counter": n, "entry_hash": format!("h{n}"), "pad": "x".repeat(220)})
        };
        let text = line.to_string();
        writeln!(file, "{text}").expect("write");
        bytes += text.len() as u64 + 1;
        n += 1;
    }
    file.flush().expect("flush");
    drop(file);

    // Resident memory on Linux, where the measurement is run.
    let rss_kib = || {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("VmRSS:"))
                    .and_then(|line| line.split_whitespace().nth(1)?.parse::<u64>().ok())
            })
            .unwrap_or_default()
    };
    let shared = Shared::with_key([7; 32]);
    shared.update(|set| {
        set.set_health(Source::ControlPlane, Health::Ready);
        set.set_health(Source::Capability, Health::Absent);
    });
    let before = rss_kib();
    let started = std::time::Instant::now();
    replay_grant_decisions(&path, &shared);
    let elapsed = started.elapsed();
    let after = rss_kib();
    let view = shared.view().expect("replayed");
    println!(
        "replay: {bytes} bytes, {n} records, {notes} grant notes, {} open requests, \
         {elapsed:?}, rss {before} KiB -> {after} KiB",
        view.decisions.len(),
    );
    assert_eq!(view.decisions.len(), 500, "one request per subject");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replay_waits_for_the_one_already_running() {
    let dir = tempfile::tempdir().expect("dir");
    let log = log_in(&dir, 1 << 20, 12);
    let shared = Arc::new(Shared::with_key([7; 32]));
    shared.update(|set| {
        set.set_health(Source::ControlPlane, Health::Ready);
        set.set_health(Source::Capability, Health::Absent);
        set.set_health(Source::Discovery, Health::Ready);
    });
    let replays = Arc::new(Replays {
        path: log.path(),
        shared: Arc::clone(&shared),
        one_at_a_time: tokio::sync::Mutex::new(()),
    });

    // Another replay is running: it holds the lock.
    let running = replays.one_at_a_time.lock().await;
    let waiting = tokio::spawn(replay_until_ready(Arc::clone(&replays)));
    tokio::task::yield_now().await;
    assert!(
        shared.view().is_err(),
        "no second replay marks the source ready"
    );

    drop(running);
    tokio::time::timeout(Duration::from_secs(30), waiting)
        .await
        .expect("the waiting replay ran once the first ended")
        .expect("the replay task finished");
    assert!(
        shared.view().is_ok(),
        "ready after the replay it waited for"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_waiting_replay_unmarks_a_ready_it_did_not_read() {
    let dir = tempfile::tempdir().expect("dir");
    let shared = Arc::new(Shared::with_key([7; 32]));
    // A directory is no log: this replay cannot read, so it never marks ready.
    let replays = Arc::new(Replays {
        path: dir.path().to_path_buf(),
        shared: Arc::clone(&shared),
        one_at_a_time: tokio::sync::Mutex::new(()),
    });
    let running = replays.one_at_a_time.lock().await;
    let waiting = tokio::spawn(replay_until_ready(Arc::clone(&replays)));

    // The running replay ends and marks the source ready.
    shared.update(|set| {
        set.set_health(Source::ControlPlane, Health::Ready);
        set.set_health(Source::Capability, Health::Absent);
        set.set_health(Source::Access, Health::Ready);
        set.set_health(Source::Discovery, Health::Ready);
    });
    assert!(shared.view().is_ok());
    drop(running);

    // The waiting replay takes the lock and has read nothing: not ready.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while shared.view().is_ok() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the waiting replay left a ready it had not read"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    waiting.abort();
}

#[test]
fn a_log_with_no_sealed_segment_has_an_edge() {
    let dir = tempfile::tempdir().expect("dir");
    let log = log_in(&dir, 1 << 20, 12);
    let now = crate::clock::utc_now().expect("a readable clock");
    write(&log, note("stripe.charges", now));

    let edge = retention_edge(&log.path()).expect("the active file's first record");
    let last = std::fs::read_to_string(log.path())
        .expect("the log")
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|record| record.get("counter").and_then(Value::as_u64))
        .max()
        .expect("a written record");
    assert!(edge <= last, "the edge keeps the record just written");
}

async fn count(state: &Arc<AppState>, admin: bool) -> (StatusCode, Value) {
    let guard = Guard::for_route(
        routes::UI_DECISIONS_COUNT,
        &Method::GET,
        Some(client(admin)),
    );
    let response = count_decisions(State(Arc::clone(state)), guard).await;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// R6: while a source is unavailable the count answers the list's own 503,
/// never a number.
#[tokio::test]
async fn the_count_is_unavailable_while_a_source_is() {
    let dir = tempfile::tempdir().expect("dir");
    let log = log_in(&dir, 1 << 20, 12);
    let (state, _store) = state_with(&log).await;
    let shared = Arc::new(Shared::with_key([7; 32]));
    shared.update(|set| {
        set.set_health(Source::ControlPlane, Health::Ready);
        set.set_health(Source::Capability, Health::Absent);
        set.set_health(Source::Access, Health::Ready);
        set.discovery_down();
    });
    state.meta_mcp.set_decisions(shared);
    let (status, list) = get(&state, true).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{list}");
    let (status, body) = count(&state, true).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body, list, "the count's 503 is the list's");
}

/// R6: the count is the list's length and revision, for an admin only.
#[tokio::test]
async fn the_count_is_the_lists_length_and_revision_for_an_admin_only() {
    let dir = tempfile::tempdir().expect("dir");
    let log = log_in(&dir, 1 << 20, 12);
    let now = crate::clock::utc_now().expect("a readable clock");
    write(&log, note("stripe.charges", now));
    let (state, _store) = state_with(&log).await;

    let (status, body) = count(&state, true).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "before start: {body}"
    );
    assert_eq!(body["error"], "decisions_unavailable", "{body}");

    let (_stop, shutdown) = tokio::sync::broadcast::channel(1);
    let _tick = start(&state.meta_mcp, None, shutdown);
    let list = served_when(&state, |body| scope_len(body) == 1).await;

    let (status, body) = count(&state, true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({
            "count": list["decisions"].as_array().map_or(0, Vec::len),
            "revision": list["revision"],
        }),
    );

    let (status, _) = count(&state, false).await;
    assert_eq!(status, admin_auth_required().0, "a non-admin is refused");
}

// ---- POST /ui/api/decisions/{id}/resolve: the frame ----

async fn resolve(
    state: &Arc<AppState>,
    admin: bool,
    id: &str,
    body: impl AsRef<[u8]>,
) -> (StatusCode, Value) {
    let guard = Guard::for_route(
        routes::UI_DECISIONS_RESOLVE,
        &Method::POST,
        Some(client(admin)),
    );
    let response = resolve_decision(
        State(Arc::clone(state)),
        axum::Extension(state.live_config.generation()),
        guard,
        axum::extract::Path(id.to_owned()),
        axum::body::Bytes::copy_from_slice(body.as_ref()),
    )
    .await;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn deny_body(digest: &str) -> Value {
    json!({"action": "deny", "reason": "not needed", "scope_digest": digest})
}

/// A started gateway with one open access request; its id and digest.
async fn one_request() -> (
    Arc<AppState>,
    Arc<TransparencyLogger>,
    String,
    String,
    (tempfile::TempDir, crate::gateway::router::tests::FixtureDir),
) {
    let dir = tempfile::tempdir().expect("dir");
    let log = log_in(&dir, 1 << 20, 12);
    let now = crate::clock::utc_now().expect("a readable clock");
    write(&log, note("stripe.charges", now));
    let (state, store) = state_with(&log).await;
    let (_stop, shutdown) = tokio::sync::broadcast::channel(1);
    let _tick = start(&state.meta_mcp, None, shutdown);
    let body = served_when(&state, |body| scope_len(body) == 1).await;
    let item = &body["decisions"][0];
    let id = item["id"].as_str().expect("an id").to_owned();
    let digest = item["scope_digest"].as_str().expect("a digest").to_owned();
    (state, log, id, digest, (dir, store))
}

#[tokio::test]
async fn resolve_answers_one_status_per_state_and_writes_nothing() {
    let (state, _log, id, digest, _keep) = one_request().await;
    assert_eq!(digest.len(), 64, "{digest}");

    let (status, body) = resolve(&state, false, &id, deny_body(&digest).to_string()).await;
    assert_ne!(status, StatusCode::OK, "a non-admin is refused: {body}");
    assert_ne!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "refused before the body: {body}"
    );

    for bad in [
        "not json".to_owned(),
        json!({"action": "deny", "reason": "r", "scope_digest": digest, "extra": 1}).to_string(),
        json!({"action": "deny", "reason": " ", "scope_digest": digest}).to_string(),
        json!({"action": "deny", "reason": "r", "scope_digest": "abc"}).to_string(),
        json!({"action": "accept", "reason": "r", "scope_digest": digest}).to_string(),
        json!({"action": "accept", "reason": "r", "scope_digest": digest,
               "ttl_seconds": 60, "permanent": true})
        .to_string(),
        json!({"action": "deny", "reason": "r", "scope_digest": digest,
               "ttl_seconds": 60})
        .to_string(),
    ] {
        let (status, body) = resolve(&state, true, &id, &bad).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {body}");
        assert_eq!(body["error"], "invalid_body", "{bad}");
    }

    let (status, body) = resolve(&state, true, "no-such-id", deny_body(&digest).to_string()).await;
    assert_eq!(
        (status, &body["error"]),
        (StatusCode::NOT_FOUND, &json!("not_found"))
    );

    let stale = "0".repeat(64);
    let (status, body) = resolve(&state, true, &id, deny_body(&stale).to_string()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "scope_changed");
    assert_eq!(body["scope_digest"], json!(digest));

    let (status, body) = resolve(&state, true, &id, deny_body(&digest).to_string()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"], "not_available_yet");
}

#[tokio::test]
async fn the_digest_follows_the_scope_not_the_arrival_order() {
    let (state, log, id, digest, _keep) = one_request().await;
    let now = crate::clock::utc_now().expect("a readable clock");
    write(&log, note("stripe.refunds", now));
    let body = served_when(&state, |body| scope_len(body) == 2).await;
    let after = body["decisions"][0]["scope_digest"]
        .as_str()
        .expect("digest");
    assert_ne!(after, digest, "a wider scope is a new digest");

    let (status, body) = resolve(&state, true, &id, deny_body(&digest).to_string()).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the listed digest is stale: {body}"
    );
    assert_eq!(body["scope"].as_array().map(Vec::len), Some(2), "{body}");
}

#[tokio::test]
async fn two_resolves_do_not_overlap() {
    let (state, _log, id, digest, _keep) = one_request().await;
    let decisions = state.meta_mcp.decisions().expect("decisions");
    let held = decisions.resolving().await;
    let state2 = Arc::clone(&state);
    let body = deny_body(&digest).to_string();
    let pending = tokio::spawn(async move { resolve(&state2, true, &id, body).await });
    // One thread: a yield lets the spawned resolve run until it blocks on the
    // mutex, or finish if nothing stops it. No clock is involved.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(
        !pending.is_finished(),
        "a resolve ran while another held the mutex"
    );
    drop(held);
    let (status, _) = pending.await.expect("joined");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}
