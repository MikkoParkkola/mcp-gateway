// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The live stream's activity and config kinds, through the real router,
//! over real transparency loggers in a temporary directory.

use super::*;
use crate::security::TransparencyLogger;
use crate::security::transparency_log::TransparencyLogConfig;

const SCOPED_ADMIN: &str = "u3-scoped-admin-key";

fn logger(dir: &tempfile::TempDir, name: &str) -> Arc<TransparencyLogger> {
    let config = TransparencyLogConfig {
        enabled: true,
        path: dir.path().join(name).to_string_lossy().into_owned(),
        ..TransparencyLogConfig::default()
    };
    Arc::new(TransparencyLogger::open(Arc::new(config)).expect("the logger opens"))
}

fn scoped_admin(backends: &[&str]) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(SCOPED_ADMIN.as_bytes())),
        name: SCOPED_ADMIN.to_string(),
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        admin: true,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

/// The bearer, the standard key, and the scoped admin key over `backends`.
fn auth(backends: &[&str]) -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_string()),
        api_keys: vec![standard_key(), scoped_admin(backends)],
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    }
}

/// A gateway writing both logs (`governance` false: no governance log), with
/// the bearer, the standard key and a scoped admin key over `a` and `b`.
async fn logged(governance: bool) -> (Arc<AppState>, impl Sized, Arc<TransparencyLogger>) {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let inv = logger(&dir, "invocation.jsonl");
    let gov = governance.then(|| logger(&dir, "governance.jsonl"));
    let auth = auth(&["a", "b"]);
    let (state, fixture_dir) = super::super::tests::meta_fixture::test_router_app_state_with_logs(
        &auth,
        Some(Arc::clone(&inv)),
        gov,
    )
    .await;
    (state, (fixture_dir, dir), inv)
}

/// A wait that fails the row instead of hanging it: a stream that never
/// sends the frame (a mutant, a regression) is a red row within this bound.
async fn within<T>(wait: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), wait)
        .await
        .expect("the frame arrives in time")
}

fn call(log: &TransparencyLogger, server: &str, n: usize) {
    log.log_invocation(
        "s",
        "c",
        server,
        &format!("tool_{n}"),
        "sha256:aa",
        "sha256:bb",
    )
    .expect("the call is logged");
}

/// A real governance change, one `kind_of` delivers to a full admin: the
/// config event every config row is checked against.
fn config_change(state: &AppState) {
    state
        .governance_log
        .as_ref()
        .unwrap()
        .append_event(
            serde_json::json!({"kind": "control_plane_audit", "actor_id": "alice",
                               "target_id": "backend:alpha", "action": "mutate_grant"})
            .as_object()
            .cloned()
            .unwrap(),
            &crate::security::audit::AuditEnvelope::gateway(),
        )
        .unwrap();
}

#[tokio::test]
async fn s1a_an_admin_activity_stream_gets_a_call_made_after_it_opened() {
    let (state, _dirs, inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let hello = within(s.until("hello")).await;
    assert_eq!(
        hello.json()["kinds"],
        serde_json::json!(["status", "reload", "activity", "config"])
    );
    call(&inv, "srv", 1);
    let event = within(s.until("activity")).await;
    assert!(event.json().is_object(), "the row: {}", event.data);
    assert!(event.part('i').is_some(), "the id carries the log position");
}

#[tokio::test]
async fn s1c_a_reconnect_with_its_id_resumes_with_no_gap_and_no_repeat() {
    let (state, _dirs, inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    within(s.until("hello")).await;
    for n in 1..=3 {
        call(&inv, "srv", n);
    }
    within(s.until("activity")).await;
    let second = within(s.until("activity")).await;
    drop(s);
    let id = second.id.expect("an activity frame carries an id");
    call(&inv, "srv", 4);
    let mut again = open(&state, request(STREAM, Who::Bearer(BEARER), Some(&id))).await;
    within(again.until("hello")).await;
    let counter = |f: &Frame| {
        f.part('i')
            .and_then(|p| p.split('-').next()?.parse::<u64>().ok())
    };
    let before = counter(&Frame {
        id: Some(id.clone()),
        ..parse("")
    })
    .unwrap();
    let next = counter(&within(again.until("activity")).await).unwrap();
    let last = counter(&within(again.until("activity")).await).unwrap();
    assert_eq!(
        (next, last),
        (before + 1, before + 2),
        "the third and fourth calls, once each"
    );
}

#[tokio::test]
async fn s3_a_scoped_admin_gets_activity_and_never_config() {
    let (state, _dirs, inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(SCOPED_ADMIN), None)).await;
    let hello = within(s.until("hello")).await;
    assert_eq!(
        hello.json()["kinds"],
        serde_json::json!(["status", "reload", "activity"])
    );
    tokio::time::pause();
    config_change(&state);
    call(&inv, "a", 1);
    // Read on to the next keep-alive, past the call's activity row: a config
    // row comes from its own log, so it could arrive after that row.
    let mut activity = 0;
    within(async {
        loop {
            let f = s.next().await.expect("the stream is still open");
            assert_ne!(f.event, "config", "a scoped key never gets a config row");
            activity += usize::from(f.event == "activity");
            if f.event == "comment" && activity > 0 {
                break;
            }
        }
    })
    .await;
}

#[tokio::test]
async fn a1d_a_narrowed_backend_list_ends_the_stream_with_its_kinds_unchanged() {
    let (state, _dirs, _inv) = logged(true).await;
    tokio::time::pause();
    let mut s = open(&state, request(STREAM, Who::Bearer(SCOPED_ADMIN), None)).await;
    within(s.until("hello")).await;
    // A reload that narrows the scoped key: a whole new auth section, so the
    // generation builds a new key table, as a reload of the file does.
    state.live_config.edit(|c| c.auth = auth(&["a"]));
    // The premise, so a setup that narrows nothing fails here, loudly, and not
    // as a stream that never ends.
    let published = state.live_config.get();
    let key = published
        .auth
        .api_keys
        .iter()
        .find(|k| k.name == SCOPED_ADMIN)
        .expect("the reload publishes the scoped key");
    assert_eq!(key.backends, vec!["a".to_string()], "the key is narrowed");
    assert!(
        s.ended_within(REVOKED_WITHIN).await,
        "the narrowed access ended the stream"
    );
}

#[tokio::test]
async fn a1f_a_status_only_caller_keeps_its_stream_across_rechecks() {
    let (state, _dirs, _inv) = logged(true).await;
    tokio::time::pause();
    let mut s = open(&state, request(STREAM, Who::Bearer(KEY), None)).await;
    assert_eq!(
        within(s.until("hello")).await.json()["kinds"],
        serde_json::json!(["status"])
    );
    // Past several one-second rechecks, to the first keep-alive.
    let comment = within(s.until("comment")).await;
    assert_eq!(comment.event, "comment", "the stream is still open");
}

#[tokio::test]
async fn f13_no_frame_or_id_carries_a_search_segment_or_offset() {
    let (state, _dirs, inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let hello = within(s.until("hello")).await;
    call(&inv, "srv", 1);
    let event = within(s.until("activity")).await;
    for text in [
        hello.data.as_str(),
        event.data.as_str(),
        event.id.as_deref().unwrap_or(""),
    ] {
        for word in ["segment", "offset", "\"at\"", "restarts"] {
            assert!(!text.contains(word), "{word} in {text}");
        }
    }
}

#[tokio::test]
async fn startup_attaches_each_reader_once_per_process() {
    let (state, _dirs, _inv) = logged(true).await;
    // The fixture attached both, as server start does; a second call attaches
    // nothing, so a record is never announced twice.
    assert_eq!(
        state.dashboard_bootstrap.stream_hub().attach_logs(
            state.transparency_log.as_deref(),
            state.governance_log.as_deref(),
        ),
        0
    );
}

#[tokio::test]
async fn a_gateway_with_no_governance_log_serves_activity_without_config() {
    let (state, _dirs, inv) = logged(false).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    assert_eq!(
        within(s.until("hello")).await.json()["kinds"],
        serde_json::json!(["status", "reload", "activity"])
    );
    call(&inv, "srv", 1);
    assert!(within(s.until("activity")).await.json().is_object());
}

/// The counter an activity frame's id carries for the invocation log.
fn inv_counter(f: &Frame) -> u64 {
    f.part('i')
        .and_then(|p| p.split('-').next()?.parse().ok())
        .expect("the id carries the invocation position")
}

#[tokio::test]
async fn a1e_a_stream_whose_key_is_removed_ends_at_the_next_check() {
    let (state, _dirs, _inv) = logged(true).await;
    tokio::time::pause();
    let mut s = open(&state, request(STREAM, Who::Bearer(SCOPED_ADMIN), None)).await;
    within(s.until("hello")).await;
    state.live_config.edit(|c| {
        c.auth = AuthConfig {
            api_keys: vec![standard_key()],
            ..auth(&["a"])
        };
    });
    let published = state.live_config.get();
    assert!(
        published
            .auth
            .api_keys
            .iter()
            .all(|k| k.name != SCOPED_ADMIN),
        "the premise: the key is gone from the published config"
    );
    assert!(
        s.ended_within(REVOKED_WITHIN).await,
        "no caller ends the stream"
    );
}

#[tokio::test]
async fn r1_a_gone_cursor_resets_then_replays_the_log_from_its_oldest_record() {
    let (state, _dirs, inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    within(s.until("hello")).await;
    for n in 1..=3 {
        call(&inv, "srv", n);
    }
    let first = within(s.until("activity")).await;
    let id = first.id.clone().unwrap();
    drop(s);
    // The same counter with a hash no record has: the cursor's row is gone.
    let counter = inv_counter(&first);
    let wrong_id = id.replace(
        &first.part('i').unwrap(),
        &format!("{counter}-ffffffffffffffff"),
    );
    let mut again = open(
        &state,
        request(STREAM, Who::Bearer(BEARER), Some(&wrong_id)),
    )
    .await;
    within(again.until("hello")).await;
    let reset = within(again.until("reset")).await;
    assert_eq!(reset.json()["kind"], "activity");
    let mut seen = Vec::new();
    for _ in 0..3 {
        seen.push(inv_counter(&within(again.until("activity")).await));
    }
    assert!(
        seen.windows(2).all(|w| w[0] < w[1]) && seen.contains(&counter),
        "the replay from the oldest record holds the gone cursor's call: {seen:?}"
    );
}

#[tokio::test]
async fn r1b_a_reconnect_with_the_reset_frames_id_still_gets_the_replay() {
    let (state, _dirs, inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    within(s.until("hello")).await;
    for n in 1..=3 {
        call(&inv, "srv", n);
    }
    let first = within(s.until("activity")).await;
    let id = first.id.clone().unwrap();
    drop(s);
    let counter = inv_counter(&first);
    let wrong_id = id.replace(
        &first.part('i').unwrap(),
        &format!("{counter}-ffffffffffffffff"),
    );
    let mut reset_by = open(
        &state,
        request(STREAM, Who::Bearer(BEARER), Some(&wrong_id)),
    )
    .await;
    within(reset_by.until("hello")).await;
    // The client drops right after the reset frame, before any replayed row,
    // and reconnects with the id that frame carried.
    let reset = within(reset_by.until("reset")).await;
    drop(reset_by);
    let reset_id = reset.id.expect("a reset frame carries an id");
    let mut again = open(
        &state,
        request(STREAM, Who::Bearer(BEARER), Some(&reset_id)),
    )
    .await;
    within(again.until("hello")).await;
    call(&inv, "srv", 4);
    // Read up to the call made after the reconnect. Tool names, not
    // counters: the log's counters also count its segment-opened record.
    let mut seen: Vec<String> = Vec::new();
    while seen.last().map(String::as_str) != Some("tool_4") {
        seen.extend(tools(&mut again, 1).await);
    }
    assert_eq!(
        seen,
        ["tool_1", "tool_2", "tool_3", "tool_4"],
        "the replay the reset announced still comes, from the oldest record"
    );
}

#[tokio::test]
async fn f7_a_config_change_is_a_config_event_and_never_an_activity_one() {
    let (state, _dirs, inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    within(s.until("hello")).await;
    config_change(&state);
    call(&inv, "srv", 1);
    let (mut config, mut activity) = (Vec::new(), Vec::new());
    within(async {
        while config.is_empty() || activity.is_empty() {
            let f = s.next().await.expect("the stream is still open");
            match f.event.as_str() {
                "config" => config.push(f.data),
                "activity" => activity.push(f.data),
                _ => {}
            }
        }
    })
    .await;
    assert!(
        config[0].contains("mutate_grant"),
        "the change is a config event: {config:?}"
    );
    assert!(
        activity.iter().all(|d| !d.contains("mutate_grant")) && activity[0].contains("tool_1"),
        "the call is the activity event, the change never is: {activity:?}"
    );
}

#[tokio::test]
async fn s1d_a_burst_past_the_broadcast_capacity_arrives_exactly_once_in_order() {
    let (state, _dirs, inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    within(s.until("hello")).await;
    // Nothing reads the stream while the burst is written: the appends must
    // still complete, and the stream falls behind its broadcast. Sized from
    // the capacity, so a larger broadcast still leaves this row lagging.
    let burst = crate::gateway::ui::stream::BROADCAST + 76;
    for n in 0..burst {
        call(&inv, "srv", n);
    }
    let mut seen = Vec::with_capacity(burst);
    while seen.len() < burst {
        seen.push(inv_counter(&within(s.until("activity")).await));
    }
    assert!(
        seen.windows(2).all(|w| w[1] == w[0] + 1),
        "every call once, in counter order, across the lag"
    );
}

use crate::gateway::ui::stream::{KEEP_ALIVE, PAGE};

/// A stream reconnected `behind` calls back, on a paused clock, with its
/// catch-up under way: its first catch-up row is read, so the stream is
/// inside its first page with the rest of that page still to send.
async fn catching_up(
    state: &Arc<AppState>,
    inv: &TransparencyLogger,
    who: &str,
    behind: usize,
) -> Open {
    let mut s = open(state, request(STREAM, Who::Bearer(who), None)).await;
    within(s.until("hello")).await;
    call(inv, "a", 0);
    let id = within(s.until("activity")).await.id.expect("an id");
    drop(s);
    for n in 1..=behind {
        call(inv, "a", n);
    }
    tokio::time::pause();
    let mut again = open(state, request(STREAM, Who::Bearer(who), Some(&id))).await;
    within(again.until("hello")).await;
    within(again.until("activity")).await;
    again
}

#[tokio::test]
async fn c1_a_catch_up_still_ends_at_its_lifetime_between_pages() {
    let (state, _dirs, inv) = logged(false).await;
    let behind = 4 * PAGE;
    let mut again = catching_up(&state, &inv, BEARER, behind).await;
    // On to the one-hour lifetime and past it, reading as the clock moves:
    // steps shorter than a stalled write's limit, so only the lifetime can
    // end the stream, and it must do so at a page boundary.
    let mut rows = 1;
    loop {
        tokio::time::advance(Duration::from_secs(10)).await;
        match within(again.next()).await {
            Some(f) => rows += usize::from(f.event == "activity"),
            None => break,
        }
    }
    assert!(
        rows < behind && rows % PAGE == 0,
        "the lifetime ends the catch-up at a page boundary: {rows} of {behind} rows sent"
    );
}

#[tokio::test]
async fn c2_a_catch_up_serves_a_due_keep_alive_before_its_next_page() {
    let (state, _dirs, inv) = logged(false).await;
    let mut again = catching_up(&state, &inv, BEARER, 3 * PAGE).await;
    // A keep-alive and a recheck both fall due inside the first page.
    tokio::time::advance(KEEP_ALIVE + Duration::from_secs(1)).await;
    let mut rows = 1;
    loop {
        let f = within(again.next())
            .await
            .expect("the stream is still open");
        match f.event.as_str() {
            "comment" => break,
            "activity" => rows += 1,
            _ => {}
        }
    }
    assert!(
        rows <= PAGE,
        "the due keep-alive is sent when the first page ends, before the next one: after {rows} rows"
    );
}

#[tokio::test]
async fn f8_a_config_change_is_not_held_back_by_a_run_of_calls() {
    let (state, _dirs, inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    within(s.until("hello")).await;
    // Every one of these is queued before the stream reads any: a run of
    // calls with one config change in the middle.
    for n in 0..50 {
        call(&inv, "srv", n);
    }
    config_change(&state);
    for n in 50..100 {
        call(&inv, "srv", n);
    }
    let mut before = 0;
    within(async {
        loop {
            let f = s.next().await.expect("the stream is still open");
            match f.event.as_str() {
                "config" => break,
                "activity" => before += 1,
                _ => {}
            }
        }
    })
    .await;
    assert!(
        before < 100,
        "the config change arrives among the calls, not after every one of them: {before} calls first"
    );
}

/// The tool names of the next `n` activity rows.
async fn tools(s: &mut Open, n: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let f = within(s.until("activity")).await;
        let tool = f.json()["tool"].as_str().map(str::to_string);
        out.push(tool.unwrap_or_else(|| panic!("an activity row names its tool: {}", f.data)));
    }
    out
}

#[tokio::test]
async fn s3b_a_scoped_admin_gets_only_its_backends_rows_live_and_on_resume() {
    let (state, _dirs, inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(SCOPED_ADMIN), None)).await;
    within(s.until("hello")).await;
    call(&inv, "x", 1);
    call(&inv, "a", 2);
    let first = within(s.until("activity")).await;
    assert!(
        first.data.contains("tool_2") && !first.data.contains("tool_1"),
        "live: the call on a backend outside the key is never sent: {}",
        first.data
    );
    drop(s);
    let id = first.id.expect("an id");
    for (server, n) in [("x", 3), ("b", 4), ("x", 5), ("a", 6)] {
        call(&inv, server, n);
    }
    let mut again = open(
        &state,
        request(STREAM, Who::Bearer(SCOPED_ADMIN), Some(&id)),
    )
    .await;
    within(again.until("hello")).await;
    call(&inv, "x", 7);
    call(&inv, "a", 8);
    assert_eq!(
        tools(&mut again, 3).await,
        ["tool_4", "tool_6", "tool_8"],
        "catch-up and live: only the key's backends, in order"
    );
}

fn gov_counter(f: &Frame) -> u64 {
    f.part('g')
        .and_then(|p| p.split('-').next()?.parse().ok())
        .expect("the id carries the governance position")
}

#[tokio::test]
async fn s1c_config_a_reconnect_resumes_its_config_rows_with_no_gap_and_no_repeat() {
    let (state, _dirs, _inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    within(s.until("hello")).await;
    config_change(&state);
    let seen = within(s.until("config")).await;
    drop(s);
    let before = gov_counter(&seen);
    config_change(&state);
    config_change(&state);
    let id = seen.id.expect("a config frame carries an id");
    let mut again = open(&state, request(STREAM, Who::Bearer(BEARER), Some(&id))).await;
    within(again.until("hello")).await;
    let next = gov_counter(&within(again.until("config")).await);
    let last = gov_counter(&within(again.until("config")).await);
    assert_eq!(
        (next, last),
        (before + 1, before + 2),
        "the second and third changes, once each"
    );
}

#[tokio::test]
async fn s1f_a_fresh_stream_starts_at_the_head_not_the_oldest_record() {
    let (state, _dirs, inv) = logged(true).await;
    call(&inv, "srv", 1);
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    within(s.until("hello")).await;
    call(&inv, "srv", 2);
    assert_eq!(
        tools(&mut s, 1).await,
        ["tool_2"],
        "a call written before the stream opened is not replayed"
    );
}

#[tokio::test]
async fn a1g_a_demotion_during_a_catch_up_sends_no_more_of_its_page() {
    let (state, _dirs, inv) = logged(true).await;
    // Two catch-up pages, every row on a backend the key keeps.
    let mut again = catching_up(&state, &inv, SCOPED_ADMIN, 2 * PAGE).await;
    state.live_config.edit(|c| c.auth = auth(&["a"]));
    let published = state.live_config.get();
    let key = published
        .auth
        .api_keys
        .iter()
        .find(|k| k.name == SCOPED_ADMIN)
        .expect("the reload publishes the scoped key");
    assert_eq!(key.backends, vec!["a".to_string()], "the key is narrowed");
    // The stream holds at most one more frame of the page; every later frame
    // is checked before it is sent.
    let mut after = 0;
    while let Some(f) = within(again.next()).await {
        after += usize::from(f.event == "activity");
    }
    assert!(
        after <= 2,
        "the narrowed access stops the page at its next frame: {after} rows sent after it"
    );
}

#[tokio::test]
async fn l1_a_recheck_slower_than_its_period_does_not_starve_a_live_stream() {
    let (state, _dirs, inv) = logged(false).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    within(s.until("hello")).await;
    tokio::time::pause();
    // Every check takes a second and a half: past the one-second recheck
    // period, inside the two-second deadline, as a slow key server would.
    state
        .dashboard_bootstrap
        .stream_hub()
        .slow_validation_for_test(1_500);
    call(&inv, "srv", 1);
    let frame = within(s.until("activity")).await;
    assert!(
        frame.data.contains("tool_1"),
        "the call arrives though every check is slow: {}",
        frame.data
    );
}

#[tokio::test]
async fn r1c_a_replay_that_shows_nothing_leaves_later_ids_without_the_marker() {
    // Every call is on a backend the scoped key does not have, so the
    // replay after the reset shows this viewer no row.
    let (state, _dirs, inv) = logged(false).await;
    for n in 1..=3 {
        call(&inv, "x", n);
    }
    let mut s = open(&state, request(STREAM, Who::Bearer(SCOPED_ADMIN), None)).await;
    within(s.until("hello")).await;
    let id = within(s.until("status"))
        .await
        .id
        .expect("a status frame carries an id");
    drop(s);
    let head = Frame {
        id: Some(id.clone()),
        ..parse("")
    }
    .part('i')
    .expect("the id carries the invocation position");
    let counter = head.split('-').next().unwrap();
    let wrong_id = id.replace(&head, &format!("{counter}-ffffffffffffffff"));
    let mut again = open(
        &state,
        request(STREAM, Who::Bearer(SCOPED_ADMIN), Some(&wrong_id)),
    )
    .await;
    within(again.until("hello")).await;
    within(again.until("reset")).await;
    // Two status changes: during a catch-up a snapshot is served at most
    // once before the next page, so the second follows the replay's page.
    for name in ["docs-1", "docs-2"] {
        let _ = state
            .backends
            .register(http_backend_at(name, "http://127.0.0.1:9/mcp"));
        within(again.until("status")).await;
    }
    let _ = state
        .backends
        .register(http_backend_at("docs-3", "http://127.0.0.1:9/mcp"));
    let after = within(again.until("status")).await;
    assert_ne!(
        after.part('i').as_deref(),
        Some("0-0000000000000000"),
        "a finished replay is not owed again: {:?}",
        after.id
    );
}

#[tokio::test]
async fn r2_a_gapped_log_reached_by_a_replay_goes_live_across_reconnects() {
    // An invocation log rotating every few KB, with one sealed segment in
    // the middle removed: a replay from the oldest record meets the gap.
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let path = dir.path().join("invocation.jsonl");
    let config = TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        rotation: crate::security::audit_rotation_config::RotationConfig {
            max_segment_bytes: 4096,
            ..Default::default()
        },
        ..TransparencyLogConfig::default()
    };
    let inv = Arc::new(TransparencyLogger::open(Arc::new(config)).expect("the logger opens"));
    let (state, _fixture) = super::super::tests::meta_fixture::test_router_app_state_with_logs(
        &auth(&["a", "b"]),
        Some(Arc::clone(&inv)),
        None,
    )
    .await;
    for n in 1..=60 {
        call(&inv, "srv", n);
    }
    let sealed = crate::security::transparency_log::segments::list_segments(&path).unwrap();
    assert!(
        sealed.len() >= 3,
        "premise: several sealed segments, {}",
        sealed.len()
    );
    std::fs::remove_file(&sealed[1].path).unwrap();
    // A gone cursor: the counter of a kept record with a hash none has.
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    within(s.until("hello")).await;
    call(&inv, "srv", 61);
    let first = within(s.until("activity")).await;
    drop(s);
    let head = first.part('i').unwrap();
    let counter = head.split('-').next().unwrap();
    let mut id = first
        .id
        .unwrap()
        .replace(&head, &format!("{counter}-ffffffffffffffff"));
    // The first connection, then three reconnects with the latest id each
    // was given: every one goes live.
    for (round, n) in (62..=65).enumerate() {
        let mut again = open(&state, request(STREAM, Who::Bearer(BEARER), Some(&id))).await;
        within(again.until("hello")).await;
        call(&inv, "srv", n);
        let want = format!("tool_{n}");
        let live = within(async {
            loop {
                let f = again
                    .next()
                    .await
                    .unwrap_or_else(|| panic!("round {round}: the stream ended before going live"));
                if let Some(next) = f.id.clone() {
                    id = next;
                }
                if f.event == "activity" && f.data.contains(&want) {
                    break f;
                }
            }
        })
        .await;
        assert!(live.data.contains(&want), "round {round}");
    }
}

#[tokio::test]
async fn l2_snapshots_changing_faster_than_a_send_do_not_starve_a_live_stream() {
    let (state, _dirs, inv) = logged(false).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    within(s.until("hello")).await;
    tokio::time::pause();
    // Every check takes 1.5 s, so a snapshot send (two checks) takes about
    // 3 s, and a status change lands every second: a snapshot is always due.
    state
        .dashboard_bootstrap
        .stream_hub()
        .slow_validation_for_test(1_500);
    let churn = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            for i in 0.. {
                let _ = state.backends.register(http_backend_at(
                    &format!("churn-{i}"),
                    "http://127.0.0.1:9/mcp",
                ));
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
    };
    // The premise: the churn reaches the stream as status frames, two of
    // them through the loop (the first comes with hello), so a snapshot can
    // follow a snapshot.
    for _ in 0..3 {
        within(s.until("status")).await;
    }
    call(&inv, "srv", 1);
    let frame = within(s.until("activity")).await;
    churn.abort();
    assert!(
        frame.data.contains("tool_1"),
        "the call arrives though a snapshot is always due: {}",
        frame.data
    );
}
