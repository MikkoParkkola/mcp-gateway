// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The live stream's replay after a reset and its upkeep timers, through the
//! real router: a replay owed across a reconnect, a replay that shows nothing
//! or meets a gap, and checks and snapshots slower than their periods.

use super::*;

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
    inv.keep_test_dir(Arc::clone(&dir));
    let (state, _fixture) =
        crate::gateway::router::tests::meta_fixture::test_router_app_state_with_logs(
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
    // A gone cursor: the counter of a kept record with a hash none has, from
    // the first frame's id (its status), so no catch-up runs before it.
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    within(s.until("hello")).await;
    // The probe's second per row and the rows' bound run on the paused
    // clock, like L2 and L3: no wall-clock wait.
    tokio::time::pause();
    let status = within(s.until("status")).await;
    drop(s);
    let head = status.part('i').unwrap();
    let counter = head.split('-').next().unwrap();
    let mut id = status
        .id
        .unwrap()
        .replace(&head, &format!("{counter}-ffffffffffffffff"));
    // Four reconnects, each with the latest id it was given, all go live.
    // Every catch-up on this log meets the gap (a fresh search starts at the
    // oldest segment), and going live skips the rows up to the head the
    // catch-up captured, which the client reloads after its reset frame; so
    // a row is written each second until one arrives live.
    let mut n = 61;
    for round in 0..4 {
        let mut again = open(&state, request(STREAM, Who::Bearer(BEARER), Some(&id))).await;
        within(again.until("hello")).await;
        let first = n;
        within(async {
            loop {
                call(&inv, "srv", n);
                n += 1;
                let arrived = tokio::time::timeout(Duration::from_secs(1), async {
                    loop {
                        let f = again.next().await.unwrap_or_else(|| {
                            panic!("round {round}: the stream ended before going live")
                        });
                        if let Some(next) = f.id.clone() {
                            id = next;
                        }
                        // A replayed row from before the gap is not live.
                        if f.event == "activity"
                            && (first..n).any(|k| f.data.contains(&format!("tool_{k}")))
                        {
                            return;
                        }
                    }
                })
                .await;
                if arrived.is_ok() {
                    break;
                }
            }
        })
        .await;
    }
}

/// L2 under a wall-clock bound: the row runs on its own thread and
/// runtime, and the test thread waits at most 120 s. A connection loop that
/// spins without yielding (a snapshot debt never paid) starves the paused
/// clock and with it every bound inside the row, so it would hang, not fail;
/// this turns that hang into a red row. The spinning thread is left behind.
#[test]
fn l2_snapshots_changing_faster_than_a_send_do_not_starve_a_live_stream() {
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let row = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the row's runtime builds")
            .block_on(l2_row());
        let _ = done_tx.send(());
    });
    match done_rx.recv_timeout(Duration::from_secs(120)) {
        Ok(()) => row.join().expect("the row's thread ends"),
        // The row panicked: its own failure, not the bound's.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            std::panic::resume_unwind(row.join().expect_err("the row panicked"))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("L2 did not end within 120 s of wall time: the stream starved its runtime")
        }
    }
}

async fn l2_row() {
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
            for i in 0..10_000 {
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

#[tokio::test]
async fn l3_a_key_removed_under_load_gets_no_row_made_after_the_removal() {
    let (state, _dirs, inv) = logged(false).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(SCOPED_ADMIN), None)).await;
    within(s.until("hello")).await;
    tokio::time::pause();
    // L2's load: every check 1.5 s, a status change every second.
    state
        .dashboard_bootstrap
        .stream_hub()
        .slow_validation_for_test(1_500);
    let churn = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            for i in 0..10_000 {
                let _ = state.backends.register(http_backend_at(
                    &format!("churn-{i}"),
                    "http://127.0.0.1:9/mcp",
                ));
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
    };
    call(&inv, "a", 1);
    let first = within(s.until("activity")).await;
    assert!(first.data.contains("tool_1"), "premise: live under load");
    state.live_config.edit(|c| {
        c.auth = AuthConfig {
            api_keys: vec![standard_key()],
            ..auth(&["a"])
        };
    });
    // Calls keep coming after the removal: none may reach the removed key.
    let writer = {
        let inv = Arc::clone(&inv);
        tokio::spawn(async move {
            for n in 2..10_000 {
                call(&inv, "a", n);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
    };
    let mut after = Vec::new();
    within(async {
        while let Some(f) = s.next().await {
            if f.event == "activity" {
                after.push(f.data);
            }
        }
    })
    .await;
    churn.abort();
    writer.abort();
    assert!(
        after.is_empty(),
        "no row made after the removal reaches the removed key: {after:?}"
    );
}
