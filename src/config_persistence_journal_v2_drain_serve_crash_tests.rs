// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! WIRE.1 / SERVE.1, crash rows at the serve level: a write a crash left behind (a staged v2
//! journal) is settled by a served start. A start killed during its repair leaves the next served
//! start to finish the job; a start whose delivery fails builds no gateway, and the next one
//! delivers what was owed, each record settling to one distinct outcome.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use super::super::abandoned::{encode_frame, frames_of, marked};
use super::super::{Fact, JournalV2, Phase};
use super::fault::{self, At, Fault};
use super::fixtures::{Live, WRITER, decided, records_at, replace_bytes, staged, state};
use super::startup_tests::expect_staged_owed;
use crate::commands::serve_fixture::serve_load;
use crate::config_persistence::commit::FileRevision;
use crate::config_persistence::journal;
use crate::security::transparency_log::settle::Role;

/// Set in a child test process: the config folder of the served start it runs.
const CHILD_DIR: &str = "MCP_GATEWAY_SERVE_CRASH_DIR";
const CHILD_LIMIT: Duration = Duration::from_secs(60);

/// Config bytes that name the fixture's audit log, so a served start opens that log. The one
/// backend lets a row see whether a start got as far as registering backends.
fn served_bytes(port: u16, log: &Path) -> Vec<u8> {
    format!(
        "server:\n  port: {port}\nbackends:\n  probe:\n    http_url: \"http://127.0.0.1:9/mcp\"\nsecurity:\n  transparency_log:\n    enabled: true\n    path: \"{}\"\n    key_id: s6a2-fixture\n",
        log.display()
    )
    .into_bytes()
}

/// What a crashed write leaves: the new bytes in place, the original staged beside them, and a
/// staged journal bound to the fixture's log. Returns the original bytes and the paths a served
/// start needs; the fixture's own logger is closed, so a served start can open the log.
struct Left {
    dir: Arc<tempfile::TempDir>,
    resolved: PathBuf,
    path: PathBuf,
    log_path: PathBuf,
    original: Vec<u8>,
}

fn crashed_write(row: &str) -> Left {
    let live = Live::new();
    let original = served_bytes(1, &live.log_path);
    let edited = served_bytes(2, &live.log_path);
    let mut journal = state(&live.resolved);
    staged(&mut journal);
    journal.original_revision = Some(FileRevision::of(&original));
    journal.new_revision = Some(FileRevision::of(&edited));
    journal.fact = Some(Fact::Committed(FileRevision::of(&edited)));
    replace_bytes(&live.path, &edited);
    drop(live.seed(journal, row));
    // The fixture stages its own original bytes; this row's original names the log.
    replace_bytes(&journal::original_path(&live.path), &original);
    let left = Left {
        dir: Arc::clone(&live.dir),
        resolved: live.resolved.clone(),
        path: live.path.clone(),
        log_path: live.log_path.clone(),
        original,
    };
    drop(live);
    left
}

/// A served start, load then build, in this process.
async fn serve_start(row: &str, config: &Path) -> crate::Result<crate::gateway::Gateway> {
    let mut evaluated = serve_load(row, config).await;
    let env = Arc::new(evaluated.live_env());
    crate::gateway::Gateway::new_evaluated(evaluated.config, env, Some(config.to_path_buf())).await
}

/// The distinct outcomes the log holds for `token`. A resend after a cut between an append and
/// its flag repeats an equal record, which collapses here, as `converged` counts it
/// (`crash_f1_terminal`); a second distinct outcome would be a terminal settled twice.
fn outcomes_for(records: &[Value], token: &str) -> usize {
    records
        .iter()
        .filter(|record| record["token"] == token && record["event"] == "config_write_outcome")
        .map(|record| {
            ["result", "reason", "settled_by", "intent_counter"].map(|key| record[key].to_string())
        })
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

/// The recovery attempt a killed start persisted in the journal.
fn persisted_recovery_token(path: &Path, row: &str) -> String {
    let bytes = std::fs::read(journal::journal_path(path))
        .unwrap_or_else(|error| panic!("{row}: the journal survives the kill: {error}"));
    let journal =
        JournalV2::decode(&bytes).unwrap_or_else(|_| panic!("{row}: the journal decodes"));
    journal
        .attempts
        .iter()
        .find(|attempt| attempt.intent.role == Role::RecoveryIntent)
        .map_or_else(
            || panic!("{row}: the killed start persisted a recovery attempt"),
            |attempt| attempt.intent_id.0.clone(),
        )
}

/// Runs the child half of `row` against the config folder `resolved` and returns its status.
async fn run_child(row: &str, resolved: &Path) -> std::process::ExitStatus {
    let filter = format!("config_persistence::journal::v2::drain::serve_crash_tests::{row}_child");
    let fixture_root = resolved.parent().expect("the fixture root");
    let mut child = tokio::process::Command::from(crate::test_home::test_binary());
    child
        .args(["--exact", &filter, "--nocapture"])
        .env(CHILD_DIR, resolved)
        .env(
            "MCP_GATEWAY_TEST_KEPT_DIRS",
            std::env::join_paths([fixture_root]).expect("a joinable path"),
        )
        .kill_on_drop(true);
    tokio::time::timeout(CHILD_LIMIT, child.status())
        .await
        .unwrap_or_else(|_| panic!("{row}: the child finished within {CHILD_LIMIT:?}"))
        .expect("run the child")
}

/// `crash_s1`: a served start is killed after its repair step has persisted the recovery attempt
/// and before the restore. The next served start restores the original, keeps the attempt the
/// killed start chose, and delivers every owed record once.
#[tokio::test(flavor = "multi_thread")]
async fn crash_s1() {
    use std::os::unix::process::ExitStatusExt as _;
    const ROW: &str = "crash_s1";
    let left = crashed_write(ROW);
    let status = run_child(ROW, &left.resolved).await;
    assert_eq!(
        status.signal(),
        Some(6),
        "{ROW}: the served start was killed at its repair step, got {status}"
    );
    let token = persisted_recovery_token(&left.path, ROW);

    let gateway = Box::pin(serve_start(ROW, &left.path))
        .await
        .unwrap_or_else(|error| panic!("{ROW}: the next served start builds: {error}"));
    drop(gateway);
    assert_eq!(
        std::fs::read(&left.path).expect("config bytes"),
        left.original,
        "{ROW}: the config is the original"
    );
    assert!(
        !journal::journal_path(&left.path).exists() && !journal::original_path(&left.path).exists(),
        "{ROW}: the journal and the staged original are gone once settled"
    );
    expect_staged_owed(&records_at(&left.log_path), &token, ROW);
    drop(left.dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn crash_s1_child() {
    let Some(resolved) = std::env::var_os(CHILD_DIR) else {
        return;
    };
    let path = PathBuf::from(resolved).join("gateway.yaml");
    let _armed = fault::arm(&path, Fault::Kill(At::RepairPaused));
    // With the startup gate the kill fires inside this load; without it the load just returns.
    let _ = crate::commands::load_for_serve(Some(&path)).await;
}

/// `crash_s2`: a served start is killed after it opened the serving log and before it settled the
/// session. The next served start settles with the same log: the config is the original, and the
/// attempt the killed start chose is settled once, with no duplicate record.
#[tokio::test(flavor = "multi_thread")]
async fn crash_s2() {
    use std::os::unix::process::ExitStatusExt as _;
    const ROW: &str = "crash_s2";
    let left = crashed_write(ROW);
    let status = run_child(ROW, &left.resolved).await;
    assert_eq!(
        status.signal(),
        Some(6),
        "{ROW}: the served start was killed after opening its log, got {status}"
    );
    let token = persisted_recovery_token(&left.path, ROW);
    let gateway = Box::pin(serve_start(ROW, &left.path))
        .await
        .unwrap_or_else(|error| panic!("{ROW}: the next served start builds: {error}"));
    drop(gateway);
    assert_eq!(
        std::fs::read(&left.path).expect("config bytes"),
        left.original,
        "{ROW}: the config is the original"
    );
    expect_staged_owed(&records_at(&left.log_path), &token, ROW);
    drop(left.dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn crash_s2_child() {
    use crate::config_reload::serve_seams::{self, Point};
    let Some(resolved) = std::env::var_os(CHILD_DIR) else {
        return;
    };
    let path = PathBuf::from(resolved).join("gateway.yaml");
    let _armed = serve_seams::arm(&path, Point::AfterServingOpen, || {
        std::process::abort();
    });
    let _ = Box::pin(serve_start("crash_s2_child", &path)).await;
}

/// `crash_s3`: delivery fails at a boundary while a served gateway is built. No gateway is
/// built, and the next served start delivers what was owed. Counted as distinct outcomes, not
/// records: a cut between an append and its flag resends an equal record, which collapses.
#[tokio::test(flavor = "multi_thread")]
async fn crash_s3() {
    const ROW: &str = "crash_s3";
    for at in [At::IntentAppended, At::OutcomeAppended] {
        let left = crashed_write(ROW);
        // Counted on this thread, which runs both starts' construction.
        let (counting, registered) = crate::test_log_capture::live_count("Registered backend");
        let armed = fault::arm(&left.path, Fault::Fail(at));
        let built = Box::pin(serve_start(ROW, &left.path)).await;
        let before_refusal = *registered.borrow();
        let fired = fault::fired(&left.path);
        drop(armed);
        assert!(fired > 0, "{ROW} {at:?}: the delivery reached the boundary");
        assert!(
            built.is_err(),
            "{ROW} {at:?}: a failed delivery builds no gateway"
        );
        assert_eq!(
            before_refusal, 0,
            "{ROW} {at:?}: no backend registers before the start has settled"
        );
        drop(built);

        let gateway = Box::pin(serve_start(ROW, &left.path))
            .await
            .unwrap_or_else(|error| panic!("{ROW} {at:?}: the next served start builds: {error}"));
        drop(gateway);
        assert_eq!(
            *registered.borrow(),
            1,
            "{ROW} {at:?}: the count sees the next start register its one backend"
        );
        drop(counting);
        let records = records_at(&left.log_path);
        assert_eq!(
            outcomes_for(&records, WRITER),
            1,
            "{ROW} {at:?}: the writer settled to one distinct outcome"
        );
        let attempts = records
            .iter()
            .filter(|record| record["event"] == "config_recovery_intent")
            .filter_map(|record| record["token"].as_str())
            .collect::<std::collections::BTreeSet<_>>();
        for token in &attempts {
            assert_eq!(
                outcomes_for(&records, token),
                1,
                "{ROW} {at:?}: recovery attempt {token} settled to one distinct outcome"
            );
        }
        assert!(
            !journal::journal_path(&left.path).exists(),
            "{ROW} {at:?}: the journal is gone once settled"
        );
        drop(left.dir);
    }
}

/// WIRE.4 / Q2 on a well-formed abandoned file, which the drain reads all the way to the point
/// where it needs a logger. Logging off: the start keeps the file for later and serves. Logging
/// on but its open failed: the start refuses. Neither start touches the file.
#[tokio::test]
async fn a_failed_serving_log_refuses_a_readable_abandoned_file() {
    use crate::commands::serve_fixture::{ABANDONED_CLASS, failed_log_config};
    use crate::gateway::test_helpers::write_owner_only;
    const ROW: &str = "a_failed_serving_log_refuses_a_readable_abandoned_file";
    for open_failed in [false, true] {
        let scratch = crate::test_dir_keep::kept_tempdir();
        let root = scratch.path().canonicalize().expect("canonical root");
        let mut donor = state(&root);
        decided(&mut donor);
        staged(&mut donor);
        donor.phase = Phase::Accepted;
        let frames = frames_of(&marked(&donor)).expect("a bound donor yields frames");
        let wire: Vec<u8> = frames
            .iter()
            .flat_map(|frame| encode_frame(frame).expect("encodable"))
            .collect();
        let config = root.join("gateway.yaml");
        let yaml = if open_failed {
            failed_log_config(&root)
        } else {
            String::from("auth:\n  enabled: false\n")
        };
        write_owner_only(&config, yaml).expect("write the config");
        let left_behind = journal::v2::abandoned_path(&config);
        write_owner_only(&left_behind, &wire).expect("plant the abandoned file");

        let outcome = Box::pin(serve_start(ROW, &config)).await;
        if open_failed {
            let refusal = outcome
                .err()
                .unwrap_or_else(|| panic!("{ROW}: with its log unopened the start must refuse"));
            assert!(
                refusal.to_string().contains(ABANDONED_CLASS),
                "{ROW}: refused for the pending file, not for something else: {refusal}"
            );
        } else {
            let gateway = outcome.unwrap_or_else(|error| {
                panic!("{ROW}: with logging off the start serves: {error}")
            });
            drop(gateway);
        }
        assert_eq!(
            std::fs::read(&left_behind).expect("the planted file is still there"),
            wire,
            "{ROW} open_failed={open_failed}: the planted file is byte-identical"
        );
    }
}
