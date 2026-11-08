// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The health history through a real start: `Gateway::run` saves health.json
//! and counters.json before it serves, records a clean stop at shutdown, and
//! starts and serves even when neither file can be written. A file that does
//! not decode is moved aside, never overwritten.

use std::time::Duration;

use super::super::Gateway;
use crate::config::{AuthConfig, Config};

const TOKEN: &str = "health-start-token";

fn config(dir: &std::path::Path) -> Config {
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = 0;
    config.tasks.store_dir = dir.join("tasks").to_string_lossy().into_owned();
    // Each test's own audit log: the default one in the home directory takes
    // a one-process lease, so two of these starts at once refuse each other.
    config.security.transparency_log.path = dir.join("audit.jsonl").to_string_lossy().into_owned();
    config.auth = AuthConfig {
        enabled: true,
        bearer_token: Some(TOKEN.to_string()),
        ..AuthConfig::default()
    };
    config
}

/// Start a gateway with data dir `data`, run `at_bound` once it listens (the
/// files it finds were written before anything was served), then shut it down.
async fn run_once(tasks: &std::path::Path, data: &std::path::Path, at_bound: impl FnOnce(u16)) {
    let mut gateway = Gateway::new(config(tasks))
        .await
        .expect("gateway builds")
        .with_data_dir(data.to_path_buf());
    let bound = gateway.bound_port_for_test();
    let trigger = gateway.shutdown_trigger_for_test();
    let server = tokio::spawn(async move { Box::pin(gateway.run()).await });
    let Ok(port) = tokio::time::timeout(Duration::from_secs(60), bound)
        .await
        .expect("binds within a minute")
    else {
        panic!("the start ended before it bound: {:?}", server.await);
    };
    at_bound(port);
    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/ui/api/gateway"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .expect("answered");
    assert_eq!(response.status(), 200, "the gateway serves");
    trigger.send(()).expect("run holds the trigger");
    let ended = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("run returns")
        .expect("no panic");
    assert!(ended.is_ok(), "{ended:?}");
}

/// H12, H17: health.json and counters.json are both on disk once the gateway
/// listens, before any request (counters.json otherwise waits five minutes);
/// the shutdown records a clean stop, so the next start's restart is measured.
#[tokio::test]
async fn h12_both_files_are_saved_before_serving_and_the_stop_is_clean() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let data = dir.path().join("data");
    Box::pin(run_once(dir.path(), &data, |_| {
        assert!(
            data.join("health.json").exists(),
            "health.json before serving"
        );
        assert!(
            data.join("counters.json").exists(),
            "counters.json before serving"
        );
    }))
    .await;
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(data.join("health.json")).expect("saved"))
            .expect("json");
    assert!(saved["clean_stop"].is_u64(), "{saved}");
}

/// H10b: a health.json that does not decode is moved aside with its bytes
/// intact (as counters.json is), and the start writes a fresh one.
#[tokio::test]
async fn h10b_an_undecodable_history_is_moved_aside_not_overwritten() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    std::fs::write(data.join("health.json"), b"not json").expect("seed");
    Box::pin(run_once(dir.path(), &data, |_| {})).await;
    let aside: Vec<_> = std::fs::read_dir(&data)
        .expect("listed")
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("health.json.unreadable-")
        })
        .collect();
    assert_eq!(aside.len(), 1, "one aside file: {aside:?}");
    assert_eq!(std::fs::read(aside[0].path()).expect("aside"), b"not json");
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(data.join("health.json")).expect("saved"))
            .expect("the new file decodes");
    assert!(saved["clean_stop"].is_u64(), "{saved}");
}

/// H17: neither health.json nor counters.json can be written (the data dir,
/// set up by a first start, is read-only), and the gateway still starts and
/// serves. A data dir that cannot be created at all is not this row: the
/// record key in it is required, and its absence refuses the start.
#[cfg(unix)]
#[tokio::test]
async fn h17_unwritable_history_never_stops_the_start() {
    use std::os::unix::fs::PermissionsExt;
    let dir = crate::test_dir_keep::kept_tempdir();
    let data = dir.path().join("data");
    Box::pin(run_once(dir.path(), &data, |_| {})).await;
    for name in ["health.json", "counters.json"] {
        std::fs::remove_file(data.join(name)).expect("saved by the first start");
    }
    let mode = |m| std::fs::set_permissions(&data, std::fs::Permissions::from_mode(m));
    mode(0o555).expect("read-only");
    let probe = std::fs::write(data.join("probe"), b"x");
    // Its own audit log: the first start's lease on the shared one can still
    // be held when this start begins.
    let second = dir.path().join("second");
    std::fs::create_dir_all(&second).expect("second dir");
    Box::pin(run_once(&second, &data, |_| {})).await;
    mode(0o755).expect("writable again");
    assert!(
        probe.is_err(),
        "the data dir must refuse writes for this row"
    );
    assert!(!data.join("health.json").exists());
    assert!(!data.join("counters.json").exists());
}

/// H10c (code review r1): when an undecodable health.json cannot be moved
/// aside (its data dir is read-only), the run never saves over it: the
/// original bytes are there after the shutdown save.
#[cfg(unix)]
#[tokio::test]
async fn h10c_a_failed_move_aside_keeps_the_original_bytes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = crate::test_dir_keep::kept_tempdir();
    let data = dir.path().join("data");
    Box::pin(run_once(dir.path(), &data, |_| {})).await;
    std::fs::write(data.join("health.json"), b"not json").expect("seed");
    let mode = |m| std::fs::set_permissions(&data, std::fs::Permissions::from_mode(m));
    mode(0o555).expect("read-only");
    let probe = std::fs::write(data.join("probe"), b"x");
    let second = dir.path().join("second");
    std::fs::create_dir_all(&second).expect("second dir");
    Box::pin(run_once(&second, &data, |_| {})).await;
    mode(0o755).expect("writable again");
    assert!(
        probe.is_err(),
        "the data dir must refuse writes for this row"
    );
    assert_eq!(
        std::fs::read(data.join("health.json")).expect("still there"),
        b"not json"
    );
}

/// H10d (mutant failed-aside-still-saves survived H10c, whose read-only dir
/// also fails every save): when the move aside fails, this run saves
/// nowhere and its history is incomplete; when it succeeds, it saves.
#[test]
fn h10d_a_failed_move_aside_turns_saves_off() {
    use super::super::health_wiring::save_path;
    let fresh = || {
        crate::health_history::HealthHistory::start(
            None,
            crate::health_history::Restores::Counted(1),
            1_800_000_000,
        )
        .0
    };
    let path = std::path::PathBuf::from("health.json");
    // Each case on a fresh history; the move aside sees this path and instant.
    let history = fresh();
    let refused = save_path(true, path.clone(), 7, &history, |p, at| {
        assert_eq!((p, at), (std::path::Path::new("health.json"), 7));
        Err(std::io::Error::other("refused"))
    });
    assert_eq!(refused, None);
    assert!(history.incomplete());
    let history = fresh();
    let moved = save_path(true, path.clone(), 7, &history, |p, at| {
        assert_eq!((p, at), (std::path::Path::new("health.json"), 7));
        Ok(p.with_extension("aside"))
    });
    assert_eq!(moved, Some(path.clone()));
    assert!(!history.incomplete());
    let history = fresh();
    assert_eq!(
        save_path(false, path.clone(), 7, &history, |_, _| unreachable!()),
        Some(path)
    );
    assert!(!history.incomplete());
}
