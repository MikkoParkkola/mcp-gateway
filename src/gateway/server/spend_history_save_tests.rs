// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's side of `spend-history.json`: the cost save writes it in
//! the `COST_WRITE` turn, always owner-only, and the start restores it
//! whether or not cost governance is on.

use std::path::Path;
use std::sync::PoisonError;

use super::tests::enforcer_with_spend;
use super::{COST_WRITE, save_costs, save_costs_unless_busy};
use crate::cost_accounting::CostTracker;
use crate::cost_accounting::spend_history::{self, FILE_NAME};

/// A tracker holding one dated call by key `k`.
fn spent() -> CostTracker {
    let tracker = CostTracker::new();
    tracker.record("", Some("k"), "srv", "t", 3, 1.0);
    tracker
}

/// Whether costs.json and the history exist in `dir`.
fn files(dir: &Path) -> (bool, bool) {
    (
        dir.join("costs.json").exists(),
        dir.join(FILE_NAME).exists(),
    )
}

/// S7: the history is written in the costs.json turn. A periodic save that
/// finds the turn taken writes neither file; once it is free, a save writes
/// both. Mutant: the history written outside the turn.
#[test]
fn a_skipped_periodic_save_writes_neither_file() {
    crate::test_day::same_utc_day(|| {
        let dir = tempfile::tempdir().expect("dir");
        let (enforcer, tracker) = (enforcer_with_spend(0.25), spent());
        let turn = COST_WRITE.lock().unwrap_or_else(PoisonError::into_inner);
        let skipped = !save_costs_unless_busy(&enforcer, &tracker, dir.path());
        drop(turn);
        assert!(skipped, "the save ran while the turn was taken");
        assert_eq!(files(dir.path()), (false, false), "a skipped save wrote");
        // Other tests take the same process-wide turn; wait each out.
        let wrote = (0..100).any(|_| {
            let free = COST_WRITE.lock().unwrap_or_else(PoisonError::into_inner);
            drop(free);
            save_costs_unless_busy(&enforcer, &tracker, dir.path())
        });
        assert!(wrote, "no free turn in 100 tries");
        assert_eq!(files(dir.path()), (true, true), "the next save wrote both");
    });
}

/// The final and checkpoint saves write the history too.
#[test]
fn the_blocking_save_writes_the_history_beside_costs_json() {
    crate::test_day::same_utc_day(|| {
        let dir = tempfile::tempdir().expect("dir");
        assert!(save_costs(&enforcer_with_spend(0.25), &spent(), dir.path()));
        let bytes = std::fs::read(dir.path().join(FILE_NAME)).expect("the history");
        let file: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(file["keys"][0]["name"], "k");
    });
}

#[cfg(unix)]
mod modes {
    const CASE: &str = "MCP_GW_TEST_SPEND_HISTORY_MODE_CASE";
    const CHILD: &str =
        "gateway::server::persistence::spend_history_save_tests::modes::mode_case_in_a_child";

    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::{FILE_NAME, spend_history, spent};

    /// Permission bits of `path` itself, never of a link's target.
    fn bits(path: &std::path::Path) -> u32 {
        let meta = std::fs::symlink_metadata(path).expect("metadata");
        meta.permissions().mode() & 0o777
    }

    /// The case `case`, rerun as its own process with umask 022. The umask
    /// belongs to the process, and a stricter host default (077) would make a
    /// default-mode file look private.
    fn under_umask_022(case: &str) {
        let binary = std::env::current_exe().expect("the test binary");
        let mut command = std::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("umask 022 && exec \"$0\" \"$@\"")
            .arg(&binary);
        command.args(["--exact", CHILD, "--ignored", "--nocapture"]);
        command.envs(crate::test_home::child_env()).env(CASE, case);
        let run = command.output().expect("the child starts");
        let printed = String::from_utf8_lossy(&run.stdout);
        let errors = String::from_utf8_lossy(&run.stderr);
        assert!(run.status.success(), "{case}:\n{printed}\n{errors}");
        // The child prints this only once its checks pass: a child that
        // matched no case fails here.
        assert!(
            printed.contains(&format!("{case} passed in the child")),
            "{case}: nothing ran"
        );
    }

    #[test]
    #[ignore = "started by the rows below as a child under umask 022"]
    fn mode_case_in_a_child() {
        let Ok(case) = std::env::var(CASE) else {
            return;
        };
        let dir = tempfile::tempdir().expect("dir");
        let (path, target) = (
            dir.path().join(FILE_NAME),
            dir.path().join("elsewhere.json"),
        );
        let widen = |at: &std::path::Path| {
            let open = std::fs::Permissions::from_mode(0o644);
            std::fs::set_permissions(at, open).expect("chmod");
        };
        match case.as_str() {
            "first" => {}
            "widened" => {
                std::fs::write(&path, "{}").expect("write");
                widen(&path);
            }
            "symlink" => {
                std::fs::write(&target, "kept").expect("write");
                widen(&target);
                symlink(&target, &path).expect("symlink");
            }
            other => panic!("no case {other}"),
        }
        let now = crate::clock::unix_secs().expect("a clock");
        assert!(
            spend_history::save(&spent(), dir.path(), now),
            "{case}: no save"
        );
        let kind = std::fs::symlink_metadata(&path)
            .expect("the file")
            .file_type();
        assert!(kind.is_file(), "{case}: the path is not a plain file");
        assert_eq!(bits(&path), 0o600, "{case}: readable beyond its owner");
        if case == "symlink" {
            assert_eq!(std::fs::read_to_string(&target).expect("target"), "kept");
            assert_eq!(bits(&target), 0o644, "the link's target was touched");
        }
        println!("{case} passed in the child");
    }

    /// S17: under umask 022 the first history file is owner-only. Mutant: the
    /// mode inherited (the new file is 0644).
    #[test]
    fn a_first_history_file_is_owner_only() {
        under_umask_022("first");
    }

    /// S17: a history file someone widened to 0644 is owner-only after the
    /// next save.
    #[test]
    fn a_widened_history_file_is_owner_only_after_a_save() {
        under_umask_022("widened");
    }

    /// S17: a symlink at the path becomes an owner-only plain file, and the
    /// file it pointed at keeps its bytes and mode. Mutant: the mode
    /// inherited (the new file is 0644).
    #[test]
    fn a_symlinked_history_path_becomes_an_owner_only_file() {
        under_umask_022("symlink");
    }
}

/// A config with auth on and the one API key `k`, its files under `dir`.
fn one_key_config(dir: &Path) -> crate::config::Config {
    let under = |name: &str| dir.join(name).to_string_lossy().into_owned();
    let key = crate::config::ApiKeyConfig {
        name: "k".to_owned(),
        key_sha256: Some(format!("sha256:{}", "a".repeat(64))),
        ..crate::config::ApiKeyConfig::default()
    };
    let mut config = crate::config::Config::default();
    config.auth.enabled = true;
    config.auth.api_keys = vec![key];
    (config.server.host, config.server.port) = ("127.0.0.1".to_owned(), 0);
    config.tasks.store_dir = under("tasks");
    // Not the home directory's audit log, which one process holds at a time.
    config.security.transparency_log.path = under("audit.jsonl");
    config
}

/// r7d carry: with cost governance off at start the history still comes
/// back, since the restore is its own start step. Mutant: the restore moved
/// inside the governance boot, which returns early when governance is off.
#[tokio::test]
async fn the_history_restores_with_cost_governance_off() {
    // The gateway opens its audit log here: a kept dir outlives the log.
    let dir = crate::test_dir_keep::kept_tempdir();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    let now = crate::clock::unix_secs().expect("a clock");
    assert!(spend_history::save(&spent(), &data, now));

    let config = one_key_config(dir.path());
    assert!(
        !config.cost_governance.enabled,
        "premise: governance is off"
    );
    let gateway = crate::gateway::Gateway::new(config)
        .await
        .expect("the gateway builds")
        .with_data_dir(data);
    let built = Box::pin(gateway.build_meta_mcp()).await;
    let meta = built.expect("the meta layer builds").meta_mcp;
    let series = meta.cost_tracker().key_series("k").expect("restored");
    assert_eq!(series.hours.rows().iter().map(|r| r.2).sum::<u64>(), 3);
}

/// agy r7d carry: with auth off no key is charged per key, so a saved key row
/// attaches to no configured name even when `api_keys` still lists one; its
/// spend comes back in the gateway's total, through the carried overflow.
/// Mutant: the names passed whatever `auth.enabled` says.
#[tokio::test]
async fn with_auth_off_a_saved_key_row_attaches_to_no_key() {
    // The gateway opens its audit log here: a kept dir outlives the log.
    let dir = crate::test_dir_keep::kept_tempdir();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    let now = crate::clock::unix_secs().expect("a clock");
    assert!(spend_history::save(&spent(), &data, now));

    let mut config = one_key_config(dir.path());
    config.auth.enabled = false;
    assert_eq!(
        config.auth.api_keys.len(),
        1,
        "premise: a key is still listed"
    );
    let gateway = crate::gateway::Gateway::new(config)
        .await
        .expect("the gateway builds")
        .with_data_dir(data);
    let built = Box::pin(gateway.build_meta_mcp()).await;
    let tracker = built
        .expect("the meta layer builds")
        .meta_mcp
        .cost_tracker();
    assert!(
        tracker.key_series("k").is_none(),
        "a key row attached with auth off"
    );
    let total = tracker.gateway_series(now);
    assert_eq!(total.hours.rows().iter().map(|r| r.2).sum::<u64>(), 3);
}
