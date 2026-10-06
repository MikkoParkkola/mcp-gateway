// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Env files are followed through retargets by the poll (#1286), end to end
//! through `ConfigWatcher`.

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::ConfigWatcher;
use super::env_poll::TEST_ENV_POLL;
use crate::config::{Config, EnvOverlay, LiveEnv, ResolvedEnvFiles};
use crate::gateway::test_helpers::write_owner_only;

/// Point `link` at `target` atomically, as a deploy does.
fn retarget(link: &Path, target: &Path) {
    let name = link.file_name().expect("link name").to_string_lossy();
    let tmp = link.with_file_name(format!("{name}.retarget-tmp"));
    symlink(target, &tmp).expect("tmp link");
    std::fs::rename(&tmp, link).expect("rename over link");
}

struct Started {
    watcher: ConfigWatcher,
    env: Arc<LiveEnv>,
    live: Arc<super::LiveConfig>,
    _shutdown: tokio::sync::broadcast::Sender<()>,
}

/// A watcher on a plain config in `root`, with `env_paths` recorded as startup
/// records them and the live overlay loaded from them.
fn start(root: &Path, env_paths: Vec<PathBuf>) -> Started {
    let cfg = root.join("gateway.yaml");
    write_owner_only(&cfg, "routing_profiles:\n  p:\n    description: \"x\"\n").unwrap();
    let overlay = EnvOverlay::from_paths(&env_paths);
    let env = Arc::new(LiveEnv::new(
        Arc::new(overlay),
        ResolvedEnvFiles::new(env_paths, false),
    ));
    let (shutdown, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let live = Arc::new(super::LiveConfig::new(Config::default()));
    let watcher = ConfigWatcher::start(
        cfg,
        Arc::clone(&live),
        Arc::new(crate::backend::BackendRegistry::new()),
        &Config::default(),
        Arc::clone(&env),
        None,
        None,
        shutdown_rx,
    )
    .expect("the watcher starts");
    Started {
        watcher,
        env,
        live,
        _shutdown: shutdown,
    }
}

fn value(env: &LiveEnv, key: &str) -> Option<String> {
    env.get().resolve(key)
}

/// Wait up to `secs` for `key` to read `want` in the live overlay.
async fn reaches(env: &LiveEnv, key: &str, want: &str, secs: u64) {
    let got = tokio::time::timeout(Duration::from_secs(secs), async {
        while value(env, key).as_deref() != Some(want) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        got.is_ok(),
        "{key} never read {want:?} within {secs} s; it reads {:?}",
        value(env, key)
    );
}

/// P1: a directory-link retarget, then a write to the new target.
#[tokio::test]
async fn p1_a_directory_link_retarget_then_a_write_reaches_the_overlay() {
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    for rel in ["rel1", "rel2"] {
        std::fs::create_dir(r.join(rel)).unwrap();
        write_owner_only(r.join(rel).join(".env"), format!("MCP_GW_T1286_P1={rel}\n")).unwrap();
    }
    symlink("rel1", r.join("current")).unwrap();
    let g = start(r, vec![r.join("current").join(".env")]);
    assert_eq!(value(&g.env, "MCP_GW_T1286_P1").as_deref(), Some("rel1"));

    retarget(&r.join("current"), Path::new("rel2"));
    reaches(&g.env, "MCP_GW_T1286_P1", "rel2", 3).await;
    write_owner_only(r.join("rel2").join(".env"), "MCP_GW_T1286_P1=rel2b\n").unwrap();
    reaches(&g.env, "MCP_GW_T1286_P1", "rel2b", 3).await;
}

/// P2: a file-symlink retarget, then a write to the new target.
#[tokio::test]
async fn p2_a_file_link_retarget_then_a_write_reaches_the_overlay() {
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    for (dir, v) in [("a", "one"), ("b", "two")] {
        std::fs::create_dir(r.join(dir)).unwrap();
        write_owner_only(r.join(dir).join(".env"), format!("MCP_GW_T1286_P2={v}\n")).unwrap();
    }
    symlink(r.join("a").join(".env"), r.join("link.env")).unwrap();
    let g = start(r, vec![r.join("link.env")]);
    assert_eq!(value(&g.env, "MCP_GW_T1286_P2").as_deref(), Some("one"));

    retarget(&r.join("link.env"), &r.join("b").join(".env"));
    reaches(&g.env, "MCP_GW_T1286_P2", "two", 3).await;
    write_owner_only(r.join("b").join(".env"), "MCP_GW_T1286_P2=three\n").unwrap();
    reaches(&g.env, "MCP_GW_T1286_P2", "three", 3).await;
}

/// P3: a malformed file left unchanged is retried, warned about once, and
/// picked up when fixed with no config edit; the same failure after the fix
/// is warned about again. Counted from the log an operator reads, since the
/// first failure may be warned by the config-file branch (the start's own
/// reload can coalesce with the edit) and its env-file retries stay quiet.
#[test]
fn p3_a_failing_env_file_is_retried_warned_once_and_recovers() {
    use crate::test_log_capture::{count, records};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("a.env");
    write_owner_only(&path, "MCP_GW_T1286_P3=good\n").unwrap();
    // Built inside the runtime; its tasks run whenever the runtime is driven.
    let g = runtime.block_on(async { start(root.path(), vec![path.clone()]) });

    // Phase 1: an unchanged malformed file is retried and warned about once.
    let mut limiter_warnings = 0;
    let first = records(|| {
        runtime.block_on(async {
            let counts = g.watcher.env_reloads();
            write_owner_only(&path, "MCP_GW_T1286_P3=\"unterminated\n").unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            let attempts = counts.attempts.load(Ordering::SeqCst);
            assert!(
                attempts >= 3,
                "an unchanged failing file must be retried; {attempts} reloads ran"
            );
            assert_eq!(
                value(&g.env, "MCP_GW_T1286_P3").as_deref(),
                Some("good"),
                "a failed reload keeps the overlay"
            );
            limiter_warnings = counts.warns.load(Ordering::SeqCst);
        });
    });
    assert!(
        limiter_warnings <= 1,
        "the limiter warned {limiter_warnings} times for one unchanged error"
    );
    assert_eq!(
        count(&first, "WARN", "Config reload:"),
        1,
        "one warning for one unchanged failure"
    );

    // Phase 2: fixed with no config edit, then the same failure again within
    // the minute. The success reset the limiter, so it warns again, once.
    let second = records(|| {
        runtime.block_on(async {
            write_owner_only(&path, "MCP_GW_T1286_P3=fixed\n").unwrap();
            reaches(&g.env, "MCP_GW_T1286_P3", "fixed", 3).await;
            write_owner_only(&path, "MCP_GW_T1286_P3=\"unterminated\n").unwrap();
            tokio::time::sleep(Duration::from_secs(3)).await;
        });
    });
    assert_eq!(
        count(&second, "WARN", "Config reload:"),
        1,
        "the same failure after a successful reload warns again, once"
    );
}

fn description(live: &super::LiveConfig) -> Option<String> {
    live.get()
        .routing_profiles
        .get("p")
        .map(|p| p.description.clone())
}

/// Wait up to `secs` for the live config's profile to read `want`.
async fn describes(live: &super::LiveConfig, want: &str, secs: u64) {
    let got = tokio::time::timeout(Duration::from_secs(secs), async {
        while description(live).as_deref() != Some(want) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        got.is_ok(),
        "the live config never read {want:?} within {secs} s; it reads {:?}",
        description(live)
    );
}

/// P4: a valid config edit that failed together with a broken env file is
/// applied once the env file is put back, with no further config edit.
#[tokio::test]
async fn p4_a_config_edit_that_failed_with_a_broken_env_file_applies_when_it_is_restored() {
    let root = tempfile::tempdir().unwrap();
    let env_path = root.path().join("a.env");
    write_owner_only(&env_path, "MCP_GW_T1286_P4=ok\n").unwrap();
    let g = start(root.path(), vec![env_path.clone()]);
    describes(&g.live, "x", 5).await;

    write_owner_only(&env_path, "MCP_GW_T1286_P4=\"unterminated\n").unwrap();
    write_owner_only(
        root.path().join("gateway.yaml"),
        "routing_profiles:\n  p:\n    description: \"two\"\n",
    )
    .unwrap();
    // Restore the env file as soon as a reload has failed, before or after
    // the poll saw the broken bytes: either way the edit must still apply.
    let failed = tokio::time::timeout(Duration::from_secs(5), async {
        while !g.watcher.env_reloads().failed() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(failed.is_ok(), "premise: the combined reload failed");
    assert_eq!(
        description(&g.live).as_deref(),
        Some("x"),
        "premise: the failed reload applied nothing"
    );

    write_owner_only(&env_path, "MCP_GW_T1286_P4=ok\n").unwrap();
    describes(&g.live, "two", 3).await;
}

/// ENVFILE.19 (rewritten): the running poll reads exactly the recorded paths.
/// Each recorded file's change reaches the overlay; a same-named file in
/// another directory triggers no reload.
#[tokio::test]
async fn envfile_19_the_poll_reads_the_recorded_paths_and_no_other() {
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    let mut recorded = Vec::new();
    for dir in ["one", "two", "other"] {
        std::fs::create_dir(r.join(dir)).unwrap();
        write_owner_only(
            r.join(dir).join(".env"),
            format!("MCP_GW_T1286_E19_{}=start\n", dir.to_uppercase()),
        )
        .unwrap();
        if dir != "other" {
            recorded.push(r.join(dir).join(".env"));
        }
    }
    let g = start(r, recorded.clone());
    for (path, key) in recorded
        .iter()
        .zip(["MCP_GW_T1286_E19_ONE", "MCP_GW_T1286_E19_TWO"])
    {
        write_owner_only(path, format!("{key}=changed\n")).unwrap();
        reaches(&g.env, key, "changed", 3).await;
    }

    // Let the last reload settle, then write the unrecorded sibling.
    tokio::time::sleep(TEST_ENV_POLL * 2).await;
    let before = g.watcher.env_reloads().attempts.load(Ordering::SeqCst);
    write_owner_only(
        r.join("other").join(".env"),
        "MCP_GW_T1286_E19_OTHER=changed\n",
    )
    .unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        g.watcher.env_reloads().attempts.load(Ordering::SeqCst),
        before,
        "a file the gateway never loaded started a reload"
    );
    assert_eq!(value(&g.env, "MCP_GW_T1286_E19_OTHER"), None);
}

/// A poll read that never finishes in time, like a stalled NFS mount.
fn stalled_read(_: &EnvOverlay, _: &[PathBuf]) -> Option<PathBuf> {
    std::thread::sleep(Duration::from_secs(1));
    None
}

/// Runs of T20. Without the post-poll shutdown check, a run passes only if
/// `select!` reaches shutdown before the poll branch, which is ready again at
/// once after the in-flight tick. `select!` starts at a random branch and
/// polls in order: of its four branches (shutdown, wake, retry, poll), only a
/// start at shutdown picks it, so a run passes with probability 1/4, and at
/// most 1/2 even when a directory wake is also ready. All 20 runs pass with
/// probability at most 2^-20 ~= 9.5e-7, below 1e-6.
const T20_RUNS: usize = 20;

/// T20: shutdown sent while a stalled env read is in flight ends the rewatch
/// task when that tick returns, with no further tick started, though the
/// poll interval is ready again every tick. Current-thread on purpose: the
/// test and the task share one thread, which is what makes "the task is
/// parked inside the tick" hold when the send happens.
#[tokio::test(flavor = "current_thread")]
async fn t20_shutdown_during_a_stalled_env_read_starts_no_further_tick() {
    use super::watch_chain::{CHAIN_RETRY, named_config_path, spawn_rewatch_task};
    let wait = Duration::from_millis(50);
    for run in 0..T20_RUNS {
        let root = tempfile::tempdir().unwrap();
        let named = named_config_path(root.path().join("gateway.yaml"));
        write_owner_only(&named, "a: 1\n").unwrap();
        let (tx, _events) = tokio::sync::mpsc::channel(32);
        let (wake_tx, wake_rx) = tokio::sync::watch::channel(());
        let (shutdown, _) = tokio::sync::broadcast::channel(1);
        let chain = ConfigWatcher::create_notify_watcher(tx.clone(), wake_tx, &named)
            .expect("the watcher starts");
        let poller = super::env_poll::EnvPoller::new(
            // One recorded file, so each tick runs the stalled read.
            Arc::new(LiveEnv::new(
                Arc::new(EnvOverlay::none()),
                ResolvedEnvFiles::new(vec![PathBuf::from("/unread.env")], false),
            )),
            Arc::default(),
            PathBuf::new(),
        )
        .with_read(stalled_read);
        let ticks = poller.ticks();
        let task = spawn_rewatch_task(
            named,
            chain,
            wake_rx,
            tx,
            shutdown.subscribe(),
            CHAIN_RETRY,
            poller,
            wait,
        );
        // Let a few stalled ticks pass, then send the moment the next tick
        // has started: the test and the task share one thread, so the task
        // is parked inside that tick's wait when this loop sees the count.
        let count = || ticks.load(Ordering::SeqCst);
        let seen = tokio::time::timeout(Duration::from_secs(5), async {
            while count() < 2 {
                tokio::task::yield_now().await;
            }
            let before = count();
            while count() == before {
                tokio::task::yield_now().await;
            }
            count()
        })
        .await
        .expect("the poll ticks");
        shutdown.send(()).expect("the task listens");
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("shutdown ends the task")
            .expect("the task does not panic");
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            seen,
            "run {run}: a tick started after shutdown was sent during a stalled read"
        );
    }
}
