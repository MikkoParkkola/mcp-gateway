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
    let watcher = ConfigWatcher::start(
        cfg,
        Arc::new(super::LiveConfig::new(Config::default())),
        Arc::new(crate::backend::BackendRegistry::new()),
        &Config::default(),
        Arc::clone(&env),
        None,
        shutdown_rx,
    )
    .expect("the watcher starts");
    Started {
        watcher,
        env,
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
/// picked up when fixed with no config edit.
#[tokio::test]
async fn p3_a_failing_env_file_is_retried_warned_once_and_recovers() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("a.env");
    write_owner_only(&path, "MCP_GW_T1286_P3=good\n").unwrap();
    let g = start(root.path(), vec![path.clone()]);
    let counts = g.watcher.env_reloads();

    write_owner_only(&path, "MCP_GW_T1286_P3=\"unterminated\n").unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    let attempts = counts.attempts.load(Ordering::SeqCst);
    assert!(
        attempts >= 3,
        "an unchanged failing file must be retried; {attempts} reloads ran"
    );
    assert_eq!(
        counts.warns.load(Ordering::SeqCst),
        1,
        "one warning for one unchanged error within a minute"
    );
    assert_eq!(
        value(&g.env, "MCP_GW_T1286_P3").as_deref(),
        Some("good"),
        "a failed reload keeps the overlay"
    );

    write_owner_only(&path, "MCP_GW_T1286_P3=fixed\n").unwrap();
    reaches(&g.env, "MCP_GW_T1286_P3", "fixed", 3).await;
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
