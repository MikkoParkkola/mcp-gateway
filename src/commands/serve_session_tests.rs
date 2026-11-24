// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The serve load holds one startup session: the config lock is taken at the load and kept
//! through construction, and a config whose directory no writer can use starts only when no
//! config-write artifact sits beside it.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use crate::config_persistence::lock::{NotLocked, lock_config_deferred};
use crate::gateway::test_helpers::write_owner_only;

const SERVED: &str = "server:\n  port: 9\n";

/// Taking the lock with no wait at all: `Busy` while the serve load's session holds it.
async fn held_elsewhere(config: &Path) -> bool {
    match lock_config_deferred(config, Instant::now()).await {
        Ok(taken) => {
            drop(taken);
            false
        }
        Err(NotLocked::Busy) => true,
        Err(other) => panic!("taking the lock failed for another reason: {other:?}"),
    }
}

/// WIRE.1: the lock is held from the serve load, across the environment hand-over, until the
/// gateway is built; then it is free.
#[tokio::test(flavor = "multi_thread")]
async fn startup_lock_span() {
    const ROW: &str = "startup_lock_span";
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    write_owner_only(&config, SERVED).expect("config");

    let mut evaluated = super::serve_fixture::serve_load(ROW, &config).await;
    assert!(held_elsewhere(&config).await, "{ROW}: held after the load");
    let env = Arc::new(evaluated.live_env());
    assert!(
        held_elsewhere(&config).await,
        "{ROW}: held after the environment hand-over"
    );
    let gateway = Box::pin(super::serve_fixture::serve_build(
        ROW, evaluated, env, &config,
    ))
    .await;
    assert!(
        !held_elsewhere(&config).await,
        "{ROW}: free once the gateway is built"
    );
    drop(gateway);
}

#[cfg(unix)]
fn seal(dir: &Path, sealed: bool) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut access = std::fs::metadata(dir).expect("stat").permissions();
    access.set_mode(if sealed { 0o555 } else { 0o755 });
    std::fs::set_permissions(dir, access).expect("chmod");
}

/// WIRE.3: in a directory no writer can use, each config-write artifact alone refuses the serve
/// load with the check-failed class, and nothing changes.
#[cfg(unix)]
#[tokio::test]
async fn startup_read_only_artifact_refused() {
    const ROW: &str = "startup_read_only_artifact_refused";
    const CHECK_FAILED: &str = "could not confirm that no config write is pending";
    if rustix::process::geteuid().is_root() {
        return;
    }
    for name in [
        ".gateway.yaml.replace-journal",
        "gateway.yaml.abandoned",
        "gateway.yaml.abandoned.retired",
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("gateway.yaml");
        write_owner_only(&config, SERVED).expect("config");
        write_owner_only(dir.path().join(name), "left beside the config").expect("artifact");
        seal(dir.path(), true);
        let loaded = super::load_for_serve(Some(&config)).await;
        let after = std::fs::read_dir(dir.path()).expect("list").count();
        seal(dir.path(), false);
        let message = match loaded {
            Ok(_) => panic!("{ROW} {name}: the serve load must refuse"),
            Err(error) => error.to_string(),
        };
        assert!(
            message.contains(CHECK_FAILED),
            "{ROW} {name}: the check-failed class, got {message:?}"
        );
        assert_eq!(
            after, 2,
            "{ROW} {name}: only the config and the artifact are there"
        );
    }
}

/// The discovery rows run in a child test process of their own: its working directory and home
/// are a fresh scratch folder, so a config planted at a discovery location is seen by no other
/// test, and the account's real config is never searched.
const SCENARIO_ENV: &str = "MCP_GATEWAY_SERVE_SESSION_SCENARIO";
const MODULE: &str = "commands::serve_session_tests::";
const NESTED_LIMIT: std::time::Duration = std::time::Duration::from_secs(120);

fn is_nested(scenario: &str) -> bool {
    std::env::var_os(SCENARIO_ENV).is_some_and(|running| running == scenario)
}

/// Runs `scenario` in a child test process with `scratch` as its working directory and
/// `scratch/home` as its home, and fails unless the scenario ran and passed.
async fn run_nested(row: &str, scenario: &str, scratch: &Path) {
    let home = scratch.join("home");
    std::fs::create_dir_all(&home).expect("the scenario's home");
    let filter = format!("{MODULE}{scenario}");
    let mut child = tokio::process::Command::from(crate::test_home::test_binary());
    child
        .args(["--exact", &filter, "--nocapture"])
        .env(SCENARIO_ENV, scenario)
        .env("MCP_GATEWAY_TEST_HOME_DIR", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .current_dir(scratch)
        .kill_on_drop(true);
    let output = tokio::time::timeout(NESTED_LIMIT, child.output())
        .await
        .unwrap_or_else(|_| panic!("{row}: the scenario finished within {NESTED_LIMIT:?}"))
        .expect("run the scenario");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains(&filter) && output.status.success(),
        "{row}: the scenario {filter} ran and passed; stdout={stdout:?} stderr={stderr:?}"
    );
}

/// WIRE.1 (lead 2026-11-21): with no `--config`, the config discovery finds is gated like a
/// named one. An abandoned file beside it refuses the start, and nothing beside it changes.
#[tokio::test]
async fn discovered_config_with_abandoned_session_refuses() {
    const ROW: &str = "discovered_config_with_abandoned_session_refuses";
    let scratch = tempfile::tempdir().expect("scratch");
    // Logging on: with it off, an abandoned file is accepted for later (WIRE.4), so the gate's
    // refusal would never be reached.
    let logged = format!(
        "{SERVED}security:\n  transparency_log:\n    enabled: true\n    path: {:?}\n",
        scratch.path().join("audit.jsonl").display().to_string()
    );
    write_owner_only(scratch.path().join("gateway.yaml"), logged).expect("config");
    write_owner_only(
        scratch.path().join("gateway.yaml.abandoned"),
        "left by a dead writer",
    )
    .expect("abandoned file");
    let before = (
        std::fs::read(scratch.path().join("gateway.yaml")).expect("config bytes"),
        std::fs::read(scratch.path().join("gateway.yaml.abandoned")).expect("artifact bytes"),
    );
    run_nested(ROW, "discovered_abandoned_scenario", scratch.path()).await;
    let after = (
        std::fs::read(scratch.path().join("gateway.yaml")).expect("config bytes"),
        std::fs::read(scratch.path().join("gateway.yaml.abandoned")).expect("artifact bytes"),
    );
    assert_eq!(after, before, "{ROW}: config and abandoned file unchanged");
}

#[tokio::test]
async fn discovered_abandoned_scenario() {
    const ROW: &str = "discovered_config_with_abandoned_session_refuses";
    const ABANDONED_CLASS: &str = "holds audit records this gateway cannot deliver";
    if !is_nested("discovered_abandoned_scenario") {
        return;
    }
    let discovered = crate::config::Config::fallback_config_path();
    assert_eq!(
        discovered.as_deref(),
        Some(Path::new("gateway.yaml")),
        "{ROW}: premise: discovery finds the scratch folder's config"
    );
    // Load, then build: the gate settles at construction, with the serving log (D-LOG).
    let started = match super::load_for_serve(discovered.as_deref()).await {
        Ok(mut evaluated) => {
            // The discovered path is gated like a named one: its session holds the lock from the
            // load on. The sessionless gate at construction would refuse the file too, but it
            // takes no session, so only this proves the serve load gated it.
            assert!(
                held_elsewhere(Path::new("gateway.yaml")).await,
                "{ROW}: the load's session holds the lock"
            );
            let env = Arc::new(evaluated.live_env());
            let built = crate::gateway::Gateway::new_evaluated(evaluated.config, env, discovered);
            Box::pin(built).await.map(drop)
        }
        Err(error) => Err(error),
    };
    match started {
        Ok(()) => panic!("{ROW}: the served start must refuse the discovered config"),
        Err(error) => assert!(
            error.to_string().contains(ABANDONED_CLASS),
            "{ROW}: the abandoned-file refusal, got {error}"
        ),
    }
}

/// WIRE.1 (lead 2026-11-21): a serve that found no config never loads one that appears later.
/// Discovery finds nothing; then a config is planted where discovery looks; the serve load still
/// runs on the built-in defaults.
#[tokio::test]
async fn config_appearing_after_resolve_is_never_loaded() {
    const ROW: &str = "config_appearing_after_resolve_is_never_loaded";
    let scratch = tempfile::tempdir().expect("scratch");
    run_nested(ROW, "config_appearing_scenario", scratch.path()).await;
}

#[tokio::test]
async fn config_appearing_scenario() {
    const ROW: &str = "config_appearing_after_resolve_is_never_loaded";
    const PLANTED: &str = "server:\n  port: 47123\n";
    if !is_nested("config_appearing_scenario") {
        return;
    }
    let discovered = crate::config::Config::fallback_config_path();
    assert!(
        discovered.is_none(),
        "{ROW}: premise: discovery finds no config, found {discovered:?}"
    );
    write_owner_only("gateway.yaml", PLANTED).expect("the config that appears late");
    let evaluated = super::load_for_serve(discovered.as_deref())
        .await
        .unwrap_or_else(|error| panic!("{ROW}: the serve load runs on defaults: {error}"));
    assert_ne!(
        evaluated.config.server.port, 47123,
        "{ROW}: the late config was not loaded"
    );
}

/// WIRE.5: a successor started while the old process still holds the config lock (as a
/// committed restart does) waits for it. Released within the wait: the load proceeds. Held past
/// it: the load refuses with the Busy class after the full wait.
#[tokio::test(flavor = "multi_thread")]
async fn restart_overlap_waits_then_busy() {
    const ROW: &str = "restart_overlap_waits_then_busy";
    const BUSY: &str = "past the 30-second wait";
    // limit-under-test (fires-only): a stall only lengthens the measured wait, never shortens it
    const RELEASED_AFTER: std::time::Duration = std::time::Duration::from_millis(200);
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    write_owner_only(&config, SERVED).expect("config");

    // Case A: the old process lets go during the wait.
    let Ok(held) = lock_config_deferred(&config, Instant::now()).await else {
        panic!("{ROW}: nothing else holds the fixture's lock yet");
    };
    let started = Instant::now();
    let release = tokio::spawn(async move {
        // timing: lower-bound
        tokio::time::sleep(RELEASED_AFTER).await;
        drop(held);
    });
    let loaded = super::load_for_serve(Some(&config)).await;
    let waited = started.elapsed();
    release.await.expect("the release task");
    let evaluated = loaded.unwrap_or_else(|error| {
        panic!("{ROW} A: the load proceeds once the lock is free: {error}")
    });
    drop(evaluated);
    assert!(
        waited >= RELEASED_AFTER,
        "{ROW} A: the load waited for the release, took {waited:?}"
    );

    // Case B: the old process keeps holding.
    let Ok(held) = lock_config_deferred(&config, Instant::now()).await else {
        panic!("{ROW} B: case A left the lock free");
    };
    let started = Instant::now();
    let loaded = super::load_for_serve(Some(&config)).await;
    let waited = started.elapsed();
    drop(held);
    let message = match loaded {
        Ok(_) => panic!("{ROW} B: a held lock must refuse the load, it loaded after {waited:?}"),
        Err(error) => error.to_string(),
    };
    assert!(
        message.contains(BUSY),
        "{ROW} B: the Busy class, got {message:?}"
    );
    assert!(
        (std::time::Duration::from_secs(30)..std::time::Duration::from_secs(35)).contains(&waited),
        "{ROW} B: refused after the 30 s wait, took {waited:?}"
    );
}

/// WIRE.6 / SERVE.5: the serve load reaches the startup gate, and construction finishes it.
/// WIRE.1 (kimi r3 I2 order): only the first environment taken from a serve load holds its
/// session. That construction finishes and lets the lock go; then an abandoned file is planted,
/// and every other construction (a clone of the load from before or after the hand-over, and a
/// second hand-over) has no session, so it meets the sessionless gate and refuses. The log is
/// opened once, by the first construction.
#[tokio::test(flavor = "multi_thread")]
async fn startup_session_take_once() {
    use crate::security::transparency_log::open_attempts;
    const ROW: &str = "startup_session_take_once";
    const ABANDONED_CLASS: &str = "holds audit records this gateway cannot deliver";
    let dir = crate::test_dir_keep::kept_tempdir();
    let config = dir.path().join("gateway.yaml");
    let log = dir.path().join("audit.jsonl");
    let text = format!(
        "security:\n  transparency_log:\n    enabled: true\n    path: {:?}\n",
        log.display().to_string()
    );
    write_owner_only(&config, text).expect("config");

    let mut evaluated = super::serve_fixture::serve_load(ROW, &config).await;
    let before = evaluated.clone();
    let env = Arc::new(evaluated.live_env());
    let after = evaluated.clone();
    let second = Arc::new(evaluated.live_env());
    let gateway = Box::pin(super::serve_fixture::serve_build(
        ROW, evaluated, env, &config,
    ))
    .await;
    drop(gateway);
    assert!(
        !held_elsewhere(&config).await,
        "{ROW}: premise: the first construction let the lock go"
    );
    write_owner_only(
        dir.path().join("gateway.yaml.abandoned"),
        "left by a dead writer",
    )
    .expect("abandoned file");

    let mut others = vec![("second hand-over", before.config.clone(), second)];
    for (name, mut copy) in [("clone before", before), ("clone after", after)] {
        let env = Arc::new(copy.live_env());
        others.push((name, copy.config, env));
    }
    for (name, copied, env) in others {
        let built = crate::gateway::Gateway::new_evaluated(copied, env, Some(config.clone())).await;
        match built {
            Ok(_) => panic!("{ROW} {name}: a construction without the session must refuse"),
            Err(error) => assert!(
                error.to_string().contains(ABANDONED_CLASS),
                "{ROW} {name}: the sessionless gate's abandoned-file refusal, got {error}"
            ),
        }
    }
    assert_eq!(
        open_attempts::at(&log),
        1,
        "{ROW}: only the first construction opened the log"
    );
}

/// K1: the config served is the one the startup gate checked. The config is a link to A; once
/// the gate has resolved and checked A, the link is pointed at B before the load: A is served.
#[cfg(unix)]
#[tokio::test]
async fn serve_loads_the_gated_target() {
    use crate::config_reload::serve_seams::{self, Point};
    use std::sync::atomic::{AtomicBool, Ordering};
    const ROW: &str = "serve_loads_the_gated_target";
    let dir = tempfile::tempdir().expect("tempdir");
    let a = dir.path().join("a.yaml");
    let b = dir.path().join("b.yaml");
    write_owner_only(&a, "server:\n  port: 11\n").expect("config A");
    write_owner_only(&b, "server:\n  port: 12\n").expect("config B");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink(&a, &link).expect("the link to A");
    let checked = std::fs::canonicalize(&a).expect("A resolved");
    let repointed = Arc::new(AtomicBool::new(false));
    let _armed = {
        let (link, b, repointed) = (link.clone(), b.clone(), Arc::clone(&repointed));
        serve_seams::arm(&checked, Point::AfterPrepare, move || {
            std::fs::remove_file(&link).expect("drop the link");
            std::os::unix::fs::symlink(&b, &link).expect("the link to B");
            repointed.store(true, Ordering::SeqCst);
        })
    };
    let evaluated = super::serve_fixture::serve_load(ROW, &link).await;
    assert!(
        repointed.load(Ordering::SeqCst),
        "{ROW}: premise: the link moved between the gate and the load"
    );
    assert_eq!(
        evaluated.config.server.port, 11,
        "{ROW}: the config the gate checked (A) is served"
    );
}

/// WIRE.3 control: a config in a directory no writer can use, with no artifact beside it, starts
/// without the lock, and nothing is created there. The HTTP and stdio entry points both start
/// through this load and build (cli/entry.rs:547, :606).
#[cfg(unix)]
#[tokio::test]
async fn startup_read_only_starts_unlocked() {
    const ROW: &str = "startup_read_only_starts_unlocked";
    if rustix::process::geteuid().is_root() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    write_owner_only(&config, SERVED).expect("config");
    seal(dir.path(), true);
    let mut evaluated = super::serve_fixture::serve_load(ROW, &config).await;
    let env = Arc::new(evaluated.live_env());
    let built =
        crate::gateway::Gateway::new_evaluated(evaluated.config, env, Some(config.clone())).await;
    let listed = std::fs::read_dir(dir.path()).expect("list").count();
    seal(dir.path(), false);
    built.unwrap_or_else(|error| panic!("{ROW}: the start proceeds unlocked: {error}"));
    assert_eq!(
        listed, 1,
        "{ROW}: only the config is there, no lock sidecar"
    );
}

/// WIRE.4 / Q2: an abandoned file is accepted for later only when logging is off. With logging
/// on and its best-effort open failed (auth off), a served start refuses it; the same start with
/// no artifact warns and serves.
#[tokio::test]
async fn failed_log_refuses_abandoned() {
    const ROW: &str = "failed_log_refuses_abandoned";
    for artifact in [true, false] {
        let dir = crate::test_dir_keep::kept_tempdir();
        let config = dir.path().join("gateway.yaml");
        write_owner_only(&config, super::serve_fixture::failed_log_config(dir.path()))
            .expect("config");
        if artifact {
            write_owner_only(
                dir.path().join("gateway.yaml.abandoned"),
                "left by a dead writer",
            )
            .expect("abandoned file");
        }
        let mut evaluated = super::serve_fixture::serve_load(ROW, &config).await;
        let env = Arc::new(evaluated.live_env());
        let built =
            crate::gateway::Gateway::new_evaluated(evaluated.config, env, Some(config.clone()))
                .await;
        match (artifact, built) {
            (true, Ok(_)) => panic!("{ROW}: a failed log must not let the abandoned file through"),
            (true, Err(error)) => assert!(
                error
                    .to_string()
                    .contains(super::serve_fixture::ABANDONED_CLASS),
                "{ROW}: the abandoned-file refusal, got {error}"
            ),
            (false, built) => {
                built.unwrap_or_else(|error| panic!("{ROW}: no artifact, so it serves: {error}"));
            }
        }
    }
}

#[test]
fn serve_paths_reach_the_gate() {
    const ROW: &str = "serve_paths_reach_the_gate";
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |part: &str| std::fs::read_to_string(root.join(part)).expect("read the source");
    let commands = read("src/commands/mod.rs");
    let load = commands
        .split("fn load_for_serve")
        .nth(1)
        .expect("load_for_serve is defined");
    // Its body and the boxed gated load it hands to: the two functions that follow.
    let load = load
        .split("\n}\n")
        .take(2)
        .collect::<Vec<_>>()
        .join("\n}\n");
    // The scaffold commit carried a temporary allow above the function; the head must not.
    let above = commands
        .split("fn load_for_serve")
        .next()
        .expect("text before load_for_serve");
    let attrs = above.rsplit("\n\n").next().unwrap_or_default();
    assert!(
        !attrs.contains("unused_async"),
        "{ROW}: load_for_serve carries no unused_async allow"
    );
    assert!(
        load.contains("prepare_start"),
        "{ROW}: load_for_serve runs prepare_start"
    );
    // Construction settles the session through the serving audit it opens.
    let construct = read("src/gateway/server/construct.rs");
    let audit = read("src/gateway/server/serving_audit.rs");
    assert!(
        construct.contains("serving_audit::open_and_settle(") && audit.contains("finish_start("),
        "{ROW}: construction runs finish_start"
    );
}

/// The session, and with it the config lock, lives until construction settles with the serving
/// log: at that point a second attempt at the lock finds it held. A session dropped earlier in
/// construction would leave the settle unreached, or reached with the lock free.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn the_lock_is_held_while_construction_settles() {
    use crate::config_reload::serve_seams::{self, Point};
    const ROW: &str = "the_lock_is_held_while_construction_settles";
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    write_owner_only(&config, SERVED).expect("config");
    // The gate keys its stops by the resolved config.
    let target = std::fs::canonicalize(&config).expect("resolved config");
    let seen: Arc<std::sync::Mutex<Option<bool>>> = Arc::default();
    let record = Arc::clone(&seen);
    let probe = target.clone();
    let _armed = serve_seams::arm(&target, Point::AfterServingOpen, move || {
        let attempt = crate::config_persistence::lock::lock_config_blocking_deferred(
            &probe,
            Instant::now(),
            |_| {},
        );
        *record.lock().expect("record") = Some(matches!(attempt, Err(NotLocked::Busy)));
    });
    let mut evaluated = super::serve_fixture::serve_load(ROW, &config).await;
    let env = Arc::new(evaluated.live_env());
    drop(
        Box::pin(super::serve_fixture::serve_build(
            ROW, evaluated, env, &config,
        ))
        .await,
    );
    assert_eq!(
        *seen.lock().expect("record"),
        Some(true),
        "{ROW}: the settle was reached, and with the lock held"
    );
}
