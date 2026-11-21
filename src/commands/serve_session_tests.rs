// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The serve load holds one startup session: the config lock is taken at the load and kept
//! through construction, and a config whose directory no writer can use starts only when no
//! config-write artifact sits beside it.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use crate::config_persistence::lock::{NotLocked, lock_config_deferred};
use crate::gateway::Gateway;
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

    let mut evaluated = super::load_for_serve(Some(&config))
        .await
        .unwrap_or_else(|error| panic!("{ROW}: the serve load succeeds: {error}"));
    assert!(held_elsewhere(&config).await, "{ROW}: held after the load");
    let env = Arc::new(evaluated.live_env());
    assert!(
        held_elsewhere(&config).await,
        "{ROW}: held after the environment hand-over"
    );
    let gateway = Gateway::new_evaluated(evaluated.config, env, Some(config.clone()))
        .await
        .unwrap_or_else(|error| panic!("{ROW}: the gateway builds: {error}"));
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

/// WIRE.6 / SERVE.5: the serve load reaches the startup gate, and construction finishes it.
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
    let load = load.split("\n}\n").next().expect("its body");
    assert!(
        load.contains("prepare_start"),
        "{ROW}: load_for_serve runs prepare_start"
    );
    let construct = read("src/gateway/server/construct.rs");
    assert!(
        construct.contains("finish_start("),
        "{ROW}: construction runs finish_start"
    );
}
