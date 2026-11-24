// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! WIRE.4 / SERVE.3: one serving logger. A served gateway opens its audit log once, while it is
//! built; every metadata build after that reuses that one logger and never opens another.

use std::path::Path;
use std::sync::Arc;

use super::Gateway;
use crate::commands::serve_fixture::{serve_build, serve_load};
use crate::gateway::test_helpers::write_owner_only;
use crate::security::TransparencyLogger;
use crate::security::transparency_log::open_attempts;

const TOKEN: &str = "serving-log-row-token-0123456789abcdef";

/// A config file in `dir` with auth as given and the audit log at `log`, or logging off.
fn config_file(dir: &Path, auth: bool, log: Option<&Path>) -> std::path::PathBuf {
    let audit = match log {
        Some(path) => format!(
            "security:\n  transparency_log:\n    enabled: true\n    path: {:?}\n",
            path.display().to_string()
        ),
        None => "security:\n  transparency_log:\n    enabled: false\n".to_owned(),
    };
    let config = dir.join("gateway.yaml");
    write_owner_only(
        &config,
        format!("auth:\n  enabled: {auth}\n  bearer_token: \"{TOKEN}\"\n{audit}"),
    )
    .expect("config");
    config
}

async fn served(row: &str, config: &Path) -> Gateway {
    let mut evaluated = serve_load(row, config).await;
    let env = Arc::new(evaluated.live_env());
    Box::pin(serve_build(row, evaluated, env, config)).await
}

fn one_logger(
    left: Option<&Arc<TransparencyLogger>>,
    right: Option<&Arc<TransparencyLogger>>,
) -> bool {
    matches!((left, right), (Some(left), Some(right)) if Arc::ptr_eq(left, right))
}

/// Logging on: one open, and both metadata builds hold the logger the build of the gateway
/// opened. Logging off: no logger in either build. A best-effort open (auth off) that fails while
/// the gateway is built, with the path openable afterwards: the builds still open nothing.
#[tokio::test]
async fn startup_one_logger() {
    const ROW: &str = "startup_one_logger";

    let dir = crate::test_dir_keep::kept_tempdir();
    let log = dir.path().join("audit.jsonl");
    let gateway = Box::pin(served(ROW, &config_file(dir.path(), true, Some(&log)))).await;
    let first = gateway.build_meta_mcp().await;
    let second = gateway.build_meta_mcp().await;
    let opened = open_attempts::at(&log);
    let first = first.unwrap_or_else(|error| panic!("{ROW} on: first build: {error}"));
    let second = second
        .unwrap_or_else(|error| panic!("{ROW} on: second build, {opened} opens so far: {error}"));
    assert_eq!(opened, 1, "{ROW} on: the log is opened once");
    assert!(
        one_logger(
            first.transparency_log.as_ref(),
            second.transparency_log.as_ref()
        ),
        "{ROW} on: both builds hold one logger"
    );
    drop((first, second, gateway));

    let dir = tempfile::tempdir().expect("tempdir");
    let gateway = Box::pin(served(ROW, &config_file(dir.path(), false, None))).await;
    for build in 0..2 {
        let built = gateway
            .build_meta_mcp()
            .await
            .unwrap_or_else(|error| panic!("{ROW} off: build {build}: {error}"));
        assert!(
            built.transparency_log.is_none(),
            "{ROW} off: build {build} has no logger"
        );
    }
    drop(gateway);

    let dir = crate::test_dir_keep::kept_tempdir();
    let blocker = dir.path().join("not-a-dir");
    std::fs::write(&blocker, b"x").expect("a file where the log's folder should be");
    let log = blocker.join("audit.jsonl");
    let gateway = Box::pin(served(ROW, &config_file(dir.path(), false, Some(&log)))).await;
    std::fs::remove_file(&blocker).expect("remove the file");
    std::fs::create_dir(&blocker).expect("the log's folder exists now");
    for build in 0..2 {
        let built = gateway
            .build_meta_mcp()
            .await
            .unwrap_or_else(|error| panic!("{ROW} failed open: build {build}: {error}"));
        assert!(
            built.transparency_log.is_none(),
            "{ROW} failed open: build {build} has no logger"
        );
    }
    assert_eq!(
        open_attempts::at(&log),
        1,
        "{ROW} failed open: only the gateway build tried the log"
    );
}

/// The construction data-directory seam puts back what it found: an inner guard restores the
/// outer guard's folder, and once the outer one drops, seams built on this thread name none, so
/// nothing reaches a later test that runs on the same thread.
#[test]
fn construction_data_dir_guards_restore_what_they_found() {
    use super::test_seams::{TestSeams, data_dir_for_constructions};
    const ROW: &str = "construction_data_dir_guards_restore_what_they_found";
    let outer = std::path::PathBuf::from("outer-folder");
    let inner = std::path::PathBuf::from("inner-folder");
    assert_eq!(
        TestSeams::new().data_dir,
        None,
        "{ROW}: premise: no guard yet"
    );
    let outer_guard = data_dir_for_constructions(outer.clone());
    let inner_guard = data_dir_for_constructions(inner.clone());
    assert_eq!(
        TestSeams::new().data_dir,
        Some(inner),
        "{ROW}: the inner guard wins"
    );
    drop(inner_guard);
    assert_eq!(
        TestSeams::new().data_dir,
        Some(outer),
        "{ROW}: dropping the inner guard brings the outer folder back"
    );
    drop(outer_guard);
    assert_eq!(
        TestSeams::new().data_dir,
        None,
        "{ROW}: with both guards gone, a new construction has no folder set"
    );
}
