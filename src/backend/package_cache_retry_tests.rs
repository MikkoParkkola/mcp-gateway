// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! End-to-end tests for the `start()` package-cache retry contract.
//!
//! The decision under test — clear the cache and retry exactly once — only
//! happens inside a real `start()`, so these tests drive a real `start()` over
//! a stub child instead of calling the classifier in isolation. Each stub
//! appends one line per spawn, which makes the log's length the number of calls
//! to the inner `start_once`: one means no retry, two means exactly one, and
//! three would be the loop this contract exists to prevent.
//!
//! The stub is a `sh` script that answers the frames the handshake needs and
//! reports the failure as a JSON-RPC error frame, or — the way a real package
//! manager reports an unusable install — prints the reason on stderr and dies
//! before answering anything. Both routes are covered, because the classifier
//! judges the transport's error text and the child's stderr tail together.
//!
//! A `#[path]` child of the module under test, so `use super::*` resolves to
//! its items and nothing had to be widened to test them.

#![cfg(unix)]

use super::*;
use crate::transport::{
    StdioTransport, Transport, assigned_package_cache_dir, isolated_package_manager_env,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[path = "package_cache_race_tests.rs"]
mod race;

#[path = "package_cache_log_tests.rs"]
mod logging;

#[path = "package_cache_stubs_tests.rs"]
mod stubs;
use stubs::{DYING_STUB, DYING_UNRELATED_STUB, LEAKY_DYING_STUB, STUB};

/// The key the gateway assigns per backend.
const CACHE_ENV: &str = "npm_config_cache";

/// The backend and command the assignment is asked about in the tests that
/// drive the real decision: a name of this test file's own, and a command that
/// invokes npm, so `assigned_package_cache_dir` answers for itself.
const BACKEND: &str = "cache-retry-test";
const NPM_COMMAND: &str = "npx -y some-mcp-server";

const SPAWN_LOG: &str = "MCP_GATEWAY_TEST_SPAWN_LOG";
const SPAWN_MODE: &str = "MCP_GATEWAY_TEST_SPAWN_MODE";
const SPAWN_FAILURE: &str = "MCP_GATEWAY_TEST_SPAWN_FAILURE";

/// A real npx-style start failure: the tree under the assigned cache is missing.
const CACHE_SHAPED: &str = "Cannot find module '/cache/_npx/1/node_modules/zod/v3/index.js'";
/// A failure a fresh install cannot fix.
const UNRELATED: &str = "backend exploded during startup";

const SEEDED: &str = "seeded-by-the-test";

struct SeededCache {
    root: PathBuf,
    sentinel: PathBuf,
}

fn unique_leaf() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    format!(
        "cache-retry-test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// The root the gateway owns, as a test's own temporary directory.
///
/// A test that pointed at the running gateway's data directory would clear a
/// real backend's cache, so every seed goes under a root the test owns.
fn temp_root(workspace: &Path) -> PathBuf {
    let root = workspace.join("pkg-cache");
    std::fs::create_dir_all(&root).expect("create owned root");
    root
}

fn seed_cache(workspace: &Path) -> SeededCache {
    let root = temp_root(workspace).join(unique_leaf());
    let sentinel_dir = root.join("_npx/1/node_modules/zod");
    std::fs::create_dir_all(&sentinel_dir).expect("create cache tree");
    let sentinel = sentinel_dir.join("index.js");
    std::fs::write(&sentinel, SEEDED).expect("seed cache file");
    SeededCache { root, sentinel }
}

impl Drop for SeededCache {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write_stub(workspace: &Path, script: &str) -> PathBuf {
    let server = workspace.join("server.sh");
    std::fs::write(&server, script).expect("write stub server");
    server
}

/// One line per spawn of the inner start; the length is the retry count.
fn spawns(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .map(|text| text.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

fn stub_env(log: &Path, mode: &str, failure: &str) -> HashMap<String, String> {
    HashMap::from([
        (SPAWN_LOG.to_string(), log.to_string_lossy().into_owned()),
        (SPAWN_MODE.to_string(), mode.to_string()),
        (SPAWN_FAILURE.to_string(), failure.to_string()),
    ])
}

/// The environment the child is given, with `npm_config_cache` set to the path
/// the test wants the repair to see.
fn env_with_cache(log: &Path, mode: &str, failure: &str, cache: &Path) -> HashMap<String, String> {
    let mut env = stub_env(log, mode, failure);
    env.insert(CACHE_ENV.to_string(), cache.to_string_lossy().into_owned());
    env
}

/// The transport a start is driven through, with the environment the child
/// runs under and the cache the gateway is told it assigned.
fn transport(
    workspace: &Path,
    env: HashMap<String, String>,
    request_timeout: Duration,
    assigned_cache: Option<&Path>,
) -> Arc<StdioTransport> {
    StdioTransport::new_with_assigned_cache(
        "sh server.sh",
        env,
        Some(workspace.to_string_lossy().into_owned()),
        request_timeout,
        None,
        assigned_cache.map(Path::to_path_buf),
    )
}

/// The failure the last start reported, read from the child's stderr tail.
///
/// An `initialize` error here carries the backend's error code only, never its
/// message (it may quote back a credential), so the text the stub chose is
/// asserted where the classifier reads it.
fn assert_last_attempt_said(transport: &StdioTransport, needle: &str) {
    let text = transport.stderr_tail();
    assert!(
        text.contains(needle),
        "the last attempt must have reported the original failure ({needle}): {text}"
    );
}

#[tokio::test]
async fn a_cache_shaped_failure_clears_the_cache_and_retries_exactly_once() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let env = env_with_cache(&log, "always-fail", CACHE_SHAPED, &cache.root);

    let transport = transport(
        workspace.path(),
        env,
        Duration::from_secs(5),
        Some(&cache.root),
    );

    let error = start_with_repair(&transport)
        .await
        .expect_err("every start fails here, so the caller must see an error");

    assert_eq!(
        spawns(&log).len(),
        2,
        "a cache-shaped failure must spawn exactly twice: the original start and ONE retry"
    );
    assert!(
        !cache.root.exists(),
        "the cache is cleared before the retry respawns"
    );
    assert!(matches!(error, Error::Protocol(_)), "{error:?}");
    assert_last_attempt_said(&transport, "attempt 2");
    assert_last_attempt_said(&transport, "Cannot find module");
}

#[tokio::test]
async fn a_non_cache_shaped_failure_is_returned_unchanged_without_a_retry() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let env = env_with_cache(&log, "always-fail", UNRELATED, &cache.root);

    let transport = transport(
        workspace.path(),
        env,
        Duration::from_secs(5),
        Some(&cache.root),
    );
    let error = start_with_repair(&transport)
        .await
        .expect_err("the backend is broken for good, so start must fail");

    assert_eq!(
        spawns(&log).len(),
        1,
        "an unrelated failure must not be retried"
    );
    assert!(
        matches!(error, Error::Protocol(_)),
        "the original error is returned as-is, not re-shaped by a retry: {error:?}"
    );
    assert_last_attempt_said(&transport, "attempt 1");
    assert_last_attempt_said(&transport, UNRELATED);
    assert_eq!(
        std::fs::read_to_string(&cache.sentinel).expect("the cache tree is untouched"),
        SEEDED,
        "an unrelated failure must not throw away a working install"
    );
}

#[tokio::test]
async fn a_cache_that_cannot_be_removed_is_not_retried() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    // Not a directory, so remove_dir_all cannot succeed however the test runs
    // (a permission-based "cannot remove" depends on the caller's uid). It
    // lives under pkg-cache so this exercises the removal, not the ownership
    // check that would reject the path first.
    let cache = temp_root(workspace.path()).join(unique_leaf());
    std::fs::write(&cache, SEEDED).expect("write the path the cache variable points at");
    let log = workspace.path().join("spawns.log");
    let env = env_with_cache(&log, "always-fail", CACHE_SHAPED, &cache);

    let transport = transport(workspace.path(), env, Duration::from_secs(5), Some(&cache));
    let error = start_with_repair(&transport)
        .await
        .expect_err("the backend is broken for good, so start must fail");

    assert_eq!(
        spawns(&log).len(),
        1,
        "no retry when the cache it would retry with could not be cleared"
    );
    assert!(
        cache.is_file(),
        "the caller's path must not be deleted out from under it"
    );
    assert!(matches!(error, Error::Protocol(_)), "{error:?}");
    assert_last_attempt_said(&transport, "attempt 1");
}

#[tokio::test]
async fn a_removal_that_failed_does_not_use_up_the_repair() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    // The first start finds a path the removal refuses, so it is not retried.
    let cache = temp_root(workspace.path()).join(unique_leaf());
    std::fs::write(&cache, SEEDED).expect("write a regular file where the cache goes");
    let log = workspace.path().join("spawns.log");

    let first = transport(
        workspace.path(),
        env_with_cache(&log, "always-fail", CACHE_SHAPED, &cache),
        Duration::from_secs(5),
        Some(&cache),
    );
    let _ = start_with_repair(&first)
        .await
        .expect_err("the stub fails on every attempt");
    assert_eq!(
        spawns(&log).len(),
        1,
        "nothing was retried against a cache that is still there"
    );

    // The path becomes a cache the removal can clear. The start that could not
    // be repaired never happened, so this one still gets its repair.
    std::fs::remove_file(&cache).expect("clear the file");
    std::fs::create_dir_all(cache.join("_npx/1")).expect("create the cache tree");

    let second = transport(
        workspace.path(),
        env_with_cache(&log, "always-fail", CACHE_SHAPED, &cache),
        Duration::from_secs(5),
        Some(&cache),
    );
    let _ = start_with_repair(&second)
        .await
        .expect_err("the stub fails on every attempt");

    assert_eq!(
        spawns(&log).len(),
        3,
        "a repair that never happened must not latch, so the next start is repaired: {:#?}",
        spawns(&log)
    );
    assert!(!cache.exists(), "and that repair clears the cache");
}

#[tokio::test]
async fn a_retry_that_succeeds_reports_success_to_the_caller() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let env = env_with_cache(&log, "fail-once", CACHE_SHAPED, &cache.root);

    let transport = transport(
        workspace.path(),
        env,
        Duration::from_secs(5),
        Some(&cache.root),
    );
    let result = start_with_repair(&transport).await;

    assert_eq!(
        spawns(&log).len(),
        2,
        "the first start failed, the second must be the retry"
    );
    assert!(
        !cache.root.exists(),
        "the cache was cleared before the retry that succeeded"
    );
    assert!(
        result.is_ok(),
        "a retry that succeeds is a successful start, not a reported failure: {result:?}"
    );
    assert!(
        transport.is_connected(),
        "the transport the retry brought up is connected"
    );

    transport.close().await.expect("close");
}

#[tokio::test]
async fn a_first_start_that_succeeds_never_touches_the_cache() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let env = env_with_cache(&log, "always-ok", UNRELATED, &cache.root);

    let transport = transport(
        workspace.path(),
        env,
        Duration::from_secs(5),
        Some(&cache.root),
    );
    let result = start_with_repair(&transport).await;

    assert!(
        result.is_ok(),
        "the stub answers the handshake, so the first start succeeds: {result:?}"
    );
    assert_eq!(spawns(&log).len(), 1, "a successful start is never retried");
    assert_eq!(
        std::fs::read_to_string(&cache.sentinel).expect("the cache tree is still there"),
        SEEDED,
        "a successful start must leave the install alone"
    );

    transport.close().await.expect("close");
}

#[tokio::test]
async fn a_cache_shaped_failure_without_an_assigned_cache_is_not_retried() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    // Nothing assigns this one; it stands in for any unrelated path a wrong
    // fallback might reach for.
    let unrelated = workspace.path().join("unrelated");
    std::fs::create_dir_all(&unrelated).expect("create unrelated tree");
    let bystander = unrelated.join("keep.txt");
    std::fs::write(&bystander, SEEDED).expect("seed unrelated tree");
    let log = workspace.path().join("spawns.log");

    let transport = transport(
        workspace.path(),
        stub_env(&log, "always-fail", CACHE_SHAPED),
        Duration::from_secs(5),
        None,
    );
    let error = start_with_repair(&transport)
        .await
        .expect_err("the backend is broken for good, so start must fail");

    assert_eq!(
        spawns(&log).len(),
        1,
        "with no cache assigned there is nothing to clear, so nothing is retried"
    );
    assert!(matches!(error, Error::Protocol(_)), "{error:?}");
    assert_last_attempt_said(&transport, "attempt 1");
    assert_eq!(
        std::fs::read_to_string(&bystander).expect("an unassigned path is never touched"),
        SEEDED
    );
}

#[tokio::test]
async fn a_backend_that_dies_reporting_a_missing_module_retries_itself() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), DYING_STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let env = env_with_cache(&log, "always-fail", CACHE_SHAPED, &cache.root);

    // This is how a package manager reports an unusable install: the reason on
    // stderr, no frame, a non-zero exit. Nothing in the transport's own error
    // says `Cannot find module`, so the retry can only fire if the child's
    // stderr is part of what the classifier judges.
    let error = start_with_repair(&transport(
        workspace.path(),
        env,
        Duration::from_secs(5),
        Some(&cache.root),
    ))
    .await
    .expect_err("the stub dies on every attempt");

    assert!(
        matches!(error, Error::BackendTimeout(_) | Error::Transport(_)),
        "the caller still sees the transport error, not a synthesised one: {error:?}"
    );
    assert_eq!(
        spawns(&log).len(),
        2,
        "a death that names a missing module is a failed install, so it is cleared and retried \
         once: {error}"
    );
    assert!(
        !cache.root.exists(),
        "the cache is what was cleared between the two attempts"
    );
}

#[tokio::test]
async fn a_backend_that_dies_for_an_unrelated_reason_is_not_retried() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), DYING_UNRELATED_STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let env = env_with_cache(&log, "always-fail", UNRELATED, &cache.root);

    let error = start_with_repair(&transport(
        workspace.path(),
        env,
        Duration::from_secs(5),
        Some(&cache.root),
    ))
    .await
    .expect_err("the stub dies on every attempt");

    assert_eq!(
        spawns(&log).len(),
        1,
        "a death that says nothing about the install is not a reason to reinstall: {error}"
    );
    assert!(
        cache.root.exists(),
        "an untouched install is not cleared for a failure no install can fix"
    );
}

#[tokio::test]
async fn an_operators_cache_under_pkg_cache_is_never_cleared() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), DYING_STUB);
    // A path of the shape the gateway assigns, under the root it owns, set by
    // the backend's own `env:` — which is what makes it the operator's, not
    // the gateway's, however much it looks like the gateway's.
    let outside = temp_root(workspace.path()).join("the-operators-own");
    let marker = outside.join("_npx/1/marker");
    std::fs::create_dir_all(marker.parent().expect("marker parent"))
        .expect("create operator cache");
    std::fs::write(&marker, SEEDED).expect("seed marker");
    let log = workspace.path().join("spawns.log");

    let operator_env = HashMap::from([(
        CACHE_ENV.to_string(),
        outside.to_string_lossy().into_owned(),
    )]);
    let assigned = assigned_package_cache_dir(BACKEND, NPM_COMMAND, &operator_env);
    assert!(
        assigned.is_none(),
        "the gateway assigns nothing when the backend's environment already names a cache"
    );
    let mut env = stub_env(&log, "always-fail", CACHE_SHAPED);
    env.extend(isolated_package_manager_env(
        BACKEND,
        NPM_COMMAND,
        operator_env,
    ));

    let _ = start_with_repair(&transport(
        workspace.path(),
        env,
        Duration::from_secs(5),
        assigned.as_deref(),
    ))
    .await;

    assert_eq!(
        spawns(&log).len(),
        1,
        "a cache the gateway did not assign is not the gateway's to delete"
    );
    assert_eq!(
        std::fs::read_to_string(&marker).expect("the operator's cache is untouched"),
        SEEDED,
        "the gateway deletes only the caches it assigned"
    );
}

#[tokio::test]
async fn an_operator_cache_written_with_a_trailing_separator_is_never_cleared() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), DYING_STUB);
    // `…/pkg-cache/<backend>/` reads as one path component below the root, and
    // the trailing separator is exactly what makes the OS resolve the final
    // component: with a symlink there, a removal that followed it would delete
    // the contents of the link's target.
    let outside = workspace.path().join("operator-cache-target");
    let sentinel = outside.join("node_modules/zod.js");
    std::fs::create_dir_all(sentinel.parent().expect("sentinel parent"))
        .expect("create the operator's tree");
    std::fs::write(&sentinel, SEEDED).expect("seed the operator's tree");
    let leaf = temp_root(workspace.path()).join("the-operators-own");
    symlink(&outside, &leaf).expect("link the cache path at the operator's tree");
    let log = workspace.path().join("spawns.log");

    let operator_env = HashMap::from([(CACHE_ENV.to_string(), format!("{}/", leaf.display()))]);
    let assigned = assigned_package_cache_dir(BACKEND, NPM_COMMAND, &operator_env);
    assert!(
        assigned.is_none(),
        "a value the operator wrote is not one the gateway assigned, separator or not"
    );
    let mut env = stub_env(&log, "always-fail", CACHE_SHAPED);
    env.extend(isolated_package_manager_env(
        BACKEND,
        NPM_COMMAND,
        operator_env,
    ));

    let _ = start_with_repair(&transport(
        workspace.path(),
        env,
        Duration::from_secs(5),
        assigned.as_deref(),
    ))
    .await;

    assert_eq!(
        spawns(&log).len(),
        1,
        "no retry against a path this gateway never assigned"
    );
    assert_eq!(
        std::fs::read_to_string(&sentinel).expect("the link's target is untouched"),
        SEEDED,
        "and nothing behind the link is deleted"
    );
    assert!(
        std::fs::symlink_metadata(&leaf).is_ok(),
        "the link itself is left where the operator put it"
    );
}

#[tokio::test]
async fn an_assigned_cache_that_is_a_symlink_is_not_followed() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), DYING_STUB);
    // The gateway assigned this path, so provenance alone says it may be
    // cleared. A link at the leaf is what the removal has to refuse: following
    // it would delete a tree the gateway was never given.
    let outside = workspace.path().join("link-target");
    let sentinel = outside.join("node_modules/zod.js");
    std::fs::create_dir_all(sentinel.parent().expect("sentinel parent"))
        .expect("create the linked tree");
    std::fs::write(&sentinel, SEEDED).expect("seed the linked tree");
    let leaf = temp_root(workspace.path()).join(unique_leaf());
    symlink(&outside, &leaf).expect("link the cache path at another tree");
    let log = workspace.path().join("spawns.log");
    let env = env_with_cache(&log, "always-fail", CACHE_SHAPED, &leaf);

    let error = start_with_repair(&transport(
        workspace.path(),
        env,
        Duration::from_secs(5),
        Some(&leaf),
    ))
    .await
    .expect_err("the stub dies on every attempt");

    assert_eq!(
        spawns(&log).len(),
        1,
        "a cache that could not be cleared is not retried: {error}"
    );
    assert_eq!(
        std::fs::read_to_string(&sentinel).expect("the linked tree is untouched"),
        SEEDED,
        "the link is not a cache the gateway created, and its target is not deleted"
    );
    assert!(
        std::fs::symlink_metadata(&leaf).is_ok(),
        "and the link is still where it was"
    );
}

#[tokio::test]
async fn a_cache_is_cleared_once_until_a_start_succeeds() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let path = cache.root.clone();

    let env = |mode: &str| env_with_cache(&log, mode, CACHE_SHAPED, &path);
    let start = |mode: &str| {
        transport(
            workspace.path(),
            env(mode),
            Duration::from_secs(5),
            Some(&path),
        )
    };

    // First failure: the cache is cleared and the start is retried.
    let first = start("always-fail");
    let _ = start_with_repair(&first)
        .await
        .expect_err("the stub fails on every attempt");
    assert!(
        !path.exists(),
        "the first cache-shaped failure clears the cache"
    );

    // A restart builds a new transport for the same backend. Its cache is
    // healthy by then — reinstalling per restart is the behaviour this latch
    // exists to prevent.
    std::fs::create_dir_all(path.join("_npx/1")).expect("re-seed the cache tree");
    let second = start("always-fail");
    let _ = start_with_repair(&second)
        .await
        .expect_err("the stub fails on every attempt");
    assert!(
        path.exists(),
        "a cache is cleared once until a start succeeds, not once per restart"
    );

    // A start that succeeds arms the next repair.
    let good = start("always-ok");
    start_with_repair(&good)
        .await
        .expect("the stub answers the handshake");

    let third = start("always-fail");
    let _ = start_with_repair(&third)
        .await
        .expect_err("the stub fails on every attempt");
    assert!(!path.exists(), "a start that succeeds arms the next repair");
}

#[tokio::test]
async fn an_assignment_the_child_never_received_is_not_cleared() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");

    // The transport is told it assigned `cache.root`, but the child's
    // environment names no cache at all, so the child never used it.
    let transport = transport(
        workspace.path(),
        stub_env(&log, "always-fail", CACHE_SHAPED),
        Duration::from_secs(5),
        Some(&cache.root),
    );
    let _ = start_with_repair(&transport)
        .await
        .expect_err("the stub fails on every attempt");

    assert_eq!(
        spawns(&log).len(),
        1,
        "nothing the child used, nothing to retry"
    );
    assert_eq!(
        std::fs::read_to_string(&cache.sentinel).expect("the assignment is untouched"),
        SEEDED
    );
}

#[tokio::test]
async fn a_retry_that_succeeds_arms_the_next_repair() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let path = cache.root.clone();
    let start = |log: &Path, mode: &str| {
        transport(
            workspace.path(),
            env_with_cache(log, mode, CACHE_SHAPED, &path),
            Duration::from_secs(5),
            Some(&path),
        )
    };

    let first_log = workspace.path().join("first.log");
    let first = start(&first_log, "fail-once");
    start_with_repair(&first)
        .await
        .expect("the retry after the repair succeeds");
    first.close().await.expect("close");

    // No start succeeds in between other than that retry.
    std::fs::create_dir_all(path.join("_npx/1")).expect("re-seed the cache tree");
    let second_log = workspace.path().join("second.log");
    let second = start(&second_log, "always-fail");
    let _ = start_with_repair(&second)
        .await
        .expect_err("the stub fails on every attempt");
    assert_eq!(
        spawns(&second_log).len(),
        2,
        "the next failure is repaired again"
    );
    assert!(!path.exists(), "a retry that succeeds arms the next repair");
}
