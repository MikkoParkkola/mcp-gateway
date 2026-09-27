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
use crate::transport::{StdioTransport, Transport};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The key the gateway assigns per backend.
const CACHE_ENV: &str = "npm_config_cache";

const SPAWN_LOG: &str = "MCP_GATEWAY_TEST_SPAWN_LOG";
const SPAWN_MODE: &str = "MCP_GATEWAY_TEST_SPAWN_MODE";
const SPAWN_FAILURE: &str = "MCP_GATEWAY_TEST_SPAWN_FAILURE";

/// A real npx-style start failure: the tree under the assigned cache is missing.
const CACHE_SHAPED: &str = "Cannot find module '/cache/_npx/1/node_modules/zod/v3/index.js'";
/// A failure a fresh install cannot fix.
const UNRELATED: &str = "backend exploded during startup";

const SEEDED: &str = "seeded-by-the-test";

/// Answers the handshake, injects the failure as a JSON-RPC error frame, and
/// counts its own spawns in `$SPAWN_LOG` so the *number of calls to the inner
/// start* is observable from outside the transport.
const STUB: &str = r#"count=0
if [ -f "$MCP_GATEWAY_TEST_SPAWN_LOG" ]; then
    count=$(wc -l < "$MCP_GATEWAY_TEST_SPAWN_LOG")
fi
printf 'spawned\n' >> "$MCP_GATEWAY_TEST_SPAWN_LOG"
count=$((count + 1))

while IFS= read -r request; do
    case "$request" in
    *'"method":"initialize"'*)
        id=${request#*'"id":'}
        id=${id%%,*}
        fail=0
        case "$MCP_GATEWAY_TEST_SPAWN_MODE" in
        always-fail) fail=1 ;;
        fail-once) if [ "$count" -eq 1 ]; then fail=1; fi ;;
        esac
        if [ "$fail" -eq 1 ]; then
            printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"%s attempt %s"}}\n' "$id" "$MCP_GATEWAY_TEST_SPAWN_FAILURE" "$count"
        else
            printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25"}}\n' "$id"
        fi
        ;;
    esac
done
"#;

/// Dies before the handshake, reporting the same cache-shaped text on stderr.
const DYING_STUB: &str = r#"printf 'spawned\n' >> "$MCP_GATEWAY_TEST_SPAWN_LOG"
printf 'Error: Cannot find module %s\n' "'/cache/_npx/1/node_modules/zod/v3/index.js'" >&2
exit 1
"#;

/// Dies before the handshake for a reason no install can fix.
const DYING_UNRELATED_STUB: &str = r#"printf 'spawned\n' >> "$MCP_GATEWAY_TEST_SPAWN_LOG"
printf 'Error: %s\n' "$MCP_GATEWAY_TEST_SPAWN_FAILURE" >&2
exit 1
"#;

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

/// A cache of the shape the gateway creates: below `pkg-cache`, which is the
/// only place `clear_package_cache` is allowed to delete.
fn seed_cache(_workspace: &Path) -> SeededCache {
    let root = crate::config_persistence::gateway_data_dir()
        .join("pkg-cache")
        .join(unique_leaf());
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

fn transport(
    workspace: &Path,
    env: HashMap<String, String>,
    request_timeout: Duration,
) -> Arc<StdioTransport> {
    StdioTransport::new(
        "sh server.sh",
        env,
        Some(workspace.to_string_lossy().into_owned()),
        request_timeout,
        None,
    )
}

fn assert_caller_sees(error: &Error, needle: &str) {
    let text = error.to_string();
    assert!(
        text.contains(needle),
        "the caller must see the original failure text ({needle}): {text}"
    );
}

#[tokio::test]
async fn a_cache_shaped_failure_clears_the_cache_and_retries_exactly_once() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let mut env = stub_env(&log, "always-fail", CACHE_SHAPED);
    env.insert(
        CACHE_ENV.to_string(),
        cache.root.to_string_lossy().into_owned(),
    );

    let transport = transport(workspace.path(), env, Duration::from_secs(5));

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
    assert_caller_sees(&error, "attempt 2");
    assert_caller_sees(&error, "Cannot find module");
}

#[tokio::test]
async fn a_non_cache_shaped_failure_is_returned_unchanged_without_a_retry() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let mut env = stub_env(&log, "always-fail", UNRELATED);
    env.insert(
        CACHE_ENV.to_string(),
        cache.root.to_string_lossy().into_owned(),
    );

    let error = start_with_repair(&transport(workspace.path(), env, Duration::from_secs(5)))
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
    assert_caller_sees(&error, "attempt 1");
    assert_caller_sees(&error, UNRELATED);
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
    let pkg_cache = crate::config_persistence::gateway_data_dir().join("pkg-cache");
    std::fs::create_dir_all(&pkg_cache).expect("create pkg-cache root");
    let cache = pkg_cache.join(unique_leaf());
    std::fs::write(&cache, SEEDED).expect("write the path the cache variable points at");
    let log = workspace.path().join("spawns.log");
    let mut env = stub_env(&log, "always-fail", CACHE_SHAPED);
    env.insert(CACHE_ENV.to_string(), cache.to_string_lossy().into_owned());

    let error = start_with_repair(&transport(workspace.path(), env, Duration::from_secs(5)))
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
    assert_caller_sees(&error, "attempt 1");
}

#[tokio::test]
async fn a_retry_that_succeeds_reports_success_to_the_caller() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let mut env = stub_env(&log, "fail-once", CACHE_SHAPED);
    env.insert(
        CACHE_ENV.to_string(),
        cache.root.to_string_lossy().into_owned(),
    );

    let transport = transport(workspace.path(), env, Duration::from_secs(5));
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
    let mut env = stub_env(&log, "always-ok", UNRELATED);
    env.insert(
        CACHE_ENV.to_string(),
        cache.root.to_string_lossy().into_owned(),
    );

    let transport = transport(workspace.path(), env, Duration::from_secs(5));
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
    );
    let error = start_with_repair(&transport)
        .await
        .expect_err("the backend is broken for good, so start must fail");

    assert_eq!(
        spawns(&log).len(),
        1,
        "with no cache assigned there is nothing to clear, so nothing is retried"
    );
    assert_caller_sees(&error, "attempt 1");
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
    let mut env = stub_env(&log, "always-fail", CACHE_SHAPED);
    env.insert(
        CACHE_ENV.to_string(),
        cache.root.to_string_lossy().into_owned(),
    );

    // This is how a package manager reports an unusable install: the reason on
    // stderr, no frame, a non-zero exit. Nothing in the transport's own error
    // says `Cannot find module`, so the retry can only fire if the child's
    // stderr is part of what the classifier judges.
    let error = start_with_repair(&transport(workspace.path(), env, Duration::from_secs(5)))
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
    let mut env = stub_env(&log, "always-fail", UNRELATED);
    env.insert(
        CACHE_ENV.to_string(),
        cache.root.to_string_lossy().into_owned(),
    );

    let error = start_with_repair(&transport(workspace.path(), env, Duration::from_secs(5)))
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
async fn an_operators_own_cache_is_never_cleared() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), DYING_STUB);
    let outside = workspace.path().join("operator-cache");
    let marker = outside.join("_npx/1/marker");
    std::fs::create_dir_all(marker.parent().expect("marker parent"))
        .expect("create operator cache");
    std::fs::write(&marker, SEEDED).expect("seed marker");
    let log = workspace.path().join("spawns.log");
    let mut env = stub_env(&log, "always-fail", CACHE_SHAPED);
    env.insert(
        CACHE_ENV.to_string(),
        outside.to_string_lossy().into_owned(),
    );

    let _ = start_with_repair(&transport(workspace.path(), env, Duration::from_secs(5))).await;

    assert_eq!(
        spawns(&log).len(),
        1,
        "a cache the gateway did not create is not the gateway's to delete"
    );
    assert_eq!(
        std::fs::read_to_string(&marker).expect("the operator's cache is untouched"),
        SEEDED,
        "the gateway deletes only the caches it created"
    );
}
