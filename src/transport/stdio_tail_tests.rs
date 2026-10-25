// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for what the stdio transport keeps from a child: the response
//! routing that refuses an inbound request, and the stderr tail and exit
//! status a failed start leaves for classifying it.
//!
//! Split out of `stdio_tests.rs` so both stay under the file-size ceiling
//! `scripts/dev/check-file-size.py` gates. A `#[path]` child of the
//! transport, like `stdio_tests.rs`, so `use super::*` resolves the same items.

use super::*;
use std::collections::HashMap;

/// An inbound request that happens to carry an `id` must never be routed to
/// a pending caller as if it were that caller's answer. The frame is a
/// server-to-client request (`sampling/createMessage`), not a response.
#[test]
fn handle_response_rejects_inbound_request_and_leaves_caller_pending() {
    // GIVEN: a caller waiting on id 5
    let t = StdioTransport::new(
        "echo",
        HashMap::new(),
        None,
        std::time::Duration::from_secs(30),
        None,
    );
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    t.pending.insert("5".to_string(), tx);

    // WHEN: the peer sends a *request* that reuses that id
    let json = r#"{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage","params":{}}"#;
    let outcome = t.handle_response(json);

    // THEN: the frame is refused, and the caller is still waiting
    assert!(
        outcome.is_err(),
        "a frame carrying `method` must not parse as a response"
    );
    assert!(rx.try_recv().is_err(), "caller must not be completed");
    assert!(
        t.pending.contains_key("5"),
        "caller must remain pending, not be silently consumed"
    );
}

// A child that answers nothing and dies with a reason on stderr: the shape a
// package manager produces when its install tree is unusable.
const DYING_CHILD: &str = r#"printf 'Error: Cannot find module %s\n' "'/root/.npm/_npx/1/node_modules/zod'" >&2
exit 3
"#;

/// A transport that runs `dying.sh` from `dir`.
fn dying_transport(dir: &std::path::Path) -> Arc<StdioTransport> {
    StdioTransport::new(
        "sh dying.sh",
        HashMap::new(),
        Some(dir.to_string_lossy().into_owned()),
        std::time::Duration::from_secs(5),
        None,
    )
}

/// Writes the dying child into a directory of its own, so tests running at
/// once never share one, and the directory goes when the test ends.
fn write_dying_child() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create the scratch directory");
    std::fs::write(dir.path().join("dying.sh"), DYING_CHILD).expect("write the dying child");
    dir
}

#[cfg(unix)]
#[tokio::test]
async fn a_failed_start_keeps_the_childs_stderr_for_classifying_it() {
    let dir = write_dying_child();
    let transport = dying_transport(dir.path());

    transport
        .start()
        .await
        .expect_err("a child that dies before the handshake cannot start");

    assert!(
        transport.stderr_tail().contains("Cannot find module"),
        "the tail is what tells a failed install from a backend that is merely dead, so a \
         failed start must leave it readable: {:?}",
        transport.stderr_tail()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_failed_start_records_how_the_child_exited() {
    let dir = write_dying_child();
    let transport = dying_transport(dir.path());

    transport
        .start()
        .await
        .expect_err("a child that dies before the handshake cannot start");

    let status = transport
        .exit_status()
        .expect("a failed start leaves the child's exit status readable");
    assert_eq!(
        status.code(),
        Some(3),
        "the status is the child's own, so a caller reports what actually happened: {status}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_start_drops_what_the_previous_attempt_said() {
    let dir = write_dying_child();
    let transport = dying_transport(dir.path());

    transport.start().await.expect_err("the child dies");
    assert!(
        !transport.stderr_tail().is_empty(),
        "the first attempt left a tail to drop"
    );

    // The same transport starts again, now running a child that exits
    // without a word: only the clearing can empty the tail.
    std::fs::write(dir.path().join("dying.sh"), "exit 3\n").expect("silence the child");
    transport
        .start()
        .await
        .expect_err("a child that exits before the handshake cannot start");
    assert!(
        transport.stderr_tail().is_empty(),
        "a start whose child said nothing must not report the previous attempt's words as \
         its own: {:?}",
        transport.stderr_tail()
    );
    assert!(
        transport.exit_status().is_some(),
        "the second attempt saw its own child exit"
    );
}
