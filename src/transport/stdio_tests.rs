// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Failed-start tests for the package-cache repair (#4066). v3.5.1's own
//! stdio tests stay inline in `stdio.rs`.

use super::*;
use std::collections::HashMap;
use std::sync::Arc;

// A child that answers nothing and dies with a reason on stderr: the shape a
// package manager produces when its install tree is unusable.
const DYING_CHILD: &str = r#"printf 'Error: Cannot find module %s\n' "'/root/.npm/_npx/1/node_modules/zod'" >&2
exit 3
"#;

fn dying_transport(dir: &std::path::Path) -> Arc<StdioTransport> {
    StdioTransport::new(
        "sh dying.sh",
        HashMap::new(),
        Some(dir.to_string_lossy().into_owned()),
        std::time::Duration::from_secs(5),
        None,
    )
}

/// Writes the dying child into its own scratch directory, so tests running in
/// parallel never share or rewrite one script.
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

    // The same transport starts again with its working directory gone, so it
    // fails before it spawns anything and nothing overwrites the tail: only
    // the clearing can empty it.
    let path = dir.path().to_path_buf();
    dir.close().expect("remove the scratch directory");
    assert!(!path.exists());
    transport
        .start()
        .await
        .expect_err("a start in a missing directory cannot spawn");
    assert!(
        transport.stderr_tail().is_empty(),
        "a start that never spawned reads nothing from a child, so it must not report the \
         previous attempt's words as its own"
    );
}

// A child that answers `initialize` with an error and stays alive: the late
// failure path, where the gateway itself has to kill it.
const REFUSING_CHILD: &str = r#"read -r request
id=${request#*'"id":'}
id=${id%%,*}
printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"no"}}\n' "$id"
while read -r _; do :; done
"#;

#[cfg(unix)]
#[tokio::test]
async fn a_late_failure_records_the_ending_of_the_child_it_killed() {
    let dir = tempfile::tempdir().expect("scratch");
    std::fs::write(dir.path().join("refusing.sh"), REFUSING_CHILD).expect("write the child");
    let transport = StdioTransport::new(
        "sh refusing.sh",
        HashMap::new(),
        Some(dir.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(5),
        None,
    );

    let error = transport
        .start()
        .await
        .expect_err("a refused handshake cannot start");

    assert!(
        matches!(error, crate::Error::Protocol(_)),
        "the start failed on the refused handshake, not on a timeout: {error:?}"
    );
    assert!(
        transport.exit_status().is_some(),
        "the child the failure killed has an ending to report, not \"running\""
    );
}
