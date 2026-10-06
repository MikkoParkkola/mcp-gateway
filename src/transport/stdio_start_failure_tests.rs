// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a failed start leaves for classifying it: the stderr tail and the
//! child's exit status (#1759).

use std::collections::HashMap;
use std::sync::Arc;

use super::StdioTransport;

// A child that answers nothing and dies with a reason on stderr: the shape a
// package manager produces when its install tree is unusable.
const DYING_CHILD: &str = r#"printf 'Error: Cannot find module %s\n' "'/root/.npm/_npx/1/node_modules/zod'" >&2
exit 3
"#;

fn dying_transport() -> Arc<StdioTransport> {
    StdioTransport::new(
        "sh dying.sh",
        HashMap::new(),
        Some(
            std::env::temp_dir()
                .join(format!("stdio-tail-{}", std::process::id()))
                .to_string_lossy()
                .into_owned(),
        ),
        std::time::Duration::from_secs(5),
        None,
    )
}

/// Writes the dying child where `dying_transport` runs it.
fn write_dying_child() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("stdio-tail-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create the scratch directory");
    let script = dir.join("dying.sh");
    std::fs::write(&script, DYING_CHILD).expect("write the dying child");
    script
}

#[cfg(unix)]
#[tokio::test]
async fn a_failed_start_keeps_the_childs_stderr_for_classifying_it() {
    write_dying_child();
    let transport = dying_transport();

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
    write_dying_child();
    let transport = dying_transport();

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
    write_dying_child();
    let transport = dying_transport();

    transport.start().await.expect_err("the child dies");
    assert!(
        !transport.stderr_tail().is_empty(),
        "the first attempt left a tail to drop"
    );

    // The command now fails before it spawns anything, so nothing overwrites
    // the tail: only the clearing can empty it.
    let silent = StdioTransport::new(
        "/nonexistent/definitely-not-a-real-binary",
        HashMap::new(),
        None,
        std::time::Duration::from_secs(1),
        None,
    );
    silent
        .start()
        .await
        .expect_err("a missing binary cannot start");
    assert!(
        silent.stderr_tail().is_empty(),
        "a start that never spawned reads nothing from a child, so it must not report the \
         previous attempt's words as its own"
    );
}
