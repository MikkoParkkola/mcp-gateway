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

// First run refuses `initialize` and stays alive; later runs answer it. Every
// run logs each line it reads to its own file.
const SECOND_TRY_CHILD: &str = r#"n=$(cat runs 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > runs
while IFS= read -r line; do
  printf '%s\n' "$line" >> "child$n.log"
  case "$line" in *'"method":"initialize"'*)
    id=${line#*'"id":'}; id=${id%%,*}
    if [ "$n" = 1 ]; then
      printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"no"}}\n' "$id"
    else
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"x","version":"0"}}}\n' "$id"
    fi ;;
  esac
done
"#;

/// A start retried on the same transport after a failed `initialize` hands the
/// new child exactly one `initialize`: nothing from the first attempt is
/// written into the second child's stdin (MIK-8079 with #3242's retry).
#[cfg(unix)]
#[tokio::test]
async fn a_retried_start_sends_the_new_child_exactly_one_initialize() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("child.sh"), SECOND_TRY_CHILD).unwrap();
    let transport = StdioTransport::new(
        "sh child.sh",
        HashMap::new(),
        Some(dir.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(5),
        None,
    );
    transport
        .start()
        .await
        .expect_err("the first child refuses");
    transport.start().await.expect("the second child answers");

    let log = dir.path().join("child2.log");
    let mut lines = String::new();
    for _ in 0..50 {
        lines = std::fs::read_to_string(&log).unwrap_or_default();
        if lines.contains("notifications/initialized") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let initializes = lines
        .lines()
        .filter(|line| line.contains(r#""method":"initialize""#))
        .count();
    assert_eq!(initializes, 1, "the second child read:\n{lines}");
    crate::transport::Transport::close(&*transport)
        .await
        .expect("close");
}
