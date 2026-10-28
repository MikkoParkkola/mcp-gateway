// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a failed start leaves for classifying it: the stderr tail and the
//! child's exit status (#1759).

use std::collections::HashMap;
use std::sync::Arc;

use super::super::early_exit::{ReaderHold, STDERR_READER_HOLD};
use super::StdioTransport;
use super::joined;

// A child that answers nothing and dies with a reason on stderr: the shape a
// package manager produces when its install tree is unusable.
const DYING_CHILD: &str = r#"printf 'Error: Cannot find module %s\n' "'/root/.npm/_npx/1/node_modules/zod'" >&2
exit 3
"#;

/// The dying child in a directory of its own: rows run in parallel, and a
/// script another row is rewriting reads as empty.
fn dying_transport() -> (tempfile::TempDir, Arc<StdioTransport>) {
    let dir = tempfile::tempdir().expect("scratch");
    std::fs::write(dir.path().join("dying.sh"), DYING_CHILD).expect("write the dying child");
    let transport = StdioTransport::new(
        "sh dying.sh",
        HashMap::new(),
        Some(dir.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(5),
        None,
    );
    (dir, transport)
}

#[cfg(unix)]
#[tokio::test]
async fn a_failed_start_keeps_the_childs_stderr_for_classifying_it() {
    let (_dir, transport) = dying_transport();

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
    let (_dir, transport) = dying_transport();

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
    let (_dir, transport) = dying_transport();

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

/// How long the held rows keep the reader task from the read loop: past
/// both drain windows, as a loaded host can.
const READER_HOLD: std::time::Duration = std::time::Duration::from_millis(1500);

/// The drain window a held row runs with.
#[derive(Clone, Copy, Debug)]
enum Window {
    /// The production window of the path the start takes.
    Real,
    /// No time at all: only a drain that reads before its clock can pass.
    Zero,
}

/// A failed start of `script`'s child, its reader task held at `hold`.
async fn start_with_held_reader(
    script: &str,
    hold: ReaderHold,
    window: Window,
) -> Arc<StdioTransport> {
    let dir = tempfile::tempdir().expect("scratch");
    std::fs::write(dir.path().join("child.sh"), script).expect("write the child");
    let transport = StdioTransport::new(
        "sh child.sh",
        HashMap::new(),
        Some(dir.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(5),
        None,
    );
    if matches!(window, Window::Zero) {
        *transport.stderr_bound.lock() = Some(std::time::Duration::ZERO);
    }
    STDERR_READER_HOLD.with(|cell| cell.set(Some(hold)));
    let outcome = transport.start().await;
    STDERR_READER_HOLD.with(|cell| cell.set(None));
    outcome.expect_err("the child cannot start");
    transport
}

/// The early path: a reader task that runs late loses nothing the child wrote.
#[cfg(unix)]
#[tokio::test]
async fn a_late_stderr_reader_still_leaves_the_tail_of_an_early_exit() {
    for window in [Window::Real, Window::Zero] {
        let transport = start_with_held_reader(
            DYING_CHILD,
            ReaderHold::BeforeFirstRead(READER_HOLD),
            window,
        )
        .await;
        assert!(
            transport.stderr_tail().contains("Cannot find module"),
            "the child's stderr was closed with its words in the pipe, so a reader held back by \
             load must still read them ({window:?}): {:?}",
            transport.stderr_tail()
        );
    }
}

/// The late path: the child the failure killed said why on stderr first.
#[cfg(unix)]
#[tokio::test]
async fn a_late_stderr_reader_still_leaves_the_tail_of_a_late_failure() {
    let script = format!("echo 'EACCES: permission denied' >&2\n{REFUSING_CHILD}");
    for window in [Window::Real, Window::Zero] {
        let transport =
            start_with_held_reader(&script, ReaderHold::BeforeFirstRead(READER_HOLD), window).await;
        assert!(
            transport.stderr_tail().contains("EACCES"),
            "the killed child's stderr ends at its death, so a reader held back by load must \
             still read it ({window:?}): {:?}",
            transport.stderr_tail()
        );
    }
}

/// A reader task that ran once and then starved: the clock must not have
/// started at that first poll, or the line after it is lost the same way.
#[cfg(unix)]
#[tokio::test]
async fn a_stderr_reader_starved_after_its_first_line_still_reads_the_rest() {
    // The pause lets the loop store the first line and wait before the second.
    let script = "printf 'starting\\n' >&2\nsleep 0.3\nprintf 'Error: Cannot find module zod\\n' >&2\nexit 3\n";
    for window in [Window::Real, Window::Zero] {
        let transport =
            start_with_held_reader(script, ReaderHold::AfterFirstLine(READER_HOLD), window).await;
        assert!(
            transport.stderr_tail().contains("Cannot find module"),
            "the reader had run, but the needle was its second line; a clock started at its \
             first poll still loses it ({window:?}): {:?}",
            transport.stderr_tail()
        );
    }
}

/// A last line with no newline is the child's explanation as often as not.
#[cfg(unix)]
#[tokio::test]
async fn a_late_reader_keeps_an_unterminated_last_line() {
    let script = "printf 'EACCES: permission denied' >&2\nexit 3\n";
    let transport = start_with_held_reader(
        script,
        ReaderHold::BeforeFirstRead(READER_HOLD),
        Window::Zero,
    )
    .await;
    assert!(
        transport.stderr_tail().contains("EACCES"),
        "{:?}",
        transport.stderr_tail()
    );
}

/// More lines than tokio's per-poll budget of reads, all queued by a child
/// that has exited: a dead child's pipe (64 KiB at most) fits in one budget,
/// so a drain with no time left still reads to the last line.
#[cfg(unix)]
#[tokio::test]
async fn a_late_reader_reads_a_dead_childs_whole_pipe() {
    let script = "i=1; while [ $i -le 200 ]; do echo \"line $i\" >&2; i=$((i+1)); done\nexit 3\n";
    let transport = start_with_held_reader(
        script,
        ReaderHold::BeforeFirstRead(READER_HOLD),
        Window::Zero,
    )
    .await;
    let tail = transport.stderr_tail();
    assert!(
        tail.ends_with("line 200") && tail.contains("line 181"),
        "{tail:?}"
    );
}

/// A key block opened past an overlong line's limit still masks what follows
/// when the drain, not the task, reads it: the loop's state is never lost.
#[cfg(unix)]
#[tokio::test]
async fn a_late_reader_still_masks_a_key_block_opened_in_an_overlong_line() {
    let script = "printf '%04100d-----BEGIN KEY-----\\nplainbodytext\\n' 0 >&2\nexit 3\n";
    let transport = start_with_held_reader(
        script,
        ReaderHold::BeforeFirstRead(READER_HOLD),
        Window::Zero,
    )
    .await;
    let tail = transport.stderr_tail();
    assert!(!tail.contains("plainbodytext"), "{tail:?}");
    assert!(tail.contains("[masked]"), "{tail:?}");
}

/// A child whose stderr outlives it: `holder` runs outside its process group
/// (perl's `setsid`, as macOS ships no `setsid` command) with stderr inherited.
fn child_with_held_stderr(holder: &str) -> tokio::process::Child {
    let script = format!(
        "echo 'EACCES: permission denied' >&2\nperl -MPOSIX -e 'setsid; exec @ARGV' sh -c '{holder}' &\nexit 3\n"
    );
    tokio::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn the child")
}

/// Drains a held pipe with a short window, under a hang guard. Returns the
/// tail and how long the drain took, and checks that the read loop is gone
/// once the drain has returned.
async fn drain_held(holder: &str) -> (String, std::time::Duration) {
    let mut child = child_with_held_stderr(holder);
    let reader = super::super::early_exit::spawn_stderr_tail(
        child.stderr.take().expect("piped stderr"),
        "held".to_string(),
    );
    let _ = child.wait().await;
    let tail = Arc::clone(&reader.tail);
    let started = std::time::Instant::now();
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        reader.drain(std::time::Duration::from_millis(200)),
    )
    .await
    .expect("the drain hung on a held pipe");
    let took = started.elapsed();
    // The read loop holds the tail's other handle: only once the loop is
    // gone can nothing more be read into it.
    assert_eq!(
        Arc::strong_count(&tail),
        1,
        "the read loop still runs after the drain returned"
    );
    let drained = joined(&tail.lock());
    (drained, took)
}

/// The drain ran out its window, so the pipe really was held (a holder that
/// failed to start would close it), and the window still bounded it.
fn assert_held(took: std::time::Duration) {
    assert!(
        took >= std::time::Duration::from_millis(150),
        "the drain ended early, so nothing held the pipe: {took:?}"
    );
    assert!(
        took < std::time::Duration::from_secs(2),
        "the drain took {took:?}"
    );
}

/// A quiet holder: the drain returns at its window with what was read.
#[cfg(unix)]
#[tokio::test]
async fn a_held_pipe_ends_the_drain_and_the_reader_task() {
    let (tail, took) = drain_held("sleep 5").await;
    assert!(
        tail.contains("EACCES"),
        "the line before the hold is kept: {tail:?}"
    );
    assert_held(took);
}

/// A chatty holder never leaves the pipe empty for long: the window still
/// bounds the drain, and the reader stops with it.
#[cfg(unix)]
#[tokio::test]
async fn a_chatty_held_pipe_still_ends_the_drain_at_its_window() {
    let (tail, took) =
        drain_held("i=0; while [ $i -lt 500 ]; do echo tick $i >&2; sleep 0.01; i=$((i+1)); done")
            .await;
    assert!(tail.contains("tick"), "{tail:?}");
    assert_held(took);
}
