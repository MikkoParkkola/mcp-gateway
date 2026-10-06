// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stdio child that dies before `initialize` (#526). Unix: the children are
//! `sh` scripts.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::super::StdioTransport;

/// Far longer than any row may take: a row that waits it out has regressed to
/// the timeout this change removes.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ROW_LIMIT: Duration = Duration::from_secs(5);

fn transport(script: &str, env: &[(&str, &str)]) -> Arc<StdioTransport> {
    let env: HashMap<String, String> = env
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    StdioTransport::new(
        &format!("sh -c '{script}'"),
        env,
        None,
        REQUEST_TIMEOUT,
        None,
    )
}

async fn start_err(t: &Arc<StdioTransport>) -> String {
    tokio::time::timeout(ROW_LIMIT, t.start())
        .await
        .expect("start must fail fast, not wait out the request timeout")
        .expect_err("a child that died before initialize cannot start")
        .to_string()
}

/// T1: the cause, over exit status 0 and 3. The caller sees the status and
/// the class, never the child's stderr.
#[tokio::test]
async fn t1_an_early_exit_reports_its_status_and_class_not_its_stderr() {
    for code in [0, 3] {
        let t = transport(
            &format!("echo \"ModuleNotFoundError: No module named canary_mod\" >&2; exit {code}"),
            &[],
        );
        let err = start_err(&t).await;
        assert!(err.contains("exited before initialize"), "{err}");
        assert!(err.contains(&format!("exit status: {code}")), "{err}");
        assert!(err.contains("missing_module"), "{err}");
        assert!(
            !err.contains("canary_mod"),
            "stderr reached the caller: {err}"
        );
        assert_eq!(
            t.start_failure_class(),
            Some(("missing_module", Some("ModuleNotFoundError")))
        );
    }
}

/// T1b: a child that closed its stdin first fails the `initialize` write
/// (EPIPE) before its stdout closes. That is the same early exit, not a
/// transport error.
#[tokio::test]
async fn t1b_a_failed_initialize_write_is_still_an_early_exit() {
    // Which side fails first is a race, so run it enough times to take the
    // write-fails side (it did on the first CI-shaped run).
    for _ in 0..10 {
        let t = transport("exec 0<&-; echo \"Cannot find module x\" >&2; exit 4", &[]);
        let err = start_err(&t).await;
        assert!(err.contains("exited before initialize"), "{err}");
        assert!(err.contains("exit status: 4"), "{err}");
        assert_eq!(
            t.start_failure_class(),
            Some(("missing_module", Some("Cannot find module")))
        );
    }
}

/// T2: only the tail is matched: a needle on the first of 40 lines is gone.
#[tokio::test]
async fn t2_the_head_of_a_long_stderr_is_dropped() {
    let t = transport(
        "echo EADDRINUSE >&2; i=2; while [ $i -le 40 ]; do echo \"line-$i\" >&2; i=$((i+1)); done; exit 1",
        &[],
    );
    let err = start_err(&t).await;
    assert!(err.contains("unclassified"), "{err}");
    assert_eq!(t.start_failure_class(), Some(("unclassified", None)));
}

/// T2c: a needle within the last twenty short lines is still found.
#[tokio::test]
async fn t2c_a_needle_in_the_last_twenty_lines_is_found() {
    let t = transport(
        "i=1; while [ $i -le 200 ]; do [ $i -eq 190 ] && echo EACCES >&2; echo \"s$i\" >&2; i=$((i+1)); done; exit 1",
        &[],
    );
    let _ = start_err(&t).await;
    assert_eq!(
        t.start_failure_class(),
        Some(("permission_denied", Some("EACCES")))
    );
}

/// T2e: with two needles in the tail, the later line names the cause.
#[tokio::test]
async fn t2e_the_last_matching_line_names_the_cause() {
    let t = transport(
        "echo EACCES >&2; echo \"Cannot find module x\" >&2; exit 1",
        &[],
    );
    let _ = start_err(&t).await;
    assert_eq!(
        t.start_failure_class(),
        Some(("missing_module", Some("Cannot find module")))
    );
}

/// T2b: a last line with no newline is matched.
#[tokio::test]
async fn t2b_a_final_line_without_a_newline_is_matched() {
    let t = transport("printf \"x: command not found\" >&2; exit 1", &[]);
    let _ = start_err(&t).await;
    assert_eq!(
        t.start_failure_class(),
        Some(("missing_file", Some("command not found")))
    );
}

/// T2d: an overlong line is read in bounded chunks and the lines after it
/// still arrive.
#[tokio::test]
async fn t2d_an_overlong_line_does_not_hide_the_next() {
    let t = transport(
        // 100,000 bytes with no newline, built without quotes: the script is
        // already inside single quotes.
        "i=0; while [ $i -lt 2000 ]; do printf %050d 0 >&2; i=$((i+1)); done; echo >&2; echo EADDRINUSE >&2; exit 1",
        &[],
    );
    let _ = start_err(&t).await;
    assert_eq!(
        t.start_failure_class(),
        Some(("address_in_use", Some("EADDRINUSE")))
    );
}

/// T4b: a grandchild that keeps stderr open does not erase what was read.
#[tokio::test]
async fn t4b_a_held_stderr_pipe_keeps_the_tail() {
    let t = transport(
        "(sleep 3 >/dev/null </dev/null &); echo \"Permission denied\" >&2; exit 3",
        &[],
    );
    let err = start_err(&t).await;
    assert!(err.contains("exit status: 3"), "{err}");
    assert_eq!(
        t.start_failure_class(),
        Some(("permission_denied", Some("Permission denied")))
    );
}

/// T4: a child that closes stdout but keeps running is reported at once and
/// does not outlive the failed start.
#[tokio::test]
async fn t4_a_child_that_closes_stdout_and_stays_is_reported_and_killed() {
    let t = transport("exec 1>&-; exec sleep 30", &[]);
    let err = start_err(&t).await;
    assert!(err.contains("closed its stdout before initialize"), "{err}");
    assert!(
        t.child.lock().await.is_none(),
        "the child handle is still held"
    );
}

/// T6b: with the reply and EOF both ready before the first poll, the reply
/// wins every time. An unbiased select picks EOF about half the time.
#[tokio::test]
async fn t6b_a_ready_reply_beats_a_ready_eof() {
    for _ in 0..1000 {
        let won = super::reply_or_eof(std::future::ready(7), std::future::ready(())).await;
        assert_eq!(won, Some(7));
    }
}

/// T6: a child that answers `initialize` and then exits is past the boundary:
/// whatever the start returns, it is not the early-exit report.
#[tokio::test]
async fn t6_a_child_that_answered_is_not_an_early_exit() {
    let reply = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}"#;
    // The reply and the exit race; without `biased` the EOF wins about half
    // the time, so enough iterations make that ordering a certain failure.
    for _ in 0..50 {
        let t = transport(&format!("read line; echo {reply:?}; exit 0"), &[]);
        let outcome = tokio::time::timeout(ROW_LIMIT, t.start())
            .await
            .expect("an answered start settles well inside the row limit");
        if let Err(err) = outcome {
            assert!(!err.to_string().contains("before initialize"), "{err}");
        }
        assert!(
            t.start_failure_class().is_none(),
            "an answered start kept a class"
        );
    }
}

/// T8: a previous generation's exit cannot answer the next start's race.
#[tokio::test]
async fn t8_a_restart_after_an_early_exit_is_judged_on_its_own_child() {
    let t = transport("exit 3", &[]);
    let _ = start_err(&t).await;
    // Same transport, second start, same dying command: judged afresh, and
    // still reported as its own early exit rather than a stale one.
    let err = start_err(&t).await;
    assert!(err.contains("exit status: 3"), "{err}");
}

/// MIK-7324.COV.3: stdout that is not UTF-8 ends the reader as a read error.
/// The child is still alive, so only the reader's end can fail `start` before
/// the request timeout; a reader that kept waiting would hang it the full 30s.
#[tokio::test]
async fn non_utf8_stdout_fails_start_without_waiting_for_the_timeout() {
    use crate::transport::Transport as _;
    let t = transport("printf \"\\377\\n\"; sleep 30", &[]);
    start_err(&t).await;
    assert!(!t.is_connected());
}

/// MIK-7978: no log record carries the child's stderr, not even a credential
/// the redactor's patterns miss. Test idea from #1759 (terafin).
#[tokio::test]
async fn an_early_exit_logs_no_child_stderr() {
    // One character short of the 36 the GitHub token pattern needs.
    let sentinel = format!("ghp_{}", "q7".repeat(17));
    let (captured, _guard) = crate::gateway::session_id::log_capture::capture_debug();
    let t = transport(
        &format!("echo \"Authorization: token {sentinel}\" >&2; exit 3"),
        &[],
    );
    let err = start_err(&t).await;
    assert!(err.contains("exit status: 3"), "{err}");
    let text = captured.text();
    assert!(
        text.lines().any(|l| l.contains("exited before initialize")),
        "the early exit is logged:\n{text}"
    );
    assert!(
        !text.contains(&sentinel),
        "child stderr reached the log:\n{text}"
    );
}

/// MIK-7978: the log record of a classified exit names its class and needle,
/// and carries no `stderr` field at all.
#[tokio::test]
async fn an_early_exit_logs_its_class_and_needle() {
    let (captured, _guard) = crate::gateway::session_id::log_capture::capture_debug();
    let t = transport(
        "echo \"Error: Cannot find module secret-path-7978\" >&2; exit 3",
        &[],
    );
    let _ = start_err(&t).await;
    let text = captured.text();
    let line = text
        .lines()
        .find(|l| l.contains("exited before initialize"))
        .unwrap_or_else(|| panic!("the early exit is logged:\n{text}"));
    assert!(line.contains("missing_module"), "{line}");
    assert!(line.contains("Cannot find module"), "{line}");
    assert!(!line.contains("stderr="), "{line}");
    assert!(!text.contains("secret-path-7978"), "{text}");
}

/// MIK-7978 STDERR.3: the sanitized tail is kept for the doctor's accessor,
/// with its credential masked, while the error and the log stay free of it.
#[tokio::test]
async fn an_early_exit_keeps_a_sanitized_tail_for_the_doctor_only() {
    let (captured, _guard) = crate::gateway::session_id::log_capture::capture_debug();
    let t = transport(
        "echo \"Error: Cannot find module tail-7978\" >&2; echo \"Authorization: Bearer tok-7978\" >&2; exit 3",
        &[],
    );
    let err = tokio::time::timeout(ROW_LIMIT, t.start())
        .await
        .expect("start must fail fast")
        .expect_err("an early exit");
    let shown = t.last_failure_stderr();
    assert_eq!(
        shown.first().map(String::as_str),
        Some("Error: Cannot find module tail-7978"),
        "{shown:?}"
    );
    assert!(shown.iter().all(|l| !l.contains("tok-7978")), "{shown:?}");
    // The capture saw the exit's record, so its silence below means something.
    assert!(
        captured.text().contains("missing_module"),
        "{}",
        captured.text()
    );
    for text in [err.to_string(), format!("{err:?}"), captured.text()] {
        assert!(!text.contains("tail-7978"), "stderr escaped: {text}");
        assert!(!text.contains("tok-7978"), "stderr escaped: {text}");
    }
}

/// STDERR.3: a later start clears the previous exit's tail.
#[tokio::test]
async fn a_new_start_clears_the_previous_tail() {
    let dir = tempfile::tempdir().expect("dir");
    let flag = dir.path().join("second");
    let t = transport(
        &format!(
            "[ -e {f} ] && exit 4; touch {f}; echo \"first-run-7978\" >&2; exit 3",
            f = flag.display()
        ),
        &[],
    );
    let _ = start_err(&t).await;
    assert_eq!(t.last_failure_stderr(), vec!["first-run-7978".to_string()]);
    let _ = start_err(&t).await;
    assert!(
        t.last_failure_stderr().is_empty(),
        "{:?}",
        t.last_failure_stderr()
    );
}

/// STDERR.3: a key block longer than the tail loses its BEGIN line to
/// eviction, and its body lines stay masked anyway.
#[tokio::test]
async fn a_block_longer_than_the_tail_stays_masked() {
    let t = transport(
        "echo \"-----BEGIN EXAMPLE BLOCK-----\" >&2; \
         for i in $(seq 25); do echo \"MIIEvQIBADANBg/kqhkiG9w0BAQEFAASCBKcwggSjAgEA/AoIB$i\" >&2; done; \
         echo \"AQIDBAUGBwgJCgsMDQ4PEBE=\" >&2; echo \"-----END EXAMPLE BLOCK-----\" >&2; exit 3",
        &[],
    );
    let _ = start_err(&t).await;
    let shown = t.last_failure_stderr();
    assert_eq!(shown.len(), 20, "{shown:?}");
    assert_eq!(
        shown.last().map(String::as_str),
        Some("-----END EXAMPLE BLOCK-----")
    );
    assert!(shown[..19].iter().all(|l| l == "[masked]"), "{shown:?}");
}

/// The tail after `pad` (zeros with no newline) and then a key block whose
/// `-----BEGIN` lands on the same line, past what the capture stores.
async fn tail_after_a_begin_behind(pad: &str) -> Vec<String> {
    let t = transport(
        &format!(
            "{pad}; echo \"-----BEGIN EXAMPLE BLOCK-----\" >&2; \
             echo \"MIIEvQIBADANBg/kqhkiG9w0BAQEFAASCBKcwggSjAgEA/AoIB\" >&2; \
             echo \"-----END EXAMPLE BLOCK-----\" >&2; exit 3"
        ),
        &[],
    );
    let _ = start_err(&t).await;
    t.last_failure_stderr()
}

/// STDERR.3: a `-----BEGIN` past the line limit is skipped unstored, and
/// still opens the block, so the body line after it is masked.
#[tokio::test]
async fn a_begin_past_the_line_limit_still_masks_the_body() {
    // 4,200 zeros, then the marker.
    let shown = tail_after_a_begin_behind(
        "i=0; while [ $i -lt 84 ]; do printf %050d 0 >&2; i=$((i+1)); done",
    )
    .await;
    assert_eq!(shown.len(), 3, "{shown:?}");
    assert_eq!(shown[1], "[masked]", "{shown:?}");
}

/// STDERR.3: a `-----BEGIN` cut in two by the line limit still opens the
/// block.
#[tokio::test]
async fn a_begin_split_by_the_line_limit_still_masks_the_body() {
    // 4,091 zeros: the limit (4,096) falls inside the marker.
    let shown = tail_after_a_begin_behind(
        "i=0; while [ $i -lt 81 ]; do printf %050d 0 >&2; i=$((i+1)); done; printf %041d 0 >&2",
    )
    .await;
    assert_eq!(shown.len(), 3, "{shown:?}");
    assert_eq!(shown[1], "[masked]", "{shown:?}");
}

/// STDERR.3: a start that cannot spawn shows no older exit's tail.
#[tokio::test]
async fn a_spawn_failure_clears_the_previous_tail() {
    let dir = tempfile::tempdir().expect("dir");
    let cwd = dir.path().join("cwd");
    std::fs::create_dir(&cwd).expect("cwd");
    let t = StdioTransport::new(
        "sh -c 'echo \"first-run-7980\" >&2; exit 3'",
        HashMap::new(),
        Some(cwd.display().to_string()),
        REQUEST_TIMEOUT,
        None,
    );
    let _ = start_err(&t).await;
    assert_eq!(t.last_failure_stderr(), vec!["first-run-7980".to_string()]);
    std::fs::remove_dir(&cwd).expect("remove cwd");
    let spawn = tokio::time::timeout(ROW_LIMIT, t.start()).await;
    assert!(matches!(spawn, Ok(Err(_))), "the spawn must fail");
    assert!(
        t.last_failure_stderr().is_empty(),
        "{:?}",
        t.last_failure_stderr()
    );
}
