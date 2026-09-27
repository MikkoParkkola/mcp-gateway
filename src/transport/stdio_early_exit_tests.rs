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

/// T1: the cause, over exit status 0 and 3. The caller sees the status and a
/// pointer to the log, never the child's stderr; the excerpt carries it.
#[tokio::test]
async fn t1_an_early_exit_reports_its_status_and_keeps_its_stderr_off_the_error() {
    for code in [0, 3] {
        let t = transport(
            &format!("echo \"ModuleNotFoundError: No module named canary_mod\" >&2; exit {code}"),
            &[],
        );
        let err = start_err(&t).await;
        assert!(err.contains("exited before initialize"), "{err}");
        assert!(err.contains(&format!("exit status: {code}")), "{err}");
        assert!(err.contains("gateway log"), "{err}");
        assert!(
            !err.contains("canary_mod"),
            "stderr reached the caller: {err}"
        );
        let excerpt = t.start_failure_excerpt().expect("an excerpt is kept");
        assert!(excerpt.contains("canary_mod"), "{excerpt}");
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
        let t = transport("exec 0<&-; echo \"write-race-canary\" >&2; exit 4", &[]);
        let err = start_err(&t).await;
        assert!(err.contains("exited before initialize"), "{err}");
        assert!(err.contains("exit status: 4"), "{err}");
        let excerpt = t.start_failure_excerpt().expect("an excerpt is kept");
        assert!(excerpt.contains("write-race-canary"), "{excerpt}");
    }
}

/// T2: the excerpt is bounded in lines, line length and bytes, and is the tail.
#[tokio::test]
async fn t2_the_excerpt_is_the_bounded_tail() {
    let t = transport(
        "i=1; while [ $i -le 40 ]; do printf \"line-%02d-%0300d\\n\" $i 0 >&2; i=$((i+1)); done; exit 1",
        &[],
    );
    let _ = start_err(&t).await;
    let excerpt = t.start_failure_excerpt().expect("an excerpt is kept");
    assert!(excerpt.len() <= 2048, "{} bytes", excerpt.len());
    assert!(excerpt.lines().count() <= 20);
    assert!(excerpt.lines().all(|l| l.chars().count() <= 256));
    assert!(excerpt.contains("line-40-"), "the last line is kept");
    assert!(!excerpt.contains("line-01-"), "the head is dropped");
}

/// T2c: short lines hit the line cap before the byte cap, so the tail itself
/// is bounded, not only the excerpt cut from it.
#[tokio::test]
async fn t2c_short_lines_are_capped_at_twenty() {
    let t = transport(
        "i=1; while [ $i -le 200 ]; do echo \"s$i\" >&2; i=$((i+1)); done; exit 1",
        &[],
    );
    let _ = start_err(&t).await;
    let excerpt = t.start_failure_excerpt().expect("an excerpt is kept");
    assert_eq!(excerpt.lines().count(), 20, "{excerpt}");
    assert!(excerpt.ends_with("s200"), "{excerpt}");
}

/// T2b: a last line with no newline is kept.
#[tokio::test]
async fn t2b_a_final_line_without_a_newline_is_kept() {
    let t = transport("printf \"tail-without-newline\" >&2; exit 1", &[]);
    let _ = start_err(&t).await;
    let excerpt = t.start_failure_excerpt().expect("an excerpt is kept");
    assert!(excerpt.ends_with("tail-without-newline"), "{excerpt:?}");
}

/// T3: what the gateway handed the child, and credential-shaped text, is
/// redacted before it reaches the log.
#[tokio::test]
async fn t3_argv_env_and_credentials_are_redacted() {
    let token = format!(
        "ghp_{}",
        "a1B2c3D4e5".repeat(4).get(..36).unwrap_or_default()
    );
    let script = format!("echo \"arg=$1 env=$API_TOKEN tok={token}\" >&2; exit 1");
    let env = HashMap::from([("API_TOKEN".to_string(), "env-canary-7c1".to_string())]);
    let command = format!("sh -c '{script}' sh argv-canary-9f3");
    let t = StdioTransport::new(&command, env, None, REQUEST_TIMEOUT, None);
    let err = start_err(&t).await;
    let excerpt = t.start_failure_excerpt().expect("an excerpt is kept");
    assert!(!excerpt.contains("env-canary-7c1"), "{excerpt}");
    assert!(!excerpt.contains("argv-canary-9f3"), "{excerpt}");
    #[cfg(feature = "firewall")]
    assert!(!excerpt.contains(&token), "{excerpt}");
    assert!(excerpt.contains("[REDACTED"), "{excerpt}");
    assert!(!err.contains("env-canary-7c1"), "{err}");
}

/// T3b: a secret that straddles the per-line cut is redacted whole, because
/// redaction runs before the cut.
#[tokio::test]
async fn t3b_a_secret_across_the_line_cut_is_redacted() {
    let t = transport(
        "printf \"%0250d%s\\n\" 0 \"$API_TOKEN\" >&2; exit 1",
        &[("API_TOKEN", "env-canary-7c1")],
    );
    let _ = start_err(&t).await;
    let excerpt = t.start_failure_excerpt().expect("an excerpt is kept");
    assert!(!excerpt.contains("env-ca"), "{excerpt}");
}

/// T3c: a multi-line env value is redacted line by line.
#[tokio::test]
async fn t3c_a_multi_line_secret_is_redacted_line_by_line() {
    let t = transport(
        "printf \"%s\\n\" \"$KEY\" >&2; exit 1",
        &[("KEY", "pem-line-one-9c2\npem-line-two-4d7")],
    );
    let _ = start_err(&t).await;
    let excerpt = t.start_failure_excerpt().expect("an excerpt is kept");
    assert!(!excerpt.contains("pem-line-one-9c2"), "{excerpt}");
    assert!(!excerpt.contains("pem-line-two-4d7"), "{excerpt}");
}

/// T2d: an overlong line is read in bounded chunks and the lines after it
/// still arrive.
#[tokio::test]
async fn t2d_an_overlong_line_does_not_hide_the_next() {
    let t = transport(
        // 100,000 bytes with no newline, built without quotes: the script is
        // already inside single quotes.
        "i=0; while [ $i -lt 2000 ]; do printf %050d 0 >&2; i=$((i+1)); done; echo >&2; echo after-canary >&2; exit 1",
        &[],
    );
    let _ = start_err(&t).await;
    let excerpt = t.start_failure_excerpt().expect("an excerpt is kept");
    assert!(excerpt.ends_with("after-canary"), "{excerpt:?}");
    assert!(excerpt.lines().all(|l| l.chars().count() <= 256));
}

/// T4b: a grandchild that keeps stderr open does not erase what was read.
#[tokio::test]
async fn t4b_a_held_stderr_pipe_keeps_the_tail() {
    let t = transport(
        "(sleep 3 >/dev/null </dev/null &); echo held-canary >&2; exit 3",
        &[],
    );
    let err = start_err(&t).await;
    assert!(err.contains("exit status: 3"), "{err}");
    let excerpt = t.start_failure_excerpt().expect("an excerpt is kept");
    assert!(excerpt.contains("held-canary"), "{excerpt}");
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
            t.start_failure_excerpt().is_none(),
            "an answered start kept an excerpt"
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
