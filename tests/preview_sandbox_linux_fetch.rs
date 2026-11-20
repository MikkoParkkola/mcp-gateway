// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The command preview's Linux fetch step, through the shipped binary
//! (ADR-027 step 6): the control-socket handshake with the real launcher and
//! the fetch's CA files in the root. Skipped like the run-phase rows in
//! `preview_sandbox_linux.rs` on a host that refuses the sandbox, except where
//! `PREVIEW_SANDBOX_REQUIRED` is set.
#![cfg(target_os = "linux")]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/preview_sandbox.rs"]
mod preview_sandbox_common;
#[path = "common/private_home.rs"]
#[macro_use]
mod private_home;

use std::path::{Path, PathBuf};
use std::time::Duration;

use mcp_gateway::preview_sandbox::{Started, Target, start_fetching_with_helper};
use preview_sandbox_common::{Output, skip_or_fail};
use tokio::io::AsyncReadExt as _;

/// Hang guard for the fetch step's rows: over the 30 s setup bound.
const FETCH_GUARD: Duration = Duration::from_secs(45);

fn far() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(60)
}

fn shell(script: &str) -> Target {
    Target {
        program: PathBuf::from("/bin/sh"),
        args: vec!["-c".into(), script.into()],
    }
}

/// Start `sh -c script` through the fetch step, or `None` where this host
/// refuses the sandbox and the tests are not required.
async fn fetching(script: &str) -> Option<Started> {
    let started = tokio::time::timeout(
        FETCH_GUARD,
        start_fetching_with_helper(
            Path::new(gateway_bin::path()),
            &shell(script),
            &[],
            far(),
            None,
            None,
        ),
    )
    .await
    .expect("the fetch step ended within the guard");
    match started {
        Ok(started) => Some(started),
        Err(refusal) => {
            skip_or_fail(&refusal).map(|_| unreachable!("skip_or_fail never returns output"))
        }
    }
}

/// Everything a started preview printed, once it exits.
async fn finish(mut child: tokio::process::Child) -> Output {
    let (mut out, mut err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let run = async {
        let (mut stdout, mut stderr) = (String::new(), String::new());
        let (a, b) = tokio::join!(
            out.read_to_string(&mut stdout),
            err.read_to_string(&mut stderr)
        );
        a.and(b).expect("read the preview's output");
        (
            child.wait().await.expect("wait for unshare"),
            stdout,
            stderr,
        )
    };
    let (status, stdout, stderr) = tokio::time::timeout(FETCH_GUARD, run)
        .await
        .expect("the preview finished within the guard");
    Output {
        status,
        stdout,
        stderr,
    }
}

/// R1, kills "the helper never connects", "the handshake does not finish"
/// and "the target runs before or without the handshake": a fetching
/// preview's target runs, and only once `start_fetching` has returned.
#[tokio::test]
async fn r1_a_fetching_preview_runs_its_target_after_the_handshake() {
    require_private_home!();
    let Some(Started { mut child, .. }) = fetching("echo ran").await else {
        return;
    };
    drop(child.stdin.take());
    let out = finish(child).await;
    assert!(out.status.success(), "{}", out.stderr);
    assert_eq!(out.stdout, "ran\n");
}

/// R6b, kills "a helper that exits before connecting leaves `start_fetching`
/// waiting forever": a "helper" that exits at once is refused, not awaited.
#[tokio::test]
async fn r6b_a_helper_that_never_connects_is_refused() {
    require_private_home!();
    let started = tokio::time::timeout(
        FETCH_GUARD,
        start_fetching_with_helper(
            Path::new("/bin/true"),
            &shell("true"),
            &[],
            far(),
            None,
            None,
        ),
    )
    .await
    .expect("the refusal came within the guard");
    assert!(started.is_err());
}

/// `ESRCH`: reading an exiting task's `/proc` file fails with this.
const ESRCH: i32 = 3;

/// True when a failed `/proc/<pid>/stat` read tells us nothing about the
/// process: any error but a missing file or ESRCH (gone, or exiting).
fn says_nothing(e: &std::io::Error) -> bool {
    e.kind() != std::io::ErrorKind::NotFound && e.raw_os_error() != Some(ESRCH)
}

/// True when a `/proc/<pid>/stat` state field means the process is dead:
/// zombie (`Z`) or dead (`X`, or `x` on older kernels).
fn dead_state(state: Option<&str>) -> bool {
    matches!(state, Some("Z" | "X" | "x"))
}

/// The scan's read rule as a table: out of descriptors keeps a marked process
/// live, a missing file or ESRCH counts it gone; each dead state counts it
/// gone. Runs on any Linux host.
#[test]
fn a_failed_stat_read_keeps_a_marked_process_live_unless_it_is_missing_or_exiting() {
    use std::io::{Error, ErrorKind};
    assert!(says_nothing(&Error::from_raw_os_error(24)), "EMFILE");
    assert!(says_nothing(&Error::from_raw_os_error(5)), "EIO");
    assert!(!says_nothing(&Error::from_raw_os_error(2)), "ENOENT");
    assert!(!says_nothing(&Error::from(ErrorKind::NotFound)), "NotFound");
    assert!(!says_nothing(&Error::from_raw_os_error(ESRCH)), "ESRCH");
    for state in ["Z", "X", "x"] {
        assert!(dead_state(Some(state)), "state {state} reads as dead");
    }
    for state in ["R", "S", "D"] {
        assert!(!dead_state(Some(state)), "state {state} reads as live");
    }
}

/// The pids of this process's live `unshare` children whose command line
/// holds `marker` (a zombie is not live; rows run in parallel threads).
fn live_unshare_children(marker: &str) -> Vec<u32> {
    let me = std::process::id();
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").expect("/proc").flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            // Only a missing file or ESRCH (an exiting task) means gone. A
            // stat that fails for another reason says nothing, so a process
            // carrying the marker counts as live and the caller's wait goes on.
            Err(e) if says_nothing(&e) => {
                let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
                if String::from_utf8_lossy(&cmdline).contains(marker) {
                    found.push(pid);
                }
                continue;
            }
            Err(_) => continue,
        };
        let Some((name, rest)) = stat.split_once(" (").and_then(|(_, r)| r.rsplit_once(") "))
        else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let (state, parent) = (
            fields.next(),
            fields.next().and_then(|p| p.parse::<u32>().ok()),
        );
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let tagged = String::from_utf8_lossy(&cmdline).contains(marker);
        if name == "unshare" && parent == Some(me) && tagged && !dead_state(state) {
            found.push(pid);
        }
    }
    found
}

/// R6b, kills "a dropped `start_fetching` leaves the sandbox running": the
/// future is polled once (the sandbox is spawned) and dropped; its `unshare`
/// is killed.
#[tokio::test]
async fn r6b_a_dropped_start_leaves_no_sandbox_running() {
    use std::future::Future as _;
    use std::task::Poll;
    const MARKER: &str = "r6b-dropped-start";
    require_private_home!();
    let target = shell(&format!("sleep 30 # {MARKER}"));
    let mut start = Box::pin(start_fetching_with_helper(
        Path::new(gateway_bin::path()),
        &target,
        &[],
        far(),
        None,
        None,
    ));
    let first = std::future::poll_fn(|cx| Poll::Ready(start.as_mut().poll(cx))).await;
    assert!(first.is_pending(), "the fetch step waits for the helper");
    drop(start);
    let gone = async {
        while !live_unshare_children(MARKER).is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    tokio::time::timeout(FETCH_GUARD, gone)
        .await
        .expect("the sandbox was killed within the guard");
}

/// F2-T1, the topology the peer check's pid-reuse defence rests on: with the
/// real launcher, orphans the target leaves behind never become children of
/// the spawned `unshare`; its only child is the helper.
#[tokio::test]
async fn f2_t1_the_unshares_only_child_is_the_helper() {
    use tokio::io::AsyncBufReadExt as _;
    require_private_home!();
    let Some(Started { mut child, .. }) =
        fetching("(sleep 30 &); (sleep 30 &); echo up; sleep 30").await
    else {
        return;
    };
    let mut out = tokio::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(FETCH_GUARD, out.read_line(&mut line))
        .await
        .expect("the target started within the guard")
        .expect("read");
    assert_eq!(line, "up\n");
    let unshare = child.id().expect("unshare is running");
    let children = std::fs::read_to_string(format!("/proc/{unshare}/task/{unshare}/children"))
        .expect("the kernel lists the unshare's children");
    let _ = child.kill().await;
    assert_eq!(children.split_whitespace().count(), 1, "{children:?}");
}

/// F2-T2, kills "the run child inherits or can reach the control connection":
/// nothing the target can list is a socket.
#[tokio::test]
async fn f2_t2_the_run_child_holds_no_control_connection() {
    require_private_home!();
    let Some(Started { mut child, .. }) =
        fetching("ls -l /proc/self/fd/; ls -l /proc/1/fd/ 2>&1; true").await
    else {
        return;
    };
    drop(child.stdin.take());
    let out = finish(child).await;
    assert!(out.status.success(), "{}", out.stderr);
    assert!(!out.stdout.contains("socket:"), "{}", out.stdout);
}

/// 2b-1, kills "the CA files are missing or writable in the root": from the
/// run child, `ca.pem` is there and cannot be written, removed or renamed,
/// `empty-user.npmrc`, `empty-global.npmrc` and `empty-certs` are there and
/// empty, and nothing can be added beside them.
#[tokio::test]
async fn ca_files_are_read_only_from_the_run_child() {
    require_private_home!();
    let script = "d=/etc/mcp-gateway-preview
        test -f $d/ca.pem && echo ca-present
        (echo x > $d/ca.pem) 2>/dev/null && echo ca-writable
        (rm -f $d/ca.pem) 2>/dev/null; test -f $d/ca.pem && echo ca-kept
        (mv $d/ca.pem $d/moved) 2>/dev/null && echo ca-moved
        test -f $d/empty-user.npmrc && test -f $d/empty-global.npmrc && echo npmrc-present
        test -s $d/empty-user.npmrc || test -s $d/empty-global.npmrc || echo npmrc-empty
        test -d $d/empty-certs && [ -z \"$(ls -A $d/empty-certs)\" ] && echo certs-empty
        (touch $d/new) 2>/dev/null && echo dir-writable
        true";
    let Some(Started { mut child, .. }) = fetching(script).await else {
        return;
    };
    drop(child.stdin.take());
    let out = finish(child).await;
    assert!(out.status.success(), "{}", out.stderr);
    let seen: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(
        seen,
        [
            "ca-present",
            "ca-kept",
            "npmrc-present",
            "npmrc-empty",
            "certs-empty"
        ],
        "{}",
        out.stdout
    );
}

/// 2b-1: the CA snapshot sits under host `/tmp` (the rows pass no
/// `XDG_RUNTIME_DIR`), which staging covers, so "bind by pathname after
/// staging" fails; this fails loudly if the temp dir is not `/tmp`.
#[tokio::test]
async fn the_ca_snapshot_sits_under_tmp_on_this_host() {
    require_private_home!();
    let Some(Started { mut child, .. }) = fetching("sleep 30").await else {
        return;
    };
    let unshare = child.id().expect("unshare is running");
    let cmdline = std::fs::read(format!("/proc/{unshare}/cmdline")).expect("cmdline");
    let text = String::from_utf8_lossy(&cmdline).into_owned();
    let _ = child.kill().await;
    assert!(text.contains("\"ca\":\"/tmp/"), "{text}");
}

/// T3-T5: this binary's gateway home routes to the test-home override.
#[test]
fn private_home_routes_to_the_override() {
    private_home::assert_routes_to_the_override(
        module_path!(),
        "private_home_routes_to_the_override",
    );
}
