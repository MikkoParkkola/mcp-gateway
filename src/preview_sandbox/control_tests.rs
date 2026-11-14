// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T8 (the peer is the helper) and T4 (framing) for the control socket.

use super::{CONTROL_BOUNDS, ControlBounds, MAX_LINE, peer_is_helper, read_line, started_by};
use std::time::Duration;
use tokio::io::{AsyncWriteExt as _, BufReader};

/// `/proc/<pid>/status` of a process whose parent is `ppid`, running as `uid`.
fn status(ppid: &str, uid: &str) -> String {
    format!(
        "Name:\tmcp-gateway\nState:\tS (sleeping)\nPid:\t4242\nPPid:\t{ppid}\nTracerPid:\t0\nUid:\t{uid}\nGid:\t1000\t1000\t1000\t1000\n"
    )
}

/// T8, kills "the peer check is skipped".
#[test]
fn t8_the_helper_under_the_spawned_unshare_as_the_gateway_uid_passes() {
    assert!(peer_is_helper(&status("4241", "1000\t1000\t1000\t1000"), 4241, 1000).is_ok());
}

/// T8, kills "any parent is accepted".
#[test]
fn t8_a_peer_under_another_parent_is_refused() {
    assert!(peer_is_helper(&status("4240", "1000\t1000\t1000\t1000"), 4241, 1000).is_err());
}

/// T8, kills "the uid is not checked, or only one of its fields is".
#[test]
fn t8_a_peer_with_another_uid_is_refused() {
    for uid in [
        "0\t0\t0\t0",
        "1000\t0\t1000\t1000",
        "0\t1000\t1000\t1000",
        "1000\t1000\t1000\t0",
    ] {
        assert!(
            peer_is_helper(&status("4241", uid), 4241, 1000).is_err(),
            "{uid}"
        );
    }
}

/// T8, kills "unreadable parentage reads as a match".
#[test]
fn t8_unreadable_parentage_is_refused() {
    let no_ppid = status("4241", "1000\t1000\t1000\t1000").replace("PPid:\t4241\n", "");
    let no_uid =
        status("4241", "1000\t1000\t1000\t1000").replace("Uid:\t1000\t1000\t1000\t1000\n", "");
    for text in [
        String::new(),
        no_ppid,
        no_uid,
        status("x", "1000\t1000\t1000\t1000"),
        status("4241", "1000"),
        status("4241", "1000\t1000\tx\t1000"),
    ] {
        assert!(peer_is_helper(&text, 4241, 1000).is_err(), "{text:?}");
    }
}

/// A row's bounds: the design's, with the first byte allowed the same.
const B: ControlBounds = CONTROL_BOUNDS;

/// T4, kills "a frame over the cap is read".
#[tokio::test]
async fn t4_a_line_over_one_kib_is_refused() {
    let fits = format!("{}\n", "a".repeat(MAX_LINE - 1));
    let mut reader = BufReader::new(fits.as_bytes());
    assert_eq!(
        read_line(&mut reader, B.frame, B)
            .await
            .expect("a full-size line"),
        "a".repeat(MAX_LINE - 1)
    );
    let over = format!("{}\n", "a".repeat(MAX_LINE));
    let mut reader = BufReader::new(over.as_bytes());
    assert!(read_line(&mut reader, B.frame, B).await.is_err());
}

/// T4, kills "a frame cut off by a close is taken as a line".
#[tokio::test]
async fn t4_a_line_cut_off_by_a_close_is_refused() {
    for text in ["", "{\"fetch_done\":tr"] {
        let mut reader = BufReader::new(text.as_bytes());
        assert!(
            read_line(&mut reader, B.frame, B).await.is_err(),
            "{text:?}"
        );
    }
}

/// T4, kills "a partial frame may stall forever" and "a silent peer may".
#[tokio::test(start_paused = true)]
async fn t4_a_stalled_frame_and_a_silent_peer_are_cut_off() {
    let (mut helper, gateway) = tokio::io::duplex(4096);
    helper.write_all(b"{\"fetch_").await.expect("write");
    let mut reader = BufReader::new(gateway);
    // The first byte arrived: the rest has `frame`, not the long `first`.
    let read = read_line(&mut reader, Duration::from_secs(3600), B);
    let read = tokio::time::timeout(GUARD, read).await;
    assert!(
        read.expect("a stalled frame was not cut off within the guard")
            .is_err(),
        "a stalled frame was read as a line"
    );
    let (_silent, gateway) = tokio::io::duplex(4096);
    let mut reader = BufReader::new(gateway);
    let read =
        tokio::time::timeout(GUARD, read_line(&mut reader, Duration::from_secs(10), B)).await;
    assert!(
        read.expect("a silent peer was not cut off within the guard")
            .is_err(),
        "a silent peer produced a line"
    );
    drop(helper);
}

/// Over the 10 s hang-guard floor and past every bound a row uses.
const GUARD: Duration = Duration::from_secs(15);

/// Accept one connection from this test process on a fresh socket, expecting
/// its parent to be `parent` and its uid `uid`.
#[cfg(target_os = "linux")]
async fn accept_from_self(parent: u32, uid: u32) -> Result<(), crate::preview_sandbox::Refusal> {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("control.sock");
    let listener = tokio::net::UnixListener::bind(&path).expect("bind");
    let connect = tokio::spawn(tokio::net::UnixStream::connect(path));
    let accepted = tokio::time::timeout(GUARD, super::accept_helper(listener, parent, uid, B))
        .await
        .expect("the accept did not end within the guard");
    let _peer = connect.await.expect("join");
    accepted.map(drop)
}

/// T8 on a real socket, kills "the peer's credentials are not read from the
/// kernel": the connecting process is this one, whose parent is the runner.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn t8_a_real_peer_is_judged_by_its_kernel_credentials() {
    let uid = rustix::process::getuid().as_raw();
    let parent = std::os::unix::process::parent_id();
    assert!(
        accept_from_self(parent, uid).await.is_ok(),
        "the real parent and uid"
    );
    assert!(
        accept_from_self(u32::MAX, uid).await.is_err(),
        "another parent"
    );
    assert!(
        accept_from_self(parent, uid.wrapping_add(1)).await.is_err(),
        "another uid"
    );
}

/// T8, kills "the accept waits for a helper forever".
#[tokio::test(start_paused = true)]
async fn t8_no_connection_within_the_bound_is_refused() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = tokio::net::UnixListener::bind(dir.path().join("control.sock")).expect("bind");
    let accepted = tokio::time::timeout(GUARD, super::accept_helper(listener, 1, 0, B))
        .await
        .expect("the accept did not end within the guard");
    assert!(accepted.is_err());
}

/// T8, kills "the first matching status line wins": a process name cannot
/// smuggle a second parent or uid line ahead of the real ones.
#[test]
fn t8_a_duplicated_status_field_is_refused() {
    let forged = format!(
        "Name:\tx\nPPid:\t4241\nUid:\t1000\t1000\t1000\t1000\n{}",
        status("1", "1000\t1000\t1000\t1000")
    );
    assert!(peer_is_helper(&forged, 4241, 1000).is_err());
}

/// T8, kills "the listener outlives the accept": once the helper's one
/// connection is taken, whatever the peer check said, no second connection
/// is served.
#[tokio::test]
async fn t8_no_second_connection_is_served() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("control.sock");
    let listener = tokio::net::UnixListener::bind(&path).expect("bind");
    let first = tokio::spawn(tokio::net::UnixStream::connect(path.clone()));
    let accepted = tokio::time::timeout(GUARD, super::accept_helper(listener, 1, 0, B))
        .await
        .expect("the accept did not end within the guard");
    drop(accepted);
    let _first = first.await.expect("join");
    assert!(tokio::net::UnixStream::connect(&path).await.is_err());
}

/// A `/proc/<pid>/stat` line: field 22, the start time, is `start`.
fn stat(name: &str, start: u64) -> String {
    format!("4242 ({name}) S 1 4242 4242 0 -1 4194560 10 0 0 0 0 0 0 0 20 0 1 0 {start} 1000 10")
}

/// T8, kills "the start time is not checked" and "a start in the accept's
/// own tick refuses": the pid must name a process no newer than the accept.
#[test]
fn t8_a_peer_started_after_the_accept_is_refused() {
    assert!(started_by(&stat("x", 101), 100).is_err(), "a later start");
    assert!(started_by(&stat("x", 100), 100).is_ok(), "the same tick");
    assert!(started_by(&stat("x", 99), 100).is_ok(), "an earlier start");
}

/// T8, kills "the fields are counted from the first ')'": a process name
/// holding ') 1 2' would otherwise shift the start time to a forged field.
#[test]
fn t8_a_crafted_process_name_cannot_shift_the_start_time() {
    assert!(started_by(&stat("a) 1 2", 500), 100).is_err());
}

/// T8, kills "an unreadable start time reads as early".
#[test]
fn t8_an_unreadable_start_time_is_refused() {
    let not_a_number = stat("x", 1).replace(" 1 1000", " y 1000");
    assert_ne!(not_a_number, stat("x", 1), "the start field was replaced");
    for text in [
        "",
        "4242 (x S 1 2",
        "4242 (x) S 1 2 3",
        not_a_number.as_str(),
    ] {
        assert!(started_by(text, u64::MAX).is_err(), "{text:?}");
    }
}

/// T8 on a real process, the kernel row (also run on the 5.4 target): a
/// `/proc/<pid>` directory opened while the child lived never reads its pid
/// again once the child is reaped, so a reused pid cannot be judged.
#[cfg(target_os = "linux")]
#[test]
fn t8_a_proc_directory_never_follows_a_reaped_pid() {
    use super::{boot_ticks, judge_dir, open_peer, read_peer};
    let uid = rustix::process::getuid().as_raw();
    let me = std::process::id();
    let before = boot_ticks();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn");
    let pid = i32::try_from(child.id()).expect("pid");
    let dir = open_peer(pid).expect("the live child's /proc directory");
    assert!(
        judge_dir(&dir, boot_ticks(), me, uid).is_ok(),
        "the live child"
    );
    assert!(
        judge_dir(&dir, 0, me, uid).is_err(),
        "a start after the accept"
    );
    assert!(
        judge_dir(&dir, before.saturating_sub(1), me, uid).is_err(),
        "a child spawned after the clock was read started after it"
    );
    assert!(
        judge_dir(&dir, boot_ticks(), me.wrapping_add(1), uid).is_err(),
        "another parent"
    );
    child.kill().expect("kill");
    child.wait().expect("reap");
    assert!(
        read_peer(&dir, "status").is_err(),
        "status of the reaped child"
    );
    assert!(read_peer(&dir, "stat").is_err(), "stat of the reaped child");
    assert!(
        judge_dir(&dir, u64::MAX, me, uid).is_err(),
        "the reaped child"
    );
}

/// A peer that stopped reading: no write ever completes.
struct Stuck;

impl tokio::io::AsyncWrite for Stuck {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Pending
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

/// T4, kills "a write waits for the peer forever": a helper that stops
/// reading its control socket cannot hold the session open past the bound.
#[tokio::test(start_paused = true)]
async fn t4_a_peer_that_stops_reading_is_cut_off() {
    let written = tokio::time::timeout(GUARD, super::write_line(&mut Stuck, "x", B))
        .await
        .expect("the write did not end within the guard");
    assert!(written.is_err());
}
