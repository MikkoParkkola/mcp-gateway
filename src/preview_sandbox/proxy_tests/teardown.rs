// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D4, T4c, T2: a fetch ends at its own deadline, a second revoke waits out
//! the first teardown, and revoke shuts the upstream half itself.

use super::{begin, connect_bytes, connect_status, open, rig, status};
use std::io::{ErrorKind, Read as _};
use std::net::TcpListener;
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::Duration;
use tokio::time::Instant;

/// How long a row waits for a deadline or a teardown. A missing behavior
/// fails the row here. Over the 10 s hang-guard floor and under the 30 s
/// production bounds, so a missing behavior fails at the guard, not at
/// another bound.
const GUARD: Duration = Duration::from_secs(15);

/// D4, kills "a fetch ignores its deadline and stays open until revoke".
#[tokio::test]
async fn d4_the_fetch_ends_at_its_deadline() {
    let rig = rig().await;
    let started = Instant::now();
    let cred = rig
        .proxy
        .begin_fetch(started + Duration::from_millis(400))
        .expect("credential");
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let mut tunnel = tokio::time::timeout(GUARD, open(&rig, &bytes))
        .await
        .expect("the connection was not accepted within the guard")
        .expect("connect");
    let head = tokio::time::timeout(GUARD, tunnel.head())
        .await
        .expect("the CONNECT was not answered within the guard");
    assert_eq!(status(&head), 200, "{head}");
    let echoed = tokio::time::timeout(GUARD, tunnel.echoes())
        .await
        .expect("the tunnel did not echo within the guard");
    assert!(echoed, "the tunnel was closed before its deadline");
    let closed = tokio::time::timeout(GUARD, async {
        loop {
            if tunnel.closed().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let elapsed = started.elapsed();
    assert!(closed.is_ok(), "the fetch stayed open past the guard");
    assert!(
        elapsed >= Duration::from_millis(350),
        "closed after {elapsed:?}, before its deadline"
    );
    let refused =
        tokio::time::timeout(GUARD, connect_status(&rig, "registry.npmjs.org:443", &cred))
            .await
            .expect("the credential was not refused within the guard");
    assert_eq!(refused, 407, "the credential worked after its deadline");
}

/// D4, kills "a stale deadline ends the fetch that replaced it".
#[tokio::test]
async fn d4_a_stale_deadline_leaves_the_next_fetch_alone() {
    let rig = rig().await;
    let now = Instant::now();
    let _first = rig
        .proxy
        .begin_fetch(now + Duration::from_millis(300))
        .expect("credential");
    let second = rig
        .proxy
        .begin_fetch(now + Duration::from_secs(60))
        .expect("credential");
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&second.basic()));
    let mut tunnel = tokio::time::timeout(GUARD, open(&rig, &bytes))
        .await
        .expect("the connection was not accepted within the guard")
        .expect("connect");
    let head = tokio::time::timeout(GUARD, tunnel.head())
        .await
        .expect("the CONNECT was not answered within the guard");
    assert_eq!(status(&head), 200, "{head}");
    // Past the first fetch's 300 ms deadline, inside the second's minute. A
    // slow runner can only fire the stale timer later, which passes the row;
    // it cannot fail it.
    // timing: absence
    tokio::time::sleep(Duration::from_millis(600)).await;
    let echoed = tokio::time::timeout(GUARD, tunnel.echoes())
        .await
        .expect("the next fetch's tunnel did not answer within the guard");
    assert!(echoed, "a stale deadline closed the next fetch's tunnel");
    let again = tokio::time::timeout(
        GUARD,
        connect_status(&rig, "registry.npmjs.org:443", &second),
    )
    .await
    .expect("the next fetch's credential was not answered within the guard");
    assert_eq!(again, 200, "a stale deadline refused the next fetch");
}

/// T4c, kills "a second revoke returns while the first teardown still runs".
#[tokio::test]
async fn t4c_a_second_revoke_waits_for_the_first_teardown() {
    let rig = rig().await;
    let cred = begin(&rig);
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let mut tunnel = tokio::time::timeout(GUARD, open(&rig, &bytes))
        .await
        .expect("the connection was not accepted within the guard")
        .expect("connect");
    let head = tokio::time::timeout(GUARD, tunnel.head())
        .await
        .expect("the CONNECT was not answered within the guard");
    assert_eq!(status(&head), 200, "{head}");
    let mut plain = tunnel.into_plain();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    rig.proxy.set_on_end(Box::new(move || {
        let _ = entered_tx.send(());
        let _ = release_rx.lock().expect("lock").recv();
    }));
    thread::scope(|scope| {
        let first = scope.spawn(|| rig.proxy.revoke(&cred));
        entered_rx
            .recv_timeout(GUARD)
            .expect("the first revoke never reached teardown");
        let second = scope.spawn(|| rig.proxy.revoke(&cred));
        // A second revoke that does not wait returns at once; a slow runner
        // can only make it return later, which passes the row, never fails it.
        // timing: absence
        thread::sleep(Duration::from_millis(200));
        // Taken while the first revoke is still inside the hook. Sent before
        // the assert so that failure still lets the parked revoke finish.
        let second_finished = second.is_finished();
        release_tx.send(()).expect("release");
        assert!(
            !second_finished,
            "a second revoke returned while the first teardown was still running"
        );
        first.join().expect("first revoke");
        second.join().expect("second revoke");
    });
    assert!(
        plain.peer_has_shut_down(),
        "the tunnel was still open after both revokes"
    );
}

/// T2, kills "revoke shuts the client half and leaves the upstream open".
#[tokio::test(flavor = "current_thread")]
async fn t2_revoke_closes_the_upstream_half() {
    let rig = rig().await;
    let cred = begin(&rig);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    *rig.connect.target.lock().expect("lock") = Some(listener.local_addr().expect("addr"));
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let mut tunnel = tokio::time::timeout(GUARD, open(&rig, &bytes))
        .await
        .expect("the connection was not accepted within the guard")
        .expect("connect");
    let head = tokio::time::timeout(GUARD, tunnel.head())
        .await
        .expect("the CONNECT was not answered within the guard");
    assert_eq!(status(&head), 200, "{head}");
    // The dial already completed, so this accept returns at once. Nothing
    // awaits between the revoke and the read: a task cannot have run.
    let mut upstream = listener.accept().expect("accept").0;
    upstream.set_nonblocking(true).expect("nonblocking");
    rig.proxy.revoke(&cred);
    let mut byte = [0u8; 1];
    let read = upstream.read(&mut byte);
    let shut = match &read {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => e.kind() != ErrorKind::WouldBlock,
    };
    assert!(shut, "revoke left the upstream half open: {read:?}");
}
