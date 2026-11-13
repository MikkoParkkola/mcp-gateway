// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C5/R3, C10: expiry closes tunnels already open and leaves none usable from
//! a CONNECT suspended in resolution or in the dial.

use super::{
    Credential, Entry, Opened, Rig, begin, connect_bytes, open, read_head, rig, status,
    tunnel_echoes,
};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;

/// An open, working tunnel through `entry` under `cred`.
async fn open_tunnel(rig: &Rig, entry: Entry, cred: &Credential) -> Opened {
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let mut t = open(rig, entry, &bytes).await.expect("connect");
    assert_eq!(status(&t.head().await), 200);
    assert!(t.echoes().await, "tunnel does not echo before expiry");
    t
}

/// C5, kills "tunnels kept on expiry": expiry closes a tunnel already open.
#[tokio::test]
async fn c5_expiry_closes_tunnels_already_open() {
    let rig = rig().await;
    let cred = begin(&rig);
    let mut t = open_tunnel(&rig, Entry::Tcp, &cred).await;
    rig.proxy.revoke(&cred);
    assert!(t.closed().await, "tunnel survived expiry");
}

/// R3, kills "tunnels kept on expiry" on the Unix socket.
#[tokio::test]
async fn r3_expiry_closes_tunnels_opened_through_the_unix_socket() {
    let rig = rig().await;
    let cred = begin(&rig);
    let mut t = open_tunnel(&rig, Entry::Unix, &cred).await;
    rig.proxy.revoke(&cred);
    assert!(t.closed().await, "tunnel survived expiry");
}

/// C10, kills "a tunnel usable after expiry": expiry while a CONNECT is
/// suspended in resolution leaves no usable tunnel and no dial.
#[tokio::test]
async fn c10_expiry_during_resolution_leaves_no_usable_tunnel() {
    let rig = rig().await;
    let cred = begin(&rig);
    rig.resolve.gate.close();
    let port = rig.proxy.port();
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let task = tokio::spawn(async move {
        let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.ok()?;
        s.write_all(&bytes).await.ok()?;
        let ok = status(&read_head(&mut s).await) == 200 && tunnel_echoes(&mut s).await;
        Some(ok)
    });
    reached(&rig.resolve.gate, "resolution").await;
    rig.proxy.revoke(&cred);
    rig.resolve.gate.release.notify_one();
    let usable = task.await.expect("task");
    assert_ne!(usable, Some(true), "a tunnel was usable after expiry");
    assert!(rig.connect.dials().is_empty(), "dialled after expiry");
}

/// C10, kills "a tunnel usable after expiry": expiry while a CONNECT is
/// suspended in the dial leaves no usable tunnel.
#[tokio::test]
async fn c10_expiry_during_dialling_leaves_no_usable_tunnel() {
    let rig = rig().await;
    let cred = begin(&rig);
    rig.connect.gate.close();
    let port = rig.proxy.port();
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let task = tokio::spawn(async move {
        let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.ok()?;
        s.write_all(&bytes).await.ok()?;
        let ok = status(&read_head(&mut s).await) == 200 && tunnel_echoes(&mut s).await;
        Some(ok)
    });
    reached(&rig.connect.gate, "the dial").await;
    rig.proxy.revoke(&cred);
    rig.connect.gate.release.notify_one();
    let usable = task.await.expect("task");
    assert_ne!(usable, Some(true), "a tunnel was usable after expiry");
}

/// M-1, kills "revoke only wakes the tunnels' tasks": `revoke` itself shuts an
/// open tunnel's two halves, so the peer sees the close with no proxy task
/// polled in between. A single-threaded runtime and no `await` after `revoke`
/// make that checkable: only a synchronous shutdown can have closed it.
async fn revoke_closes_the_tunnel_at_once(entry: Entry) {
    let rig = rig().await;
    let cred = begin(&rig);
    let mut tunnel = open_tunnel(&rig, entry, &cred).await.into_plain();
    assert!(!tunnel.peer_has_shut_down(), "closed before the revoke");
    rig.proxy.revoke(&cred);
    let mut shut = false;
    for _ in 0..1_000 {
        if tunnel.peer_has_shut_down() {
            shut = true;
            break;
        }
        std::thread::yield_now();
    }
    assert!(shut, "revoke returned with the tunnel still open");
}

#[tokio::test(flavor = "current_thread")]
async fn m1_revoke_shuts_a_tcp_tunnel_before_any_task_runs() {
    revoke_closes_the_tunnel_at_once(Entry::Tcp).await;
}

#[tokio::test(flavor = "current_thread")]
async fn m1_revoke_shuts_a_unix_tunnel_before_any_task_runs() {
    revoke_closes_the_tunnel_at_once(Entry::Unix).await;
}

/// M-1: a new fetch's `begin_fetch` ends the previous fetch's tunnels the same
/// way, not only a `revoke`.
#[tokio::test(flavor = "current_thread")]
async fn m1_a_new_fetch_shuts_the_previous_tunnels_before_any_task_runs() {
    let rig = rig().await;
    let old = begin(&rig);
    let mut tunnel = open_tunnel(&rig, Entry::Tcp, &old).await.into_plain();
    let _new = begin(&rig);
    let mut shut = false;
    for _ in 0..1_000 {
        if tunnel.peer_has_shut_down() {
            shut = true;
            break;
        }
        std::thread::yield_now();
    }
    assert!(shut, "begin_fetch returned with the old tunnel still open");
}

/// M-1: tunnel registration races `revoke`. Several CONNECTs run while the
/// fetch is revoked; once `revoke` has returned, no tunnel may still work,
/// whichever side of the revoke it was admitted on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m1_registration_racing_a_revoke_leaves_no_working_tunnel() {
    for round in 0..40 {
        let rig = std::sync::Arc::new(rig().await);
        let cred = begin(&rig);
        let mut attempts = Vec::new();
        for _ in 0..6 {
            let rig = rig.clone();
            let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
            attempts.push(tokio::spawn(async move {
                let mut t = open(&rig, Entry::Tcp, &bytes).await?;
                (status(&t.head().await) == 200).then_some(t)
            }));
        }
        for _ in 0..round % 5 {
            tokio::task::yield_now().await;
        }
        rig.proxy.revoke(&cred);
        for attempt in attempts {
            if let Some(mut tunnel) = attempt.await.expect("attempt") {
                assert!(
                    tunnel.closed().await,
                    "round {round}: a tunnel still worked after revoke returned"
                );
            }
        }
    }
}

/// Wait for the CONNECT to reach `gate`; a proxy that never gets there fails
/// the row instead of hanging it.
async fn reached(gate: &super::Gate, step: &str) {
    tokio::time::timeout(Duration::from_secs(30), gate.entered.notified())
        .await
        .unwrap_or_else(|_| panic!("the CONNECT never reached {step}"));
}
