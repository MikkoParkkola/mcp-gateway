// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C5/R3, C10: expiry closes tunnels already open and leaves none usable from
//! a CONNECT suspended in resolution or in the dial.

use super::{
    Credential, Opened, Rig, begin, connect_bytes, open, read_head, rig, status, tunnel_echoes,
};
use std::time::Duration;
use tokio::io::AsyncWriteExt as _;
use tokio::net::UnixStream;

/// An open, working tunnel under `cred`.
async fn open_tunnel(rig: &Rig, cred: &Credential) -> Opened {
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let mut t = open(rig, &bytes).await.expect("connect");
    assert_eq!(status(&t.head().await), 200);
    assert!(t.echoes().await, "tunnel does not echo before expiry");
    t
}

/// R3, kills "tunnels kept on expiry" on the Unix socket.
#[tokio::test]
async fn r3_expiry_closes_tunnels_opened_through_the_unix_socket() {
    let rig = rig().await;
    let cred = begin(&rig);
    let mut t = open_tunnel(&rig, &cred).await;
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
    let path = rig.proxy.unix_path().to_owned();
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let task = tokio::spawn(async move {
        let mut s = UnixStream::connect(&path).await.ok()?;
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
    let path = rig.proxy.unix_path().to_owned();
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let task = tokio::spawn(async move {
        let mut s = UnixStream::connect(&path).await.ok()?;
        s.write_all(&bytes).await.ok()?;
        let answer = status(&read_head(&mut s).await);
        let usable = answer == 200 && tunnel_echoes(&mut s).await;
        Some((answer, usable))
    });
    reached(&rig.connect.gate, "the dial").await;
    rig.proxy.revoke(&cred);
    rig.connect.gate.release.notify_one();
    let (answer, usable) = task.await.expect("task").expect("the connection was made");
    assert!(!usable, "a tunnel was usable after expiry");
    // Registering the tunnel is the check after the dial: it refuses, rather
    // than admitting a tunnel that then has to be closed.
    assert_eq!(answer, 407, "the CONNECT revoked mid-dial was not refused");
}

/// M-1, kills "revoke only wakes the tunnels' tasks": `revoke` itself shuts an
/// open tunnel's two halves, so the peer sees the close with no proxy task
/// polled in between. A single-threaded runtime and no `await` after `revoke`
/// make that checkable: only a synchronous shutdown can have closed it.
async fn revoke_closes_the_tunnel_at_once() {
    let rig = rig().await;
    let cred = begin(&rig);
    let mut tunnel = open_tunnel(&rig, &cred).await.into_plain();
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
async fn m1_revoke_shuts_a_unix_tunnel_before_any_task_runs() {
    revoke_closes_the_tunnel_at_once().await;
}

/// M-1: a new fetch's `begin_fetch` ends the previous fetch's tunnels the same
/// way, not only a `revoke`.
#[tokio::test(flavor = "current_thread")]
async fn m1_a_new_fetch_shuts_the_previous_tunnels_before_any_task_runs() {
    let rig = rig().await;
    let old = begin(&rig);
    let mut tunnel = open_tunnel(&rig, &old).await.into_plain();
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

/// M-1: a tunnel that ends on its own leaves the registry, so a long fetch
/// does not pile up sockets it will never need to shut.
#[tokio::test]
async fn m1_a_finished_tunnel_leaves_the_registry() {
    let rig = rig().await;
    let cred = begin(&rig);
    let tunnel = open_tunnel(&rig, &cred).await;
    assert_eq!(rig.proxy.open_tunnels(), 1, "the tunnel was not registered");
    drop(tunnel);
    let gone = async {
        while rig.proxy.open_tunnels() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(30), gone)
        .await
        .expect("a finished tunnel stayed in the registry");
}

/// Wait for the CONNECT to reach `gate`; a proxy that never gets there fails
/// the row instead of hanging it.
async fn reached(gate: &super::Gate, step: &str) {
    tokio::time::timeout(Duration::from_secs(30), gate.entered.notified())
        .await
        .unwrap_or_else(|_| panic!("the CONNECT never reached {step}"));
}
