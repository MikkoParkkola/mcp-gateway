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
    rig.proxy.expire(&cred);
    assert!(t.closed().await, "tunnel survived expiry");
}

/// R3, kills "tunnels kept on expiry" on the Unix socket.
#[tokio::test]
async fn r3_expiry_closes_tunnels_opened_through_the_unix_socket() {
    let rig = rig().await;
    let cred = begin(&rig);
    let mut t = open_tunnel(&rig, Entry::Unix, &cred).await;
    rig.proxy.expire(&cred);
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
    rig.proxy.expire(&cred);
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
    rig.proxy.expire(&cred);
    rig.connect.gate.release.notify_one();
    let usable = task.await.expect("task");
    assert_ne!(usable, Some(true), "a tunnel was usable after expiry");
}

/// Wait for the CONNECT to reach `gate`; a proxy that never gets there fails
/// the row instead of hanging it.
async fn reached(gate: &super::Gate, step: &str) {
    tokio::time::timeout(Duration::from_secs(30), gate.entered.notified())
        .await
        .unwrap_or_else(|_| panic!("the CONNECT never reached {step}"));
}
