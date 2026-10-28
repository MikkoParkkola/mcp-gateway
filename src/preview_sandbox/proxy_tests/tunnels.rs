// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C5/R3, C10: expiry closes tunnels already open and leaves none usable from
//! a CONNECT suspended in resolution or in the dial.

use super::{
    Credential, Entry, Opened, Rig, begin, connect_bytes, open, read_head, rig, status,
    tunnel_echoes,
};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

impl Opened {
    async fn head(&mut self) -> String {
        match self {
            Self::Tcp(s) => read_head(s).await,
            Self::Unix(s) => read_head(s).await,
        }
    }

    async fn echoes(&mut self) -> bool {
        match self {
            Self::Tcp(s) => tunnel_echoes(s).await,
            Self::Unix(s) => tunnel_echoes(s).await,
        }
    }

    /// True when the stream is dead: a write or read fails or hits EOF.
    async fn closed(&mut self) -> bool {
        !self.echoes().await
    }
}

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
    rig.resolve.gate.entered.notified().await;
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
    rig.connect.gate.entered.notified().await;
    rig.proxy.expire(&cred);
    rig.connect.gate.release.notify_one();
    let usable = task.await.expect("task");
    assert_ne!(usable, Some(true), "a tunnel was usable after expiry");
}
