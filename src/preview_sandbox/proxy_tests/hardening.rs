// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Hardening rows: the proxy keeps accepting after an accept error, serves a
//! bounded number of connections, ends an admission a revoke or a deadline
//! has overtaken, and keeps its Unix directory private and unguessable.

use super::super::{Accept, MAX_CONNECTIONS, serve};
use super::{Entry, Rig, begin, connect_bytes, open, read_head, rig, status};
use async_trait::async_trait;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// A listener whose first accept fails, as a descriptor shortage would, and
/// whose later accepts are the real thing.
struct FailsOnce {
    inner: TcpListener,
    failed: AtomicBool,
}

#[async_trait]
impl Accept for FailsOnce {
    type Stream = TcpStream;
    async fn accept(&self) -> io::Result<TcpStream> {
        if !self.failed.swap(true, Ordering::SeqCst) {
            return Err(io::Error::other("too many open files"));
        }
        Accept::accept(&self.inner).await
    }
}

/// H1, kills "the accept loop ends on its first error": after a failed accept
/// the listener still serves, so a CONNECT without a credential is answered 407.
#[tokio::test]
async fn h1_the_listener_outlives_an_accept_error() {
    let rig = rig().await;
    let inner = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let port = inner.local_addr().expect("addr").port();
    let task = tokio::spawn(serve(
        FailsOnce {
            inner,
            failed: AtomicBool::new(false),
        },
        rig.proxy.shared.clone(),
    ));
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("connect");
    client
        .write_all(&connect_bytes("registry.npmjs.org:443", None))
        .await
        .expect("write");
    assert_eq!(status(&read_head(&mut client).await), 407);
    task.abort();
}

/// Holds `MAX_CONNECTIONS` connections open, each silent so each keeps its
/// permit while the proxy waits for a request head.
async fn fill_the_bound(rig: &Rig) -> Vec<TcpStream> {
    let mut held = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        held.push(
            TcpStream::connect((Ipv4Addr::LOCALHOST, rig.proxy.port()))
                .await
                .expect("connect"),
        );
    }
    // Every permit is taken once each held connection has been accepted and
    // its task is waiting on the head: poll the semaphore, not the clock.
    let waited = async {
        while rig.proxy.shared.permits.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    };
    tokio::time::timeout(Duration::from_secs(30), waited)
        .await
        .expect("the proxy never took every permit");
    held
}

/// H2, kills "no bound on connections": past the bound a connection is closed
/// at once, and the bound frees up when a held connection ends.
#[tokio::test]
async fn h2_connections_past_the_bound_are_dropped_and_the_bound_frees_up() {
    let rig = rig().await;
    let mut held = fill_the_bound(&rig).await;
    let mut extra = TcpStream::connect((Ipv4Addr::LOCALHOST, rig.proxy.port()))
        .await
        .expect("connect");
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(30), extra.read(&mut byte))
        .await
        .expect("the extra connection was left open");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "a connection past the bound was served: {read:?}"
    );
    drop(held.pop());
    let served = async {
        loop {
            let mut next = TcpStream::connect((Ipv4Addr::LOCALHOST, rig.proxy.port()))
                .await
                .expect("connect");
            if next
                .write_all(&connect_bytes("registry.npmjs.org:443", None))
                .await
                .is_ok()
                && status(&read_head(&mut next).await) == 407
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    };
    tokio::time::timeout(Duration::from_secs(30), served)
        .await
        .expect("the bound never freed up");
}

/// A CONNECT with the live credential, sent and left waiting on `gate`.
async fn stuck_connect(rig: &Rig, gate: &super::Gate, step: &str) -> tokio::task::JoinHandle<u16> {
    let cred = begin(rig);
    gate.close();
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let mut client = open(rig, Entry::Tcp, &bytes).await.expect("connect");
    tokio::time::timeout(Duration::from_secs(30), gate.entered.notified())
        .await
        .unwrap_or_else(|_| panic!("the CONNECT never reached {step}"));
    rig.proxy.revoke(&cred);
    tokio::spawn(async move { status(&client.head().await) })
}

/// H3, kills "resolution ignores revoke": a CONNECT stuck in a resolution that
/// never answers is refused once its fetch is revoked.
#[tokio::test]
async fn h3_a_revoke_ends_a_connect_stuck_in_resolution() {
    let rig = rig().await;
    let answer = stuck_connect(&rig, &rig.resolve.gate, "resolution").await;
    assert_eq!(answer.await.expect("answer"), 407);
}

/// H3, kills "the dial ignores revoke": the same for a dial that never answers.
#[tokio::test]
async fn h3_a_revoke_ends_a_connect_stuck_in_the_dial() {
    let rig = rig().await;
    let answer = stuck_connect(&rig, &rig.connect.gate, "the dial").await;
    assert_eq!(answer.await.expect("answer"), 407);
}

/// H4, kills "no admission deadline": with no revoke, a resolution that never
/// answers is cut off at the admission bound and answered 502.
#[tokio::test]
async fn h4_an_admission_past_its_bound_is_cut_off() {
    let rig = rig().await;
    rig.proxy.set_admit_bound(Duration::from_secs(1));
    let cred = begin(&rig);
    rig.resolve.gate.close();
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let mut client = open(&rig, Entry::Tcp, &bytes).await.expect("connect");
    assert_eq!(status(&client.head().await), 502);
}

/// H5, kills "a predictable or open Unix directory": two proxies get distinct
/// owner-only directories whose names carry neither the pid nor the port.
#[tokio::test]
async fn h5_the_unix_directory_is_private_and_unguessable() {
    use std::os::unix::fs::PermissionsExt as _;
    let first = rig().await;
    let second = rig().await;
    let dir = |rig: &Rig| {
        rig.proxy
            .unix_path()
            .parent()
            .expect("a directory")
            .to_owned()
    };
    let (a, b) = (dir(&first), dir(&second));
    assert_ne!(a, b, "two proxies shared one directory");
    for (dir, rig) in [(&a, &first), (&b, &second)] {
        let mode = std::fs::metadata(dir)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "the directory is not owner-only");
        let name = dir
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        assert!(
            !name.contains(&std::process::id().to_string()) || name.len() > 20,
            "{name}"
        );
        assert!(!name.contains(&rig.proxy.port().to_string()), "{name}");
    }
}

/// M-1: revoking a stale credential, once a newer fetch has begun, must not
/// touch the newer fetch's tunnels.
#[tokio::test]
async fn m1_a_stale_revoke_leaves_the_new_fetch_alone() {
    let rig = rig().await;
    let old = begin(&rig);
    let new = begin(&rig);
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&new.basic()));
    let mut tunnel = open(&rig, Entry::Tcp, &bytes).await.expect("connect");
    assert_eq!(status(&tunnel.head().await), 200);
    rig.proxy.revoke(&old);
    assert!(
        tunnel.echoes().await,
        "a stale revoke closed the new tunnel"
    );
}

/// M-1: a `begin_fetch` that fails to make a credential still ends the previous
/// fetch, so a failed start never leaves the old credential live.
#[tokio::test]
async fn m1_a_failed_begin_fetch_still_ends_the_previous_fetch() {
    let mut rig = rig().await;
    let old = begin(&rig);
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&old.basic()));
    let mut open_tunnel = open(&rig, Entry::Tcp, &bytes).await.expect("connect");
    assert_eq!(status(&open_tunnel.head().await), 200);
    let mut tunnel = open_tunnel.into_plain();
    rig.proxy.random = |_| Err(io::Error::other("no entropy"));
    assert!(rig.proxy.begin_fetch().is_err());
    let mut shut = false;
    for _ in 0..1_000 {
        if tunnel.peer_has_shut_down() {
            shut = true;
            break;
        }
        std::thread::yield_now();
    }
    assert!(shut, "the old fetch's tunnel outlived a failed begin_fetch");
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&old.basic()));
    let refused = super::send(&rig, Entry::Tcp, &bytes).await;
    assert_eq!(status(&refused), 407, "the old credential still works");
}

/// H6, kills "registration accepts a revoked fetch": the fetch is revoked from
/// inside the dial, at the moment the dial completes, so the dial itself is not
/// interrupted and registration alone must refuse. The CONNECT is answered 407
/// and no tunnel works.
#[tokio::test]
async fn h6_a_fetch_revoked_as_the_dial_completes_gets_no_tunnel() {
    let rig = rig().await;
    let cred = begin(&rig);
    let shared = rig.proxy.shared.clone();
    let revoked = cred.clone();
    *rig.connect.on_dial.lock().expect("lock") = Some(Box::new(move || shared.revoke(&revoked)));
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let mut client = open(&rig, Entry::Tcp, &bytes).await.expect("connect");
    assert_eq!(
        status(&client.head().await),
        407,
        "a tunnel was admitted for a fetch revoked at the dial"
    );
    assert!(client.closed().await, "a tunnel worked after the revoke");
}
