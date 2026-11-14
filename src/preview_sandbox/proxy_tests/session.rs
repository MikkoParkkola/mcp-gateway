// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T4: the control session issues the fetch's credential, answers `expired`
//! only once that credential's tunnels are shut, and revokes on any other
//! line or a closed socket.

use super::super::super::control::{CONTROL_BOUNDS, serve_session};
use super::{Rig, connect_bytes, open, rig, send, status};
use std::os::fd::AsFd as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::UnixStream;

const NPM: &str = "registry.npmjs.org:443";

/// Over the 10 s hang-guard floor; a session that waits on a line that never
/// comes fails here instead of hanging the row.
const GUARD: Duration = Duration::from_secs(15);

fn basic(secret: &str) -> String {
    use base64::Engine as _;
    let raw = format!("x:{secret}");
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

/// The status a CONNECT under `secret` gets.
async fn status_under(rig: &Rig, secret: &str) -> u16 {
    status(&send(rig, &connect_bytes(NPM, Some(&basic(secret)))).await)
}

fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(60)
}

/// The credential out of the gateway's answer to `fetch_start`.
fn secret_of(line: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(line).expect("credential line");
    let secret = v["credential"]
        .as_str()
        .expect("credential field")
        .to_owned();
    assert_eq!(secret.len(), 64, "{line}");
    assert!(v["deadline_ms"].as_u64().is_some_and(|ms| ms > 0), "{line}");
    secret
}

/// T4, kills "expired is sent before the credential's tunnels are shut".
#[tokio::test(flavor = "current_thread")]
async fn s1_expired_comes_only_after_the_credentials_tunnels_are_shut() {
    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    // When the revoke starts, nothing may be waiting for the helper yet: the
    // gateway writes `expired` only after the revoke shut every tunnel.
    let probe = helper.as_fd().try_clone_to_owned().expect("dup");
    let waiting = Arc::new(Mutex::new(None));
    let seen = waiting.clone();
    rig.proxy.set_on_end(Box::new(move || {
        let queued = rustix::io::ioctl_fionread(&probe).unwrap_or(u64::MAX);
        *seen.lock().expect("lock") = Some(queued);
    }));
    let session = serve_session(gateway, &rig.proxy, deadline(), CONTROL_BOUNDS);
    let script = async {
        let (read, mut write) = helper.into_split();
        let mut read = BufReader::new(read);
        write
            .write_all(b"{\"fetch_start\":true}\n")
            .await
            .expect("write");
        let mut line = String::new();
        read.read_line(&mut line).await.expect("credential");
        let secret = secret_of(&line);
        let mut tunnel = open(&rig, &connect_bytes(NPM, Some(&basic(&secret))))
            .await
            .expect("open");
        assert_eq!(status(&tunnel.head().await), 200);
        write
            .write_all(b"{\"fetch_done\":true}\n")
            .await
            .expect("write");
        line.clear();
        read.read_line(&mut line).await.expect("expired");
        assert_eq!(line, "{\"expired\":true}\n");
        assert!(tunnel.closed().await, "the tunnel outlived `expired`");
        secret
    };
    let (served, secret) = tokio::join!(session, script);
    served.expect("the session");
    assert_eq!(
        *waiting.lock().expect("lock"),
        Some(0),
        "`expired` was queued before the revoke"
    );
    assert_eq!(status_under(&rig, &secret).await, 407);
}

/// T4, kills "an out-of-order, false or unrecognised line is accepted".
#[tokio::test(flavor = "current_thread")]
async fn s2_any_other_line_ends_the_session_and_revokes() {
    let first = [
        "{\"fetch_done\":true}",
        "{\"fetch_start\":false}",
        "{\"fetch_start\":true,\"extra\":1}",
        "not json",
    ];
    for line in first {
        let rig = rig().await;
        let (mut helper, gateway) = UnixStream::pair().expect("pair");
        helper
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("write");
        let served = serve_session(gateway, &rig.proxy, deadline(), CONTROL_BOUNDS);
        let served = tokio::time::timeout(GUARD, served)
            .await
            .unwrap_or_else(|_| panic!("{line}: the session did not end within the guard"));
        assert!(served.is_err(), "{line}");
    }
    // After the credential: a second fetch_start, an unknown key, or a false
    // fetch_done ends the session, and the credential stops working.
    for line in [
        "{\"fetch_start\":true}",
        "{\"fetch_done\":true,\"x\":0}",
        "{\"fetch_done\":false}",
    ] {
        let rig = rig().await;
        let (helper, gateway) = UnixStream::pair().expect("pair");
        let session = serve_session(gateway, &rig.proxy, deadline(), CONTROL_BOUNDS);
        let script = async {
            let (read, mut write) = helper.into_split();
            let mut read = BufReader::new(read);
            write
                .write_all(b"{\"fetch_start\":true}\n")
                .await
                .expect("write");
            let mut issued = String::new();
            read.read_line(&mut issued).await.expect("credential");
            write
                .write_all(format!("{line}\n").as_bytes())
                .await
                .expect("write");
            secret_of(&issued)
        };
        let (served, secret) = tokio::join!(session, script);
        assert!(served.is_err(), "{line}");
        assert_eq!(status_under(&rig, &secret).await, 407, "{line}");
    }
}

/// T4, kills "a helper that dies mid-fetch leaves its credential live".
#[tokio::test(flavor = "current_thread")]
async fn s3_a_closed_socket_mid_fetch_revokes_the_credential() {
    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    let session = serve_session(gateway, &rig.proxy, deadline(), CONTROL_BOUNDS);
    let script = async {
        let (read, mut write) = helper.into_split();
        let mut read = BufReader::new(read);
        write
            .write_all(b"{\"fetch_start\":true}\n")
            .await
            .expect("write");
        let mut issued = String::new();
        read.read_line(&mut issued).await.expect("credential");
        drop((read, write));
        secret_of(&issued)
    };
    let (served, secret) = tokio::join!(session, script);
    assert!(served.is_err());
    assert_eq!(status_under(&rig, &secret).await, 407);
}

/// T4, kills "a dropped session leaves its credential live": the session
/// future is dropped right after the credential went out.
#[tokio::test(flavor = "current_thread")]
async fn s4_a_dropped_session_revokes_the_credential() {
    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    let (read, mut write) = helper.into_split();
    let mut read = BufReader::new(read);
    let secret = {
        let session = serve_session(gateway, &rig.proxy, deadline(), CONTROL_BOUNDS);
        tokio::pin!(session);
        write
            .write_all(b"{\"fetch_start\":true}\n")
            .await
            .expect("write");
        let mut issued = String::new();
        tokio::select! {
            _ = &mut session => panic!("the session ended before the credential was read"),
            read = read.read_line(&mut issued) => { read.expect("credential"); }
        }
        secret_of(&issued)
    };
    assert_eq!(status_under(&rig, &secret).await, 407);
}
