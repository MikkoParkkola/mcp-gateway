// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The four time bounds: admission, the request head, each dial, and a
//! tunnel's lifetime.

use super::super::{BOUNDS, Bounds};
use super::{GLOBAL, NPM, OTHER, begin, connect_bytes, open, read_head, rig, status};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;

/// How long a row waits for a bound. A missing bound fails the row here.
/// Over the 10 s hang-guard floor and under the 30 s production bounds.
const GUARD: Duration = Duration::from_secs(15);

/// D0, kills "the production bounds differ from the design".
#[test]
fn d0_the_production_bounds_are_the_designs() {
    assert_eq!(
        BOUNDS,
        Bounds {
            admit: Duration::from_secs(30),
            head: Duration::from_secs(5),
            dial: Duration::from_secs(5),
            splice: Duration::from_secs(30),
        }
    );
}

/// D1, kills "a silent client waits out a hard-coded 30 s head read".
#[tokio::test]
async fn d1_a_silent_client_is_cut_off_at_the_head_bound() {
    let rig = rig().await;
    rig.proxy.set_bounds(Bounds {
        head: Duration::from_millis(200),
        // Well past GUARD: a head read that waits on the admission bound
        // instead of the head bound fails at the guard, not with a 400.
        admit: Duration::from_secs(60),
        ..BOUNDS
    });
    let mut client = tokio::time::timeout(GUARD, UnixStream::connect(rig.proxy.unix_path()))
        .await
        .expect("the connection was not accepted within the guard")
        .expect("connect");
    let started = Instant::now();
    let head = tokio::time::timeout(GUARD, read_head(&mut client))
        .await
        .expect("a silent client was not cut off within the guard");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(150),
        "cut off after {elapsed:?}, before the head bound"
    );
    let code = status(&head);
    assert!(
        code == 400 || code == 0,
        "a silent client got {code}: {head:?}"
    );
}

/// D2, kills "a hung dial is never abandoned for the next address".
#[tokio::test]
async fn d2_a_hanging_dial_moves_on_to_the_next_address() {
    let rig = rig().await;
    rig.proxy.set_bounds(Bounds {
        dial: Duration::from_millis(200),
        admit: Duration::from_secs(10),
        ..BOUNDS
    });
    rig.resolve.set(NPM, vec![OTHER, GLOBAL]);
    let first = SocketAddr::new(OTHER, 443);
    *rig.connect.hang.lock().expect("lock") = Some(first);
    let cred = begin(&rig);
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let mut client = tokio::time::timeout(GUARD, open(&rig, &bytes))
        .await
        .expect("the connection was not accepted within the guard")
        .expect("connect");
    let head = tokio::time::timeout(GUARD, client.head())
        .await
        .expect("a hanging dial was not answered within the guard");
    assert_eq!(status(&head), 200, "{head}");
    assert_eq!(
        rig.connect.dials(),
        vec![first, SocketAddr::new(GLOBAL, 443)]
    );
}

/// D3, kills "an open tunnel lives until the fetch ends".
#[tokio::test]
async fn d3_a_tunnel_closes_at_its_splice_bound() {
    let rig = rig().await;
    rig.proxy.set_bounds(Bounds {
        splice: Duration::from_millis(400),
        ..BOUNDS
    });
    let cred = begin(&rig);
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let mut client = tokio::time::timeout(GUARD, open(&rig, &bytes))
        .await
        .expect("the connection was not accepted within the guard")
        .expect("connect");
    let head = tokio::time::timeout(GUARD, client.head())
        .await
        .expect("the CONNECT was not answered within the guard");
    assert_eq!(status(&head), 200, "{head}");
    let admitted = Instant::now();
    let echoed = tokio::time::timeout(GUARD, client.echoes())
        .await
        .expect("the tunnel did not echo within the guard");
    assert!(echoed, "the tunnel was closed before its splice bound");
    let closed = tokio::time::timeout(GUARD, async {
        loop {
            if client.closed().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let elapsed = admitted.elapsed();
    assert!(closed.is_ok(), "the tunnel stayed open past the guard");
    assert!(
        elapsed >= Duration::from_millis(350),
        "closed after {elapsed:?}, before the splice bound"
    );
    assert_eq!(rig.proxy.open_tunnels(), 0);
}
