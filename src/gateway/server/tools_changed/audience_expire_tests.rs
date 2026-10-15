// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 A-EXPIRE: an Open `WebUI` assertion a stream was admitted under
//! has a window; a stream held past it is dead, judged by the same function
//! and inclusive boundary admission used (D11, D16). The adapter's skew is
//! its default, 30 seconds; the assertion lives 120.

use super::audience_fixture::{World, adapter_assertion, tool};

const SKEW: u64 = 30;
const LIFETIME: u64 = 120;

fn alpha_with(read: &str) -> Vec<crate::protocol::Tool> {
    vec![
        tool("read", read),
        tool("write", "w"),
        tool("scan", "s"),
        tool("fetch", "f"),
    ]
}

/// A-EXPIRE (a) and (b): at the last inclusive second the stream is live and
/// told; one second later it is dead and closed. The API-key bearer is live
/// throughout, so the assertion alone decides.
#[tokio::test]
async fn a_expire_a_stream_past_its_assertion_window_is_closed() {
    let w = World::start_adapter(|meta| meta).await;
    let issued = crate::clock::unix_secs().expect("clock after 1970");
    let alice = adapter_assertion("alice");
    let mut ear = w.listen_as("k-std", Some(&alice)).await;

    let last_live = crate::clock::test_clock::at_secs(issued + LIFETIME + SKEW);
    w.store_shared("alpha", alpha_with("r2"));
    assert_eq!(
        ear.told(&w).await,
        1,
        "at the inclusive boundary it is live"
    );
    drop(last_live);

    let _past = crate::clock::test_clock::at_secs(issued + LIFETIME + SKEW + 1);
    w.store_shared("alpha", alpha_with("r3"));
    assert!(
        ear.closed(&w).await,
        "one second past the window it is dead"
    );
}

/// A-EXPIRE (a), GET stream: the same on the legacy stream, through the real
/// route.
#[tokio::test]
async fn a_expire_a_get_stream_past_its_assertion_window_is_closed() {
    let w = World::start_adapter(|meta| meta).await;
    let issued = crate::clock::unix_secs().expect("clock after 1970");
    let alice = adapter_assertion("alice");
    let mut ear = w.sse_as("k-std", Some(&alice)).await;
    let _past = crate::clock::test_clock::at_secs(issued + LIFETIME + SKEW + 1);
    w.store_shared("alpha", alpha_with("r2"));
    assert_eq!(ear.told(&w).await, 0, "a dead stream is told nothing");
    assert!(
        !ear.is_open(&w).await,
        "one second past the window the GET stream itself has ended, not merely gone quiet"
    );

    let fresh = adapter_assertion("alice");
    let mut live = w.sse_as("k-std", Some(&fresh)).await;
    assert_eq!(
        live.told(&w).await,
        0,
        "a fresh live stream attached after r2 is told nothing further"
    );
    assert!(
        live.is_open(&w).await,
        "a fresh live stream at the same instant stays open while quiet"
    );
}
