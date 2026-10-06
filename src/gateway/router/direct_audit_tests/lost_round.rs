// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7979 on the direct route (`POST /mcp/{backend}`), which settles a
//! failed call in its own `settle_direct_failure`: a lost round serves a
//! same-key retry the uncertain notice under the original code, and a
//! pre-send refusal frees the key.

use super::*;

const KEY: &str = "k-7979";
const UNCERTAIN: &str = "outcome is unknown";

fn keyed(fail: fn() -> crate::Error) -> Setup {
    Setup {
        backend_fail: Some(fail),
        meta_mode: MetaMode::Idempotent,
        ..Setup::default()
    }
}

/// MIK-7979.SETTLE.1: the request left and the transport failed with no
/// answer. The retry is not run again and is told the outcome is unknown,
/// under the code the first caller got.
#[tokio::test]
async fn a_direct_lost_round_serves_the_uncertain_notice() {
    let fx = fixture(keyed(|| crate::Error::Transport("connection reset".into()))).await;
    let (_, first) = post_modern(&fx, "/mcp/alpha", &direct_call("cust-1", Some(KEY))).await;
    let reached = fx.calls.load(Ordering::SeqCst);
    assert!(reached >= 1, "{first}");

    let (_, retry) = post_modern(&fx, "/mcp/alpha", &direct_call("cust-1", Some(KEY))).await;
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        reached,
        "the retry ran again: {retry}"
    );
    assert_eq!(retry["error"]["code"], first["error"]["code"], "{retry}");
    let message = retry["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains(UNCERTAIN), "{retry}");
}

/// MIK-7979.SETTLE.3: a `BackendUnavailable` is raised before the request is
/// sent, so the direct route frees the key and the retry runs.
#[tokio::test]
async fn a_direct_backend_unavailable_frees_the_key() {
    let fx = fixture(keyed(|| crate::Error::BackendUnavailable("alpha".into()))).await;
    let _ = post_modern(&fx, "/mcp/alpha", &direct_call("cust-1", Some(KEY))).await;
    let reached = fx.calls.load(Ordering::SeqCst);
    let (_, retry) = post_modern(&fx, "/mcp/alpha", &direct_call("cust-1", Some(KEY))).await;
    assert!(
        fx.calls.load(Ordering::SeqCst) > reached,
        "a freed key lets the retry run: {retry}"
    );
}
