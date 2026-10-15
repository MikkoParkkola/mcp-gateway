// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 rows that need the real GET stream (test plan S4c): the stream is
//! opened through `mcp_sse_handler` and read through its SSE body, so every
//! frame passes the write-time credential check (`credential_at_write`). The
//! bare receiver of `World::legacy` never reaches it.

use super::audience_fixture::{World, scoped_token, tool};

fn alpha_with(read: &str, write: &str) -> Vec<crate::protocol::Tool> {
    vec![
        tool("read", read),
        tool("write", write),
        tool("scan", "s"),
        tool("fetch", "f"),
    ]
}

/// Harness guard (GREEN on base): a visible change reaches a live GET stream,
/// so the SSE ear can tell "told" from "not told".
#[tokio::test]
async fn sse_a_visible_change_reaches_a_live_get_stream() {
    let w = World::start().await;
    let mut ear = w.sse("k-std").await;
    w.store_shared("alpha", alpha_with("r2", "w"));
    assert_eq!(ear.told(&w).await, 1, "k-std sees read: the stream is live");
}

/// M-B2' (MIK-8350), killer M4: a frame withheld AT WRITE leaves what the
/// listener was last told unchanged, so a later change it cannot see delivers
/// the withheld one; a further hidden-only change then sends nothing.
///
/// The token sees `write`, `scan` and `fetch`, not `read`. A `write` change is
/// queued while the token is live; the pause holds it before the write-time
/// check, the token is revoked, and the frame is withheld (the stream closes).
/// The same bearer is restored and the same session resumed. A `read` change
/// (hidden from the token) then delivers the withheld `write` change, because
/// last-told never advanced; a second `read` change delivers nothing. RED on
/// base at the last assertion: base tells every authorized listener.
#[tokio::test]
async fn m_b2_a_frame_withheld_at_write_is_delivered_by_the_next_change() {
    let w = World::start().await;
    let token = scoped_token("R", &["write", "scan", "fetch"]);
    let (bearer, jti) = (token.token.clone(), token.jti.clone());
    w.key_server.store.insert(token.clone()).await;
    assert!(
        !w.served_names(&bearer).await.contains(&"read".to_string()),
        "premise: the token does not see read"
    );
    let mut ear = w.sse(&bearer).await;
    let session = ear.session_id().to_string();

    let (reached, release) = w.state.multiplexer.before_write_check.arm();
    w.store_shared("alpha", alpha_with("r1", "w2"));
    crate::test_pause::within("the frame reaching the write check", reached.notified()).await;
    assert!(w.key_server.store.revoke_by_jti(&jti).await);
    release.notify_one();
    assert_eq!(ear.told(&w).await, 0, "premise: withheld at write");

    w.key_server.store.insert(token).await;
    let mut ear = w.sse_resume(&bearer, &session).await;
    assert_eq!(ear.session_id(), session, "the same listener");
    w.store_shared("alpha", alpha_with("r2", "w2"));
    assert_eq!(
        ear.told(&w).await,
        1,
        "the withheld write change is delivered by the next change"
    );
    w.store_shared("alpha", alpha_with("r3", "w2"));
    assert_eq!(
        ear.told(&w).await,
        0,
        "a change hidden from the token sends it nothing: RED on base"
    );
}
