// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 rows added by the delta review: each is RED on the first
//! implementation (52c20300f) and names the finding it pins.

use super::audience_fixture::{World, scoped_token, tool};

fn alpha_with(read: &str) -> Vec<crate::protocol::Tool> {
    vec![
        tool("read", read),
        tool("write", "w"),
        tool("scan", "s"),
        tool("fetch", "f"),
    ]
}

/// Principals A and B, each warm on their own slot of `beta`.
async fn duo() -> (World, String, String) {
    let w = World::start().await;
    let (a, b) = (w.principal("A").await, w.principal("B").await);
    w.slot_serves("beta", "A", vec![tool("a_tool", "a")]);
    w.slot_serves("beta", "B", vec![tool("b_tool", "b")]);
    for (bearer, who) in [(&a, "a_tool"), (&b, "b_tool")] {
        assert!(
            w.discovered(bearer, "beta")
                .await
                .contains(&who.to_string())
        );
    }
    (w, a, b)
}

/// R1 (gpt HIGH): the served-list digest is the listener's, not each
/// backend's. After a visible change on `alpha` is delivered, a change to
/// B's slot of `beta` (hidden from A) must still send A nothing.
async fn hidden_change_after_a_visible_one(listen: bool) {
    let (w, a, _b) = duo().await;
    let mut ear = if listen {
        w.listen(&a).await
    } else {
        w.legacy("a", &a).await
    };
    w.store_shared("alpha", alpha_with("r2"));
    assert_eq!(ear.told(&w).await, 1, "premise: A sees the alpha change");
    w.store_user("beta", "B", vec![tool("b_tool", "b"), tool("b_more", "m")]);
    assert_eq!(
        ear.told(&w).await,
        0,
        "B's slot is not A's view, whatever was told before: RED on 52c20300f"
    );
}

#[tokio::test]
async fn r1_legacy_a_hidden_change_after_a_delivered_visible_change_sends_nothing() {
    hidden_change_after_a_visible_one(false).await;
}

#[tokio::test]
async fn r1_listen_a_hidden_change_after_a_delivered_visible_change_sends_nothing() {
    hidden_change_after_a_visible_one(true).await;
}

/// R2 (gpt MEDIUM, muse HIGH): a backend registered after the listener
/// attached has its first visible tools told, not recorded as a baseline.
async fn late_backend(listen: bool) {
    let w = World::start().await;
    let mut ear = if listen {
        w.listen("k-std").await
    } else {
        w.legacy("std", "k-std").await
    };
    w.register_late("delta", vec![tool("late_tool", "l")]);
    assert_eq!(
        ear.told(&w).await,
        1,
        "the caller's list gained late_tool: RED on 52c20300f"
    );
}

#[tokio::test]
async fn r2_legacy_a_backend_registered_after_attach_is_told() {
    late_backend(false).await;
}

#[tokio::test]
async fn r2_listen_a_backend_registered_after_attach_is_told() {
    late_backend(true).await;
}

/// R4 (gpt MEDIUM): a hint queued before the caller listed is not written
/// for a view it already holds. The GET frame is held at the write check, the
/// caller lists inside its session, and the frame is released.
#[tokio::test]
async fn r4_a_queued_hint_made_stale_by_a_listing_is_not_written() {
    let w = World::start().await;
    let token = scoped_token("R", &["read", "write", "scan", "fetch"]);
    let bearer = token.token.clone();
    w.key_server.store.insert(token).await;
    let mut ear = w.sse(&bearer).await;
    let session = ear.session_id().to_string();
    let (reached, release) = w.state.multiplexer.before_write_check.arm();
    w.store_shared("alpha", alpha_with("r2"));
    crate::test_pause::within("the frame reaching the write check", reached.notified()).await;
    let listed = w
        .post_session(&bearer, &session, "tools/list", serde_json::json!({}))
        .await;
    assert!(
        listed["result"]["tools"].is_array(),
        "premise: listed {listed}"
    );
    release.notify_one();
    assert_eq!(
        ear.told(&w).await,
        0,
        "the listing already shows the change: RED on 52c20300f"
    );
}
