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
    // The legacy variant reads the real GET route: the write-time decision is
    // where a record is made, and a bare receiver never writes.
    let mut ear = if listen {
        w.listen(&a).await
    } else {
        w.sse(&a).await
    };
    // The warm-ups duo() ran may still be draining; they are not the change.
    w.settle().await;
    let _ = ear.told(&w).await;
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

/// R6 (D16b): a stream on `?codemode=search_and_execute` is shown the two
/// fixed Code Mode tools, which no backend change moves.
#[tokio::test]
async fn r6_a_listen_on_the_code_mode_url_is_told_nothing_of_a_backend_change() {
    let w = World::start().await;
    let mut code = w
        .listen_at("k-std", "/mcp?codemode=search_and_execute", None)
        .await;
    let mut plain = w.listen("k-std").await;
    w.store_shared("alpha", alpha_with("r2"));
    let told = [code.told(&w).await, plain.told(&w).await];
    assert_eq!(
        told,
        [0, 1],
        "its list is the two fixed tools: RED on 52c20300f"
    );
}

/// R12 (D17e): two GET streams of one session, one on the code-mode URL and
/// one plain, attached in either order. Neither is judged by the other's
/// surface: a backend change reaches the plain stream and not the code-mode
/// one.
async fn mixed_surfaces(code_first: bool) {
    let w = World::start().await;
    let token = scoped_token("R", &["read", "write", "scan", "fetch"]);
    let bearer = token.token.clone();
    w.key_server.store.insert(token).await;
    let code_url = "/mcp?codemode=search_and_execute";
    let (mut code, mut plain);
    if code_first {
        code = w.sse_at(&bearer, code_url, None).await;
        let session = code.session_id().to_string();
        plain = w.sse_at(&bearer, "/mcp", Some(&session)).await;
    } else {
        plain = w.sse_at(&bearer, "/mcp", None).await;
        let session = plain.session_id().to_string();
        code = w.sse_at(&bearer, code_url, Some(&session)).await;
    }
    assert_eq!(
        code.session_id(),
        plain.session_id(),
        "premise: one session"
    );
    w.store_shared("alpha", alpha_with("r2"));
    let told = [plain.told(&w).await, code.told(&w).await];
    assert_eq!(told, [1, 0], "each stream is judged by its own surface");
}

#[tokio::test]
async fn r12_a_code_mode_stream_attached_first_leaves_the_plain_one_told() {
    mixed_surfaces(true).await;
}

#[tokio::test]
async fn r12_a_plain_stream_attached_first_leaves_the_code_mode_one_quiet() {
    mixed_surfaces(false).await;
}

/// R16 (D17d bound, kimi/gpt): judging a hint at write reads caches only. A
/// caller with an uncached credential and a cold slot on a per-user backend
/// is told of a visible change and not of a hidden one, with the fixture's
/// minter armed to hang and no backend `tools/list` made. The control first
/// shows the fetch counter moves when discovery does the work (the minter is
/// armed so a mint under the record gate would hang the row instead).
async fn judging_stays_on_caches(listen: bool) {
    use std::sync::atomic::Ordering::SeqCst;
    let (w, _a, _b) = duo().await;
    let (cold, control) = (w.principal("C").await, w.principal("D").await);
    w.slot_serves("beta", "D", vec![tool("d_tool", "d")]);
    let before = (w.probe.mints.load(SeqCst), w.probe.fetches.load(SeqCst));
    let _ = w.discovered(&control, "beta").await;
    let after = (w.probe.mints.load(SeqCst), w.probe.fetches.load(SeqCst));
    assert!(
        after.1 > before.1,
        "control: discovery fetches ({before:?} -> {after:?})"
    );
    w.probe.hang_mints.store(true, SeqCst);
    let mut ear = if listen {
        w.listen(&cold).await
    } else {
        w.sse(&cold).await
    };
    w.settle().await;
    let _ = ear.told(&w).await;
    w.store_shared("alpha", alpha_with("r2"));
    assert_eq!(ear.told(&w).await, 1, "a visible change is told");
    w.store_user("beta", "B", vec![tool("b_tool", "b"), tool("b_more", "m")]);
    assert_eq!(ear.told(&w).await, 0, "a hidden change is not");
    assert_eq!(
        (w.probe.mints.load(SeqCst), w.probe.fetches.load(SeqCst)),
        after,
        "the write path minted or fetched"
    );
}

#[tokio::test]
async fn r16_get_judging_at_write_mints_nothing_and_fetches_nothing() {
    judging_stays_on_caches(false).await;
}

#[tokio::test]
async fn r16_listen_judging_at_admit_mints_nothing_and_fetches_nothing() {
    judging_stays_on_caches(true).await;
}

/// An anonymous caller on a public path keeps its stream at attach, and is
/// told nothing of a change: it has no view to judge, and the write-time
/// decision does not find it live.
#[tokio::test]
async fn an_anonymous_public_path_stream_is_told_nothing_of_a_change() {
    let w = World::start_public().await;
    let (status, ear) = w.anonymous_sse().await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "premise: it is admitted"
    );
    let mut ear = ear.expect("an open stream");
    w.settle().await;
    let _ = ear.told(&w).await;
    w.store_shared("alpha", alpha_with("r2"));
    assert_eq!(
        ear.told(&w).await,
        0,
        "no hint reaches a caller with no view"
    );
}

/// The exemption stops at public paths: with `/mcp` authenticated, the same
/// anonymous GET is refused by the auth layer before any attach.
#[tokio::test]
async fn an_anonymous_get_on_an_authenticated_path_is_refused() {
    let w = World::start().await;
    let (status, ear) = w.anonymous_sse().await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    assert!(ear.is_none());
}
