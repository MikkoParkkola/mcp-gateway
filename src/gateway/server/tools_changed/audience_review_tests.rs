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

/// R5 (D16a): a listen request inside a session whose routing profile hides
/// `read` is shown a list without it, so a `read` change sends it nothing;
/// a listener with no profile is told.
#[tokio::test]
async fn r5_a_listen_in_a_session_with_a_profile_is_judged_by_that_profile() {
    let w = World::start_with(|meta| meta.with_profile_registry(no_read_profiles())).await;
    let _session = w.legacy_owned("profiled", "k-std").await;
    let set = w
        .post_in(
            "k-std",
            "profiled",
            "tools/call",
            serde_json::json!({ "name": "gateway_set_profile", "arguments": { "profile": "no-read" } }),
        )
        .await;
    assert!(
        set.get("error").is_none() && set["result"]["isError"] != serde_json::json!(true),
        "premise: the profile is set: {set}"
    );
    let mut profiled = w.listen_at("k-std", "/mcp", Some("profiled")).await;
    let mut plain = w.listen("k-std").await;
    w.store_shared("alpha", alpha_with("r2"));
    let told = [profiled.told(&w).await, plain.told(&w).await];
    assert_eq!(told, [0, 1], "the profile hides read: RED on 52c20300f");
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

fn no_read_profiles() -> crate::routing_profile::ProfileRegistry {
    let mut configs = std::collections::HashMap::new();
    configs.insert(
        "no-read".to_string(),
        crate::routing_profile::RoutingProfileConfig {
            deny_tools: Some(vec!["read".to_string()]),
            ..Default::default()
        },
    );
    crate::routing_profile::ProfileRegistry::from_config(&configs, "default")
}
