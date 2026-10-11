// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 rows on the direct fixture: the profile differential (t4), the
//! cold list fetched on the miss, and the
//! signing channels (nonce validation, replay) on `/mcp`.

use std::sync::atomic::Ordering;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::super::direct_guards_fixture::{Answer, Fx, fixture_built, post_direct, send};
use super::{BACKENDS, arm_signing, profiles};

/// T4 (DIRECT.3). The caller's session profile applies on the per-backend
/// route; a call with no session, or an empty one, gets the default profile.
#[tokio::test]
async fn t4_the_session_profile_applies_on_the_direct_route() {
    for backend in BACKENDS {
        let fx = fixture_built(Answer::Ok, |meta| meta.with_profile_registry(profiles())).await;
        // A session the caller owns: a presented id is honoured only then (#2468).
        let owner = crate::gateway::session_id::SessionOwner::Credential(
            crate::gateway::auth::principal_of("k-std"),
        );
        let (session, _rx) = fx.state.multiplexer.get_or_create_session_for(None, &owner);
        fx.state
            .meta_mcp
            .session_profiles()
            .set_profile(&session, "no-alpha-read");
        // The condition MIK-8361 promises under: the session has read the
        // backend's list (the cold list is the residual row below).
        let (status, listed) = send(
            &fx,
            &format!("/mcp/{backend}"),
            "k-std",
            "tools/list",
            json!({}),
            Some(&session),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{backend}: premise, listed: {listed}");
        let warm = fx.calls.load(Ordering::SeqCst);
        let call = |tool: &'static str| {
            post_direct(&fx, backend, "k-std", tool, json!({}), None, Some(&session))
        };
        // MIK-8361: the profile-withheld name answers byte-for-byte as a name
        // the backend does not list, on the same route and session, with the
        // tool name factored out; neither is sent.
        let (status, body) = call("read").await;
        let (missing_status, missing) = call("nosuch").await;
        assert_eq!(
            (status, body.to_string()),
            (missing_status, missing.to_string().replace("nosuch", "read")),
            "{backend}: the profile's refusal differs from a missing name"
        );
        assert!(
            !body.to_string().contains("profile"),
            "premise: the answer names no profile: {body}"
        );
        assert_eq!(fx.calls.load(Ordering::SeqCst), warm, "{backend}: sent");
        for session in [None, Some("")] {
            let (_, body) =
                post_direct(&fx, backend, "k-std", "read", json!({}), None, session).await;
            assert!(
                body.get("result").is_some() && body["result"]["isError"] != true,
                "{backend} {session:?}: {body}"
            );
        }
        assert_eq!(fx.calls.load(Ordering::SeqCst), warm + 2, "{backend}");
    }
}

/// MIK-8361, the cold list on this route: an unread list is fetched on the
/// miss (F13), so an unlisted name gets text A cold as warm and is never
/// sent. Not a residual here; the stated residuals (truncated list, failed
/// fetch, `off`) are pinned by S3b, S5 and S6. A regression that forwards it
/// shows here.
#[tokio::test]
async fn t4_a_cold_list_is_fetched_on_the_miss_not_forwarded() {
    for backend in BACKENDS {
        let fx = fixture_built(Answer::Ok, |meta| meta.with_profile_registry(profiles())).await;
        let (_, body) = post_direct(&fx, backend, "k-std", "nosuch", json!({}), None, None).await;
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            0,
            "{backend}: sent: {body}"
        );
        assert_eq!(
            body["result"]["content"][0]["text"],
            json!(crate::backend::text_absent("nosuch")),
            "{backend}: {body}"
        );
    }
}

/// A signed `gateway_invoke` of `tool` on `backend` in `session`.
async fn signed_invoke(
    fx: &Fx,
    session: &str,
    (backend, tool): (&str, &str),
    nonce: Value,
) -> (StatusCode, String) {
    let params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": backend, "tool": tool, "arguments": {}, "nonce": nonce},
    });
    let (status, body) = send(fx, "/mcp", "k-std", "tools/call", params, Some(session)).await;
    (status, body.to_string())
}

/// Presents `nonce` on a signed call of `target`, then again on the missing
/// name: the second answer.
async fn spend_then_replay(
    fx: &Fx,
    session: &str,
    (backend, tool): (&str, &str),
    nonce: &str,
) -> (StatusCode, String) {
    let _ = signed_invoke(fx, session, (backend, tool), json!(nonce)).await;
    signed_invoke(fx, session, (backend, "nosuch"), json!(nonce)).await
}

/// MIK-8361 amendment A1/A2 channels on `/mcp`. A signed call naming a target the
/// session's profile withholds pays the nonce exactly as a call naming a
/// missing name does, so two channels answer alike:
/// - nonce validation: a malformed nonce gets the missing name's answer;
/// - replay: the nonce is settled alike (given back), so a replay of it is
///   answered alike.
///
/// A guard, green before and after MIK-8361 (red11 at d82299ec7): `/mcp`
/// already paid both alike; this pins it against a gate that answers first.
/// The session's list is warm, as t4's is; nothing is sent.
#[tokio::test]
async fn a_withheld_target_pays_its_nonce_as_a_missing_name_does_on_mcp() {
    for backend in BACKENDS {
        let fx = fixture_built(Answer::Ok, |meta| {
            let mut meta = meta.with_profile_registry(profiles());
            arm_signing(&mut meta, true);
            meta
        })
        .await;
        let owner = crate::gateway::session_id::SessionOwner::Credential(
            crate::gateway::auth::principal_of("k-std"),
        );
        let (session, _rx) = fx.state.multiplexer.get_or_create_session_for(None, &owner);
        let uri = format!("/mcp/{backend}");
        let (status, listed) = send(&fx, &uri, "k-std", "tools/list", json!({}), None).await;
        assert_eq!(status, StatusCode::OK, "{backend}: premise, listed: {listed}");
        fx.state
            .meta_mcp
            .session_profiles()
            .set_profile(&session, "no-alpha-read");
        let warm = fx.calls.load(Ordering::SeqCst);
        let factored = |(status, body): (StatusCode, String)| (status, body.replace("nosuch", "read"));

        let hidden = signed_invoke(&fx, &session, (backend, "read"), json!(42)).await;
        let missing = signed_invoke(&fx, &session, (backend, "nosuch"), json!(42)).await;
        assert!(
            missing.1.contains("\"error\""),
            "{backend}: premise, a missing name's malformed nonce is refused: {missing:?}"
        );
        assert_eq!(hidden, factored(missing), "{backend}: the malformed-nonce channel");

        let hidden_replay = spend_then_replay(&fx, &session, (backend, "read"), "a2-mcp-hidden-0001").await;
        let missing_replay =
            spend_then_replay(&fx, &session, (backend, "nosuch"), "a2-mcp-missing-0001").await;
        assert!(
            !missing_replay.1.contains("replay"),
            "{backend}: premise, a missing name's nonce is given back: {missing_replay:?}"
        );
        assert_eq!(hidden_replay, missing_replay, "{backend}: the replay channel");
        assert_eq!(fx.calls.load(Ordering::SeqCst), warm, "{backend}: sent");
    }
}
