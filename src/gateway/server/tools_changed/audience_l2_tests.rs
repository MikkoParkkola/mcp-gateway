// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 L2 rows: listeners whose scopes differ in exactly one input to
//! the per-nudge cache key (test plan t4, mutants M7a-M7g). A key that drops
//! that input hands one listener the other's fingerprint. Only pairs a real
//! credential can form are written here; the inputs no transport can vary on
//! its own are reported to the lead instead of faked.

use serde_json::{Value, json};

use super::audience_fixture::{World, tool};

const STD: &str = "k-std";
#[cfg(feature = "spec-preview")]
const DENY: &str = "k-deny";

fn alpha_with(read: &str) -> Vec<crate::protocol::Tool> {
    vec![
        tool("read", read),
        tool("write", "w"),
        tool("scan", "s"),
        tool("fetch", "f"),
    ]
}

fn access_token(reply: &(u16, Value)) -> String {
    assert_eq!(reply.0, 200, "premise: the exchange succeeds: {}", reply.1);
    reply.1["access_token"]
        .as_str()
        .expect("an access token")
        .to_string()
}

/// L2-authorizer (MIK-8350), RED (killer M7a): one OIDC principal holds two
/// exchanged tokens, one granted every tool and one narrowed to every tool
/// but `read`. Name, admin standing and grant subject are the principal's,
/// so equal; only the authorizer differs. Both may access `alpha` (base
/// already filters by backend), so a `read` change tells the full token only.
#[tokio::test]
async fn l2_authorizer_two_tokens_of_one_principal_differ_only_in_scope() {
    use crate::key_server::oidc_test_harness::ISS_A;
    let (w, h) = World::start_oidc().await;
    let id_token = h.mint(ISS_A, "A", &json!({ "email": "A@corp.example" }));
    let full = access_token(&h.exchange(&id_token).await);
    let narrow = access_token(&h.exchange_scoped(&id_token, "tools:write,scan,fetch").await);
    assert!(
        w.served_names(&full).await.contains(&"read".to_string()),
        "premise: the full token sees read"
    );
    assert!(
        !w.served_names(&narrow).await.contains(&"read".to_string()),
        "premise: the narrowed token does not"
    );
    let mut ears = [w.listen(&full).await, w.listen(&narrow).await];
    w.store_shared("alpha", alpha_with("r2"));
    let told = [ears[0].told(&w).await, ears[1].told(&w).await];
    assert_eq!(told, [1, 0], "only the token that sees read: RED on base");
}

/// A routing profile `no-read` that hides `read`.
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

/// L2-profile (MIK-8350), RED (killer M7f): one key, two legacy sessions;
/// one session switches to a routing profile that hides `read`. A `read`
/// change tells only the other session.
#[tokio::test]
async fn l2_profile_two_sessions_of_one_key_differ_only_in_profile() {
    let w = World::start_with(|meta| meta.with_profile_registry(no_read_profiles())).await;
    let mut hidden = w.legacy_owned("hidden", STD).await;
    let mut shown = w.legacy_owned("shown", STD).await;
    let set = w
        .post_in(
            STD,
            "hidden",
            "tools/call",
            json!({ "name": "gateway_set_profile", "arguments": { "profile": "no-read" } }),
        )
        .await;
    assert!(
        set.get("error").is_none() && set["result"]["isError"] != json!(true),
        "premise: the profile is set: {set}"
    );
    let _ = (hidden.told(&w).await, shown.told(&w).await);
    w.store_shared("alpha", alpha_with("r2"));
    let told = [hidden.told(&w).await, shown.told(&w).await];
    assert_eq!(
        told,
        [0, 1],
        "only the session whose profile shows read: RED on base"
    );
}

/// L2-promotion (MIK-8350), RED (killer M7g): one key that cannot see
/// `read`, two legacy sessions; one promotes `scan` by invoking it. Their
/// served lists differ, so a key without the promotion would hand one the
/// other's fingerprint. A `read` change is hidden from both: neither is told.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn l2_promotion_two_sessions_of_one_key_differ_only_in_promotion() {
    let w = World::start().await;
    w.alpha_answers_calls(alpha_with("r"));
    let mut promoted = w.legacy_owned("promoted", DENY).await;
    let mut plain = w.legacy_owned("plain", DENY).await;
    let call = w
        .post_in(
            DENY,
            "promoted",
            "tools/call",
            json!({ "name": "gateway_invoke",
                    "arguments": { "server": "alpha", "tool": "scan", "arguments": {} } }),
        )
        .await;
    assert!(
        call.get("error").is_none() && call["result"]["isError"] != json!(true),
        "premise: the invocation succeeds: {call}"
    );
    let listed = w.post_in(DENY, "promoted", "tools/list", json!({})).await;
    assert!(
        listed.to_string().contains("\"scan\""),
        "premise: scan is promoted into the session: {listed}"
    );
    let _ = (promoted.told(&w).await, plain.told(&w).await);
    w.store_shared("alpha", alpha_with("r2"));
    let told = [promoted.told(&w).await, plain.told(&w).await];
    assert_eq!(told, [0, 0], "read is hidden from both: RED on base");
}

/// The grant authority of the adapter's end users.
fn adapter_authority() -> String {
    crate::gateway::openwebui_adapter::adapter_issuer(super::audience_fixture::ADAPTER_INSTALLATION)
}

/// A personal capability `alice_cal` owned by the adapter's end user `alice`.
fn alice_cal(description: &str) -> String {
    format!(
        "fulcrum: \"1.0\"\nname: alice_cal\ndescription: {description}\n\
schema:\n  input:\n    type: object\n    properties: {{}}\n\
metadata:\n  exposure: personal\n  identity_owner:\n    authority: \"{}\"\n    subject: alice\n\
providers:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.invalid\n      path: /cal\n      method: GET\n\
auth:\n  required: false\n  type: none\n",
        adapter_authority()
    )
}

/// The adapter user `alice`'s grant on `alice_cal`.
fn alice_grant() -> crate::identity_grants::LocalIdentityGrantStore {
    use crate::identity_grants::{GrantAgent, GrantScope, GrantSubject, IdentityGrant};
    let alice = GrantSubject::new(adapter_authority(), "alice", None);
    crate::identity_grants::LocalIdentityGrantStore::from_grants([IdentityGrant {
        grant_id: "g-alice".to_string(),
        subject: alice.clone(),
        agent: GrantAgent::Any,
        capability: "alice_cal".to_string(),
        tool: None,
        scope: GrantScope::Any,
        owner: Some(alice),
        expires_at: None,
        revoked_at: None,
        provenance: "mik-8350".to_string(),
        reason: "L2 grant-subject pair".to_string(),
    }])
}

/// L2-grant-subject (MIK-8350), RED (killer M7e): one API key presenting
/// Open `WebUI` assertions for two end users, so one principal and two grant
/// subjects (the adapter identity MIK-8350's D11 captures). Only alice may
/// see her personal capability, so its change tells only alice's listener.
/// The trusted-proxy and Cloudflare variants are MIK-8377's.
#[tokio::test]
async fn l2_grant_subject_one_key_two_adapter_users_differ_only_in_subject() {
    use super::audience_fixture::adapter_assertion;
    let w = World::start_adapter(|meta| meta.with_identity_grants(alice_grant())).await;
    w.set_capability_yaml(&alice_cal("one"));
    w.settle().await;
    let (alice, bob) = (adapter_assertion("alice"), adapter_assertion("bob"));
    let seen = (
        w.discovered_as(STD, Some(&alice), "caps").await,
        w.discovered_as(STD, Some(&bob), "caps").await,
    );
    assert!(
        seen.0.contains(&"alice_cal".to_string()),
        "premise: alice sees her capability: {seen:?}"
    );
    assert!(
        !seen.1.contains(&"alice_cal".to_string()),
        "premise: bob does not: {seen:?}"
    );
    let mut ears = [
        w.listen_as(STD, Some(&alice)).await,
        w.listen_as(STD, Some(&bob)).await,
    ];
    w.set_capability_yaml(&alice_cal("two"));
    let told = [ears[0].told(&w).await, ears[1].told(&w).await];
    assert_eq!(told, [1, 0], "only alice sees alice_cal: RED on base");
}

/// L2-delegated (MIK-8350), RED (killer: a key on the delegated bearer's
/// actor rather than its token): one user's two live ID tokens, presented as
/// delegated bearers, carry different `groups`. The first-match policy gives
/// the `full` group every tool and everyone else every tool but `read`. Both
/// bearers name the same issuer and subject, so a principal keyed on the
/// actor would merge them; only the `full` token may be told of a `read`
/// change.
#[tokio::test]
async fn l2_delegated_two_id_tokens_of_one_user_differ_only_in_groups() {
    use crate::key_server::oidc_test_harness::ISS_A;
    let (w, h) = World::start_oidc_with(&format!(
        "  - match: {{ issuer: \"{ISS_A}\", group: \"full\" }}\n    \
         scopes: {{ backends: [\"*\"], tools: [\"*\"], rate_limit: 0 }}\n  \
         - match: {{ issuer: \"{ISS_A}\" }}\n    \
         scopes: {{ backends: [\"*\"], tools: [\"write\", \"scan\", \"fetch\"], rate_limit: 0 }}\n"
    ))
    .await;
    let token = |groups: &[&str]| {
        h.mint(
            ISS_A,
            "A",
            &json!({ "email": "A@corp.example", "groups": groups }),
        )
    };
    let (full, plain) = (token(&["full"]), token(&[]));
    assert!(
        w.served_names(&full).await.contains(&"read".to_string()),
        "premise: the full-group token sees read"
    );
    assert!(
        !w.served_names(&plain).await.contains(&"read".to_string()),
        "premise: the other token does not"
    );
    let mut ears = [w.listen(&full).await, w.listen(&plain).await];
    w.store_shared("alpha", alpha_with("r2"));
    let told = [ears[0].told(&w).await, ears[1].told(&w).await];
    assert_eq!(
        told,
        [1, 0],
        "only the full-group token sees read: RED on base"
    );
}
