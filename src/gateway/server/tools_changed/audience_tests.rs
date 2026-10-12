// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 RED rows (HTTP): a `tools/list_changed` reaches a caller only
//! when that caller's own visible list changed. Labels and killers are in
//! the test plan t4 (lead-decisions scratch `mik-8350-t4.md`). The fixture
//! is `audience_fixture`; "told" is read after the drain's completion signal.

use super::audience_fixture::{Ear, World, tool};

const STD: &str = "k-std";
const DENY: &str = "k-deny";

fn alpha_with(read: &str, fetch: &str) -> Vec<crate::protocol::Tool> {
    vec![
        tool("read", read),
        tool("write", "w"),
        tool("scan", "s"),
        tool("fetch", fetch),
    ]
}

/// One listener per key, as a legacy GET session or a listen stream.
async fn pair(w: &World, listen: bool) -> (Ear, Ear) {
    if listen {
        (w.listen(STD).await, w.listen(DENY).await)
    } else {
        (w.legacy("std", STD).await, w.legacy("deny", DENY).await)
    }
}

/// Surfaced `read` changes: k-deny never sees `read`, k-std does.
async fn surfaced_read_change(listen: bool) {
    let w = World::start().await;
    let (mut std, mut deny) = pair(&w, listen).await;
    let before = (w.served_names(STD).await, w.served_names(DENY).await);
    assert!(
        before.0.contains(&"read".to_string()),
        "premise: {before:?}"
    );
    assert!(
        !before.1.contains(&"read".to_string()),
        "premise: {before:?}"
    );
    w.store_shared("alpha", alpha_with("r2", "f"));
    assert_eq!(std.told(&w).await, 1, "k-std sees read change");
    assert_eq!(deny.told(&w).await, 0, "k-deny never saw read: RED on base");
}

/// A1 (MIK-8350), RED (killer M1): a surfaced tool hidden from k-deny
/// changes; a legacy GET session of k-deny is told nothing, k-std's once.
#[tokio::test]
async fn a1_hidden_surfaced_change_tells_only_the_caller_who_sees_it() {
    surfaced_read_change(false).await;
}

/// A3 (MIK-8350), RED (killer M1): A1 over the real listen SSE stream.
#[tokio::test]
async fn a3_hidden_surfaced_change_over_listen_tells_only_the_caller_who_sees_it() {
    surfaced_read_change(true).await;
}

/// A9 (MIK-8350), RED k-deny half (killer M9, also covers A1d): a change to
/// the non-surfaced shared `fetch` is told to k-std (as base) and not to
/// k-deny, who is denied `fetch` in discovery.
#[tokio::test]
async fn a9_hidden_discovered_change_tells_only_the_caller_who_sees_it() {
    let w = World::start().await;
    let (mut std, mut deny) = pair(&w, false).await;
    let seen = (
        w.discovered(STD, "alpha").await,
        w.discovered(DENY, "alpha").await,
    );
    assert!(seen.0.contains(&"fetch".to_string()), "premise: {seen:?}");
    assert!(!seen.1.contains(&"fetch".to_string()), "premise: {seen:?}");
    w.store_shared("alpha", alpha_with("r", "f2"));
    assert_eq!(std.told(&w).await, 1, "k-std sees fetch (as base)");
    assert_eq!(
        deny.told(&w).await,
        0,
        "k-deny cannot see fetch: RED on base"
    );
}

/// A4 (MIK-8350), RED (killer M1): the capability catalogue gains a
/// capability the policy hides from k-deny; k-deny's listener hears nothing.
#[tokio::test]
async fn a4_policy_hidden_capability_change_tells_only_the_caller_who_sees_it() {
    let w = World::start().await;
    w.set_capability("one");
    w.settle().await;
    let (mut std, mut deny) = (w.listen(STD).await, w.listen(DENY).await);
    assert!(
        w.served_names(STD)
            .await
            .contains(&"hidden_cap".to_string())
    );
    assert!(
        !w.served_names(DENY)
            .await
            .contains(&"hidden_cap".to_string())
    );
    w.set_capability("two");
    assert_eq!(std.told(&w).await, 1, "k-std sees the capability");
    assert_eq!(
        deny.told(&w).await,
        0,
        "policy-hidden from k-deny: RED on base"
    );
}

/// Principals A and B, each warm on their own slot of `beta`.
async fn duo() -> (World, String, String) {
    let w = World::start().await;
    let (a, b) = (w.principal("A").await, w.principal("B").await);
    w.slot_serves("beta", "A", vec![tool("a_tool", "a")]);
    w.slot_serves("beta", "B", vec![tool("b_tool", "b")]);
    assert!(
        w.discovered(&a, "beta")
            .await
            .contains(&"a_tool".to_string())
    );
    assert!(
        w.discovered(&b, "beta")
            .await
            .contains(&"b_tool".to_string())
    );
    w.settle().await;
    (w, a, b)
}

/// B1 (MIK-8350), RED A half (killers M1, M9): B's slot on `beta` gains a
/// tool; B is told, A (warm on its own slot) is not.
#[tokio::test]
async fn b1_a_per_user_store_tells_only_the_owner_of_the_slot() {
    let (w, a, b) = duo().await;
    let (mut ear_a, mut ear_b) = (w.legacy("a", &a).await, w.legacy("b", &b).await);
    w.store_user("beta", "B", vec![tool("b_tool", "b"), tool("b_more", "m")]);
    assert_eq!(ear_b.told(&w).await, 1, "B's own view changed");
    assert_eq!(
        ear_a.told(&w).await,
        0,
        "A's view did not change: RED on base"
    );
}

/// B2 (MIK-8350), RED (killers M1, M9): B's grant is revoked; B is told, A
/// is not.
#[tokio::test]
async fn b2_a_revocation_tells_only_the_revoked_principal() {
    let (w, a, b) = duo().await;
    let (mut ear_a, mut ear_b) = (w.legacy("a", &a).await, w.legacy("b", &b).await);
    w.revoke("beta", "B");
    assert_eq!(ear_b.told(&w).await, 1, "B lost its view");
    assert_eq!(ear_a.told(&w).await, 0, "A's view is intact: RED on base");
}

/// B3 (MIK-8350), RED (killer M1): B2 mid-stream, over listen, after B was
/// just told of an earlier change; the revocation still reaches B and not A.
#[tokio::test]
async fn b3_a_revocation_mid_stream_tells_only_the_revoked_principal() {
    let (w, a, b) = duo().await;
    let (mut ear_a, mut ear_b) = (w.listen(&a).await, w.listen(&b).await);
    w.store_user("beta", "B", vec![tool("b_tool", "b2")]);
    assert_eq!(ear_b.told(&w).await, 1, "premise: B told of its change");
    assert_eq!(
        ear_a.told(&w).await,
        0,
        "A not told of B's change: RED on base"
    );
    w.revoke("beta", "B");
    assert_eq!(ear_b.told(&w).await, 1, "the revocation reaches B");
    assert_eq!(ear_a.told(&w).await, 0, "A not told of B's revocation");
}

/// B4 (MIK-8350), RED first half (killer M1): C never listed `beta`; a change
/// to B's slot sends C nothing.
#[tokio::test]
async fn b4_an_unlisted_backend_slot_change_tells_a_caller_who_never_listed_it() {
    let (w, _a, _b) = duo().await;
    let c = w.principal("C").await;
    let mut ear_c = w.legacy("c", &c).await;
    w.store_user("beta", "B", vec![tool("b_tool", "b3")]);
    assert_eq!(
        ear_c.told(&w).await,
        0,
        "C has no view of beta: RED on base"
    );
}

/// B6 (MIK-8350), RED (killer M9): `gamma` is required per-user, so a cold
/// caller has no view of it (UNLISTED) and is silent for its slot changes.
#[tokio::test]
async fn b6_a_required_backend_is_silent_to_a_cold_caller() {
    let (w, _a, b) = duo().await;
    let c = w.principal("C").await;
    let mut ear_c = w.legacy("c", &c).await;
    w.slot_serves("gamma", "B", vec![tool("g", "g")]);
    assert!(w.discovered(&b, "gamma").await.contains(&"g".to_string()));
    w.settle().await;
    let _ = ear_c.told(&w).await;
    w.store_user("gamma", "B", vec![tool("g", "g2")]);
    assert_eq!(
        ear_c.told(&w).await,
        0,
        "gamma is unlisted for C: RED on base"
    );
}

/// The shared SSE event counter's next value.
fn next_event(w: &World) -> u64 {
    let id = w.state.multiplexer.next_event_id();
    id.trim_start_matches("evt-").parse().expect("evt-N")
}

/// D-ORDER (MIK-8350), RED (killer M21): a stream held with a live dashboard
/// cookie plus a bearer whose key may not access `alpha` is not told of an
/// `alpha` change: the Authorization decides alone.
#[tokio::test]
async fn d_order_a_bearer_without_access_decides_over_a_live_cookie() {
    let w = World::start().await;
    let cookie = w.dashboard_cookie();
    let mut ear = w.legacy_with(
        "narrow",
        &[
            ("authorization", "Bearer k-narrow".to_string()),
            ("cookie", cookie),
        ],
    ).await;
    w.store_shared("alpha", alpha_with("r2", "f"));
    assert_eq!(
        ear.told(&w).await,
        0,
        "k-narrow may not access alpha: RED on base"
    );
}

/// D-ORDER-2 (MIK-8350), RED (killer M25): a non-bearer Authorization header
/// plus a live cookie is a dead credential; nothing is delivered.
#[tokio::test]
async fn d_order_2_a_non_bearer_authorization_beside_a_live_cookie_is_dead() {
    let w = World::start().await;
    let cookie = w.dashboard_cookie();
    let mut ear = w.legacy_with(
        "basic",
        &[
            ("authorization", "Basic dXNlcjpwYXNz".to_string()),
            ("cookie", cookie),
        ],
    ).await;
    w.store_shared("alpha", alpha_with("r2", "f"));
    assert_eq!(
        ear.told(&w).await,
        0,
        "a wrong Authorization is dead: RED on base"
    );
}

/// M-B5' (MIK-8350), RED (killer M8): a `list_changed` delivery does not move
/// the shared event counter, so ids show no gap.
#[tokio::test]
async fn m_b5_list_changed_does_not_consume_the_shared_event_counter() {
    let w = World::start().await;
    let mut ear = w.legacy("std", STD).await;
    let before = next_event(&w);
    w.store_shared("alpha", vec![tool("write", "w2")]);
    assert_eq!(ear.told(&w).await, 1, "premise: the change was announced");
    assert_eq!(
        next_event(&w),
        before + 1,
        "list_changed took an id: RED on base"
    );
}

/// M-B1a (MIK-8350), RED (killer M1): a listener attached, a hidden change
/// drained, then a visible change: one notice, not two.
#[tokio::test]
async fn m_b1a_a_hidden_change_then_a_visible_change_is_one_notice() {
    let w = World::start().await;
    let mut deny = w.legacy("deny", DENY).await;
    w.store_shared("alpha", alpha_with("r2", "f"));
    w.settle().await;
    w.store_shared("alpha", vec![tool("write", "w2")]);
    assert_eq!(deny.told(&w).await, 1, "two notices on base");
}

/// M-B9 (MIK-8350), STUB-RED (real barrier, killer M13): the drain is parked
/// after deciding a change; the caller lists; on release the caller, whose
/// list is already current, is told nothing.
#[tokio::test]
async fn m_b9_a_caller_who_listed_during_the_pending_nudge_is_not_told() {
    let w = World::start().await;
    let mut ear = w.legacy("std", STD).await;
    let hold = super::drain_seam::Hold::arm();
    w.store_shared("alpha", vec![tool("write", "w2")]);
    hold.reached().await;
    assert!(w.served_names(STD).await.contains(&"write".to_string()));
    hold.release();
    assert_eq!(
        ear.told(&w).await,
        0,
        "the listing refreshed it: RED on base"
    );
}

/// M-rekey (MIK-8350), RED (killer M12): a session resumed from k-std to
/// k-deny is judged against k-deny's scope; a change hidden from k-deny
/// sends nothing.
#[tokio::test]
async fn m_rekey_a_resumed_session_is_judged_against_its_new_credential() {
    let w = World::start().await;
    let mut ear = w.legacy("moved", STD).await;
    w.rekey("moved", DENY);
    w.store_shared("alpha", alpha_with("r2", "f"));
    assert_eq!(
        ear.told(&w).await,
        0,
        "read is hidden from k-deny: RED on base"
    );
}

/// M-B10 (MIK-8350), RED (killer M28): a listen attach is followed by exactly
/// one constant `list_changed` frame after the acknowledgement, whatever the
/// data. Base sends none (checked: the stream yields the ack, then waits).
#[tokio::test]
async fn m_b10_a_listen_attach_gets_one_constant_list_changed() {
    let w = World::start().await;
    let mut ear = w.listen(STD).await;
    assert_eq!(
        ear.told(&w).await,
        1,
        "no attach hint after the ack: RED on base"
    );
}

/// A6 (MIK-8350), RED (killer M17): a change that moves only the admitted
/// count in a meta-tool description, by a tool k-std may invoke and k-deny
/// may not (`fetch`): k-std is told, k-deny is not.
#[tokio::test]
async fn a6_a_count_only_change_tells_only_the_caller_whose_count_moved() {
    let w = World::start().await;
    w.store_shared(
        "alpha",
        vec![tool("read", "r"), tool("write", "w"), tool("scan", "s")],
    );
    w.settle().await;
    let (mut std, mut deny) = (w.legacy("std", STD).await, w.legacy("deny", DENY).await);
    let (std_before, deny_before) = (w.served(STD).await, w.served(DENY).await);
    w.store_shared("alpha", alpha_with("r", "f"));
    let (std_after, deny_after) = (w.served(STD).await, w.served(DENY).await);
    assert_ne!(std_before, std_after, "premise: k-std's list moved");
    assert_eq!(deny_before, deny_after, "premise: k-deny's list did not");
    assert_eq!(std.told(&w).await, 1, "k-std's count moved");
    assert_eq!(
        deny.told(&w).await,
        0,
        "k-deny's count did not: RED on base"
    );
}

/// A7 (MIK-8350), RED (killer M2): under code mode the served list omits
/// surfaced tools, so a surfaced-tool change sends nothing.
#[tokio::test]
async fn a7_a_surfaced_change_under_code_mode_sends_nothing() {
    let w = World::start_with(|meta| meta.with_code_mode(true)).await;
    let mut std = w.legacy("std", STD).await;
    assert!(
        !w.served_names(STD).await.contains(&"read".to_string()),
        "premise"
    );
    w.store_shared("alpha", alpha_with("r2", "f"));
    assert_eq!(std.told(&w).await, 0, "the list omits read: RED on base");
}

/// B5 (MIK-8350), RED negative half (positive half IMPL, killer M1): D
/// reached `beta` only through search; another principal's slot change sends
/// D nothing.
#[tokio::test]
async fn b5_a_search_only_caller_is_silent_for_another_principals_slot() {
    let (w, _a, _b) = duo().await;
    let d = w.principal("D").await;
    let _ = w
        .post(
            &d,
            "tools/call",
            serde_json::json!({ "name": "gateway_search_tools", "arguments": { "query": "tool" } }),
        )
        .await;
    w.settle().await;
    let mut ear_d = w.legacy("d", &d).await;
    w.store_user("beta", "B", vec![tool("b_tool", "b4")]);
    assert_eq!(ear_d.told(&w).await, 0, "not D's slot: RED on base");
}

/// L3 (MIK-8350), RED negative half (killer M1): a listen listener whose
/// principal warmed `beta` through a POST is not told of another principal's
/// slot change.
#[tokio::test]
async fn l3_a_warmed_listen_listener_is_silent_for_another_principals_slot() {
    let (w, a, _b) = duo().await;
    let mut ear_a = w.listen(&a).await;
    w.store_user("beta", "B", vec![tool("b_tool", "b5")]);
    assert_eq!(
        ear_a.told(&w).await,
        0,
        "A's slot is unchanged: RED on base"
    );
}

/// L2 (MIK-8350), RED (killer M7): listeners under three different
/// credentials (a policy-limited key, an unlimited key, a key-server
/// principal) on one nudge: only the credentials that see `read` are told.
/// The single-input pairs are in `audience_l2_tests`.
#[tokio::test]
async fn l2_one_nudge_tells_only_the_credentials_that_see_the_change() {
    let w = World::start().await;
    let p = w.principal("P").await;
    let mut ears = [
        w.listen(DENY).await,
        w.listen(STD).await,
        w.listen(&p).await,
    ];
    w.store_shared("alpha", alpha_with("r2", "f"));
    let told = [
        ears[0].told(&w).await,
        ears[1].told(&w).await,
        ears[2].told(&w).await,
    ];
    assert_eq!(
        told,
        [0, 1, 1],
        "only the credentials that see read: RED on base"
    );
}

/// How a K-row principal presents its OIDC identity.
#[derive(Clone, Copy, Debug)]
enum Oidc {
    /// The ID token exchanged at `/auth/token` for a temporary token.
    Exchanged,
    /// The ID token itself, as a delegated bearer.
    Delegated,
}

/// `subject`'s bearer, minted by the harness's provider and presented as `how`.
async fn oidc_bearer(
    h: &crate::key_server::oidc_test_harness::Harness,
    how: Oidc,
    subject: &str,
) -> String {
    use crate::key_server::oidc_test_harness::ISS_A;
    let email = serde_json::json!({ "email": format!("{subject}@corp.example") });
    let id_token = h.mint(ISS_A, subject, &email);
    match how {
        Oidc::Delegated => id_token,
        Oidc::Exchanged => {
            let (status, body) = h.exchange(&id_token).await;
            assert_eq!(status, 200, "premise: the exchange succeeds: {body}");
            body["access_token"]
                .as_str()
                .expect("an access token")
                .to_string()
        }
    }
}

/// As [`duo`], with principals A and B holding real OIDC credentials.
async fn oidc_duo(
    how: Oidc,
) -> (
    World,
    crate::key_server::oidc_test_harness::Harness,
    String,
    String,
) {
    let (w, h) = World::start_oidc().await;
    let (a, b) = (
        oidc_bearer(&h, how, "A").await,
        oidc_bearer(&h, how, "B").await,
    );
    w.slot_serves("beta", "A", vec![tool("a_tool", "a")]);
    w.slot_serves("beta", "B", vec![tool("b_tool", "b")]);
    for (bearer, own) in [(&a, "a_tool"), (&b, "b_tool")] {
        let seen = w.discovered(bearer, "beta").await;
        assert!(seen.contains(&own.to_string()), "{how:?} premise: {seen:?}");
    }
    w.settle().await;
    (w, h, a, b)
}

/// K1/K2 (MIK-8350), RED negative half (killer M18): an OIDC principal (an
/// exchanged temporary token, or the ID token as a delegated bearer) is not
/// told of another principal's slot change, over listen (K1) or a legacy
/// GET session (K2). Its key equalling a POST's is IMPL, after MIK-8356.
async fn oidc_principal_is_silent_for_another_principals_slot(listen: bool) {
    let mut told_a = Vec::new();
    for how in [Oidc::Exchanged, Oidc::Delegated] {
        let (w, _h, a, b) = oidc_duo(how).await;
        let (mut ear_a, mut ear_b) = if listen {
            (w.listen(&a).await, w.listen(&b).await)
        } else {
            (w.legacy("a", &a).await, w.legacy("b", &b).await)
        };
        w.store_user("beta", "B", vec![tool("b_tool", "b"), tool("b_more", "m")]);
        assert_eq!(ear_b.told(&w).await, 1, "{how:?}: B's own view changed");
        told_a.push((how, ear_a.told(&w).await));
    }
    // Both credential kinds run before the verdict, so each one's premises
    // are exercised on base, not only the first one's.
    assert!(
        told_a.iter().all(|(_, n)| *n == 0),
        "A not told of B's change: RED on base: {told_a:?}"
    );
}

#[tokio::test]
async fn k1_an_oidc_listen_listener_is_silent_for_another_principals_slot() {
    oidc_principal_is_silent_for_another_principals_slot(true).await;
}

#[tokio::test]
async fn k2_an_oidc_legacy_session_is_silent_for_another_principals_slot() {
    oidc_principal_is_silent_for_another_principals_slot(false).await;
}
