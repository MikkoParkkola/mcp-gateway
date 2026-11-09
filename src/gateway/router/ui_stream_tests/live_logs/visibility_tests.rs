// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who sees which row on the live stream, through the real router: a caller
//! demoted between catch-up pages, a scoped key's backend list reordered, and
//! another subject's call on the live path.

use super::super::identity::{ISSUER, set_mapping, token};
use super::*;
use crate::key_server::oidc::VerifiedIdentity;

/// `auditors` read every row, `devs` only their own.
const MAPPING: &str = "rules: [{ issuer: \"https://issuer.test\", group: auditors, role: auditor }, \
                       { issuer: \"https://issuer.test\", group: devs, role: developer }]";

/// A key-server token for `groups`, a gateway whose key server holds it and
/// whose invocation log the stream reads, and [`MAPPING`] published. Returns
/// the token's bearer and identity.
async fn keyed(
    groups: &[&str],
) -> (
    Arc<AppState>,
    impl Sized,
    Arc<TransparencyLogger>,
    String,
    VerifiedIdentity,
) {
    let tok = token(groups);
    let (bearer, me) = (tok.token.clone(), tok.identity.clone());
    let key_server = Arc::new(crate::key_server::KeyServer::new(
        crate::config::KeyServerConfig::default(),
        crate::key_server::email_hash::EmailHashKey::for_test(),
    ));
    crate::key_server::store::activate_for_test(key_server.store.as_ref(), key_server.config.token_ttl_secs, tok);
    let dir = crate::test_dir_keep::kept_tempdir();
    let inv = logger(&dir, "invocation.jsonl");
    inv.keep_test_dir(Arc::clone(&dir));
    let (state, fixture) =
        crate::gateway::router::tests::meta_fixture::test_router_app_state_with_logs_and_key_server(
            &auth(&["a", "b"]),
            Some(key_server),
            Some(Arc::clone(&inv)),
            None,
        )
        .await;
    set_mapping(&state, MAPPING);
    (state, (fixture, dir), inv, bearer, me)
}

/// The OIDC actor id of `subject` under `issuer`, as a call records it.
fn actor(issuer: &str, subject: &str) -> String {
    VerifiedIdentity::for_test(
        subject.to_owned(),
        format!("{subject}@example.test"),
        None,
        vec![],
        issuer.to_owned(),
    )
    .stable_actor_id()
}

/// A call by `who` (an actor id) on `server`, named `tool_{n}`.
fn call_as(log: &TransparencyLogger, who: &str, server: &str, n: usize) {
    log.log_invocation(
        "s",
        who,
        server,
        &format!("tool_{n}"),
        "sha256:aa",
        "sha256:bb",
    )
    .expect("the call is logged");
}

/// Whether a frame's row is the call named `tool_{n}`.
fn is_tool(f: &Frame, n: usize) -> bool {
    f.data.contains(&format!("\"tool_{n}\""))
}

#[tokio::test]
async fn s2b_another_subjects_call_on_the_live_path_sends_no_frame() {
    let (state, _keep, inv, bearer, me) = keyed(&["devs"]).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(&bearer), None)).await;
    within(s.until("hello")).await;
    call_as(&inv, &actor(ISSUER, "other"), "srv", 1);
    call_as(
        &inv,
        &actor("https://other-issuer.test", me.subject()),
        "srv",
        2,
    );
    call_as(&inv, "c", "srv", 3);
    call_as(&inv, &me.stable_actor_id(), "srv", 4);
    let first = within(s.until("activity")).await;
    assert!(
        is_tool(&first, 4),
        "the first activity frame is the caller's own call, not another subject's, \
         another issuer's or an unidentified one: {}",
        first.data
    );
}

#[tokio::test]
async fn sc_a_reordered_scoped_key_keeps_its_stream_and_a_narrowed_one_ends_it() {
    let (state, _dirs, inv) = logged(true).await;
    tokio::time::pause();
    let mut s = open(&state, request(STREAM, Who::Bearer(SCOPED_ADMIN), None)).await;
    within(s.until("hello")).await;
    state.live_config.edit(|c| c.auth = auth(&["b", "a", "a"]));
    let published = state.live_config.get();
    let key = published
        .auth
        .api_keys
        .iter()
        .find(|k| k.name == SCOPED_ADMIN)
        .expect("the reload publishes the scoped key");
    assert_eq!(
        key.backends,
        vec!["b", "a", "a"],
        "premise: the list is reordered"
    );
    // Still open after four recheck periods: `ended_within` cannot say this,
    // as it reads on until the stream ends and only then checks the time.
    assert!(
        tokio::time::timeout(Duration::from_secs(4), s.ended())
            .await
            .is_err(),
        "a reordered list with a repeat is the same set: the stream stays"
    );
    call(&inv, "a", 1);
    let f = within(s.until("activity")).await;
    assert!(is_tool(&f, 1), "the stream still delivers: {}", f.data);
    // The control: the recheck does see reloads, so a narrowed list ends it.
    state.live_config.edit(|c| c.auth = auth(&["a"]));
    assert!(
        s.ended_within(REVOKED_WITHIN).await,
        "a narrowed list ends the stream"
    );
}

/// An Auditor's stream catching up on another subject's calls, parked at the
/// page gate before its third page with no frame in flight; `after` is then
/// published as the role mapping and one page is released. The stream must
/// send no further row, end, and read no further page.
async fn demoted_between_pages(after: &str, role: Option<crate::control_plane::ControlPlaneRole>) {
    let (state, _keep, inv, bearer, me) = keyed(&["auditors"]).await;
    let other = actor(ISSUER, "other");
    let mut s = open(&state, request(STREAM, Who::Bearer(&bearer), None)).await;
    within(s.until("hello")).await;
    call_as(&inv, &other, "a", 0);
    let id = within(s.until("activity")).await.id.expect("an id");
    drop(s);
    for n in 1..=3 * PAGE {
        call_as(&inv, &other, "a", n);
    }
    tokio::time::pause();
    let hub = state.dashboard_bootstrap.stream_hub();
    // The hub counts every page read, armed or not, and a first connection
    // can run a catch-up of its own: count from here.
    let before = hub.pages_read_for_test();
    hub.arm_page_gate_for_test();
    hub.release_pages_for_test(2);
    let mut again = open(&state, request(STREAM, Who::Bearer(&bearer), Some(&id))).await;
    within(again.until("hello")).await;
    // Read the two released pages until the loop waits at the gate before
    // its third, then whatever was already sent: nothing sent before the
    // demotion is left to read after it. The parked loop sends nothing more.
    within(async {
        while hub.pages_at_gate_for_test() < 3 {
            // Idle until parked: a frame, or a quiet 100 ms; a loop that never
            // parks is failed by the outer bound.
            if let Ok(f) = tokio::time::timeout(Duration::from_millis(100), again.next()).await {
                f.expect("the catch-up is still open");
            }
        }
        while let Ok(f) = tokio::time::timeout(Duration::from_secs(1), again.next()).await {
            f.expect("the parked catch-up is still open");
        }
    })
    .await;
    assert_eq!(
        hub.pages_read_for_test() - before,
        2,
        "premise: two pages read, the third waits"
    );
    let read = hub.pages_read_for_test();
    set_mapping(&state, after);
    assert_eq!(
        state
            .live_config
            .get()
            .control_plane
            .role_mapping
            .resolve_role(&me),
        role,
        "premise: the published mapping demotes the caller"
    );
    hub.release_pages_for_test(1);
    within(async {
        while let Some(f) = again.next().await {
            assert_ne!(
                f.event, "activity",
                "a row sent after the demotion: {}",
                f.data
            );
        }
    })
    .await;
    assert_eq!(
        hub.pages_read_for_test(),
        read,
        "no page is read after the caller's access changed"
    );
}

#[tokio::test]
async fn a1b_an_auditor_demoted_between_pages_reads_and_sends_no_more() {
    demoted_between_pages(
        "rules: [{ issuer: \"https://issuer.test\", group: auditors, role: developer }]",
        Some(crate::control_plane::ControlPlaneRole::Developer),
    )
    .await;
}

#[tokio::test]
async fn a1b2_an_auditor_whose_role_is_removed_between_pages_reads_and_sends_no_more() {
    demoted_between_pages("rules: []", None).await;
}
