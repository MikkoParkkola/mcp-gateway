// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: opened-session history survives idle-record pruning, and a
//! never-opened session keeps the default-subject copy after the same
//! pruning. A private descendant of the custody fixture: it reaches that
//! fixture's private fields and helpers with no wider visibility.

use super::*;
use tokio::sync::broadcast::error::TryRecvError;

fn idle_subject(n: usize) -> ViewSubject {
    ViewSubject {
        grant_subject: Some(crate::identity_grants::GrantSubject::new(
            "proxy",
            format!("idle-{n}"),
            None,
        )),
        ..ViewSubject::default()
    }
}

fn prune_idle(session: &super::super::ClientSession) {
    for n in 0..(super::super::MAX_IDLE_RECORDS * 4) {
        drop(session.record_for(&idle_subject(n)));
    }
}

fn set_digest(judge: &CfJudge, served: &str, shown: &str) {
    *judge.digest.lock() = ViewDigest {
        served: served.to_owned(),
        shown: shown.to_owned(),
    };
}

fn assert_bare_hint(
    bare: &mut tokio::sync::broadcast::Receiver<crate::gateway::streaming::SessionFrame>,
    who: &str,
) {
    match bare.try_recv() {
        Ok(frame) => std::assert_eq!(
            frame.data["method"],
            serde_json::json!("notifications/tools/list_changed"),
            "{who}: the bare copy is not the tools/list_changed hint: {}",
            frame.data
        ),
        Err(error) => panic!("{who}: the bare receiver held no copy: {error:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_closed_session_whose_opened_record_was_pruned_gets_no_default_copy() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let (subject, verifier) = admit(&harness).await;
    let (fixture, view) = CustodyFixture::attach(subject, verifier).await;
    let original = Arc::downgrade(&fixture.primary.record);
    let session = fixture
        .mux
        .sessions
        .read()
        .get(fixture.session_id.as_str())
        .cloned()
        .unwrap_or_else(|| panic!("VOID: custody session vanished before close"));
    let mut body = fixture.body(view);
    body.expect_connected().await;
    drop(body);
    let CustodyFixture {
        mux,
        session_id: _session_id,
        judge,
        primary,
        _bare: mut bare,
    } = fixture;
    drop(primary);
    prune_idle(&session);
    std::assert!(
        original.upgrade().is_none(),
        "VOID: the original opened record was not evicted by idle pruning"
    );
    std::assert!(
        session.records.read().len() <= super::super::MAX_IDLE_RECORDS,
        "VOID: idle records did not stay bounded: {}",
        session.records.read().len()
    );
    // Setup premise: a default-subject record, were one (wrongly) judged,
    // would take its baseline at the current digest on this broadcast.
    let baselining = mux
        .broadcast_to_backend_judged(&hint(), BACKEND, &*judge)
        .await;
    std::assert_eq!(
        baselining,
        0,
        "VOID: the baselining premise broadcast reached a session"
    );
    set_digest(&judge, "s1", "x2");
    let reached = mux
        .broadcast_to_backend_judged(&hint(), BACKEND, &*judge)
        .await;
    std::assert_eq!(
        reached,
        0,
        "a closed session whose opened record was pruned must not be \
         re-judged as the default subject"
    );
    std::assert!(
        matches!(bare.try_recv(), Err(TryRecvError::Empty)),
        "the closed session's bare receiver must hold no default copy"
    );
    std::assert!(
        !session.never_opened(),
        "opened-session history must survive idle pruning"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_never_opened_session_still_gets_the_default_copy_after_idle_pruning() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let verifier =
        OidcVerifier::with_http_client(harness.ks.config.oidc.clone(), reqwest::Client::new());
    let judge = CfJudge::new(verifier);
    let authorizer = custody_auth("custody-key");
    let credential = held("custody-key");
    let caller = current_caller(&authorizer, Some(&credential))
        .await
        .unwrap_or_else(|| panic!("VOID: cold bearer must resolve before its session opens"));
    std::assert!(
        caller.client.authenticated && !caller.client.principal.is_empty(),
        "VOID: cold bearer did not authenticate"
    );
    let owner =
        crate::gateway::session_id::SessionOwner::Credential(caller.client.principal.clone());
    let mux = Arc::new(NotificationMultiplexer::new(
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::StreamingConfig::default(),
    ));
    mux.set_authorizer(authorizer);
    let (session_id, mut bare) = mux.get_or_create_session_scoped(None, &owner, Some(credential));
    let session = mux
        .sessions
        .read()
        .get(session_id.as_str())
        .cloned()
        .unwrap_or_else(|| panic!("VOID: cold session vanished"));
    std::assert!(
        session.never_opened(),
        "VOID: the cold session must start never-opened"
    );
    let baselining = mux
        .broadcast_to_backend_judged(&hint(), BACKEND, &*judge)
        .await;
    std::assert_eq!(
        baselining,
        0,
        "VOID: the baselining premise broadcast reached the cold session"
    );
    set_digest(&judge, "s1", "x2");
    let reached = mux
        .broadcast_to_backend_judged(&hint(), BACKEND, &*judge)
        .await;
    std::assert_eq!(
        reached,
        1,
        "a never-opened session must get the default-subject copy"
    );
    assert_bare_hint(&mut bare, "cold first copy");
    prune_idle(&session);
    std::assert!(
        session.records.read().len() <= super::super::MAX_IDLE_RECORDS,
        "idle records must stay bounded: {}",
        session.records.read().len()
    );
    std::assert!(
        session.never_opened(),
        "idle pruning must not mark a never-opened session opened"
    );
    let rebaselining = mux
        .broadcast_to_backend_judged(&hint(), BACKEND, &*judge)
        .await;
    std::assert_eq!(
        rebaselining,
        0,
        "VOID: the post-prune baselining premise broadcast reached the cold session"
    );
    set_digest(&judge, "s2", "x3");
    let reached = mux
        .broadcast_to_backend_judged(&hint(), BACKEND, &*judge)
        .await;
    std::assert_eq!(
        reached,
        1,
        "a never-opened session must still get the default copy after idle pruning"
    );
    assert_bare_hint(&mut bare, "post-prune cold copy");
}
