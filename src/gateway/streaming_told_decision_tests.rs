// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows on a stream's write-time decision (MIK-8350 D17).

use super::*;

pub(super) fn auth() -> AuthState {
    AuthState {
        key_server: None,
        dashboard_bootstrap: Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        tls_enabled: false,
        live_config: Arc::new(crate::config_reload::LiveConfig::with_auth(
            crate::config::Config::default(),
            Arc::new(crate::gateway::auth::ResolvedAuthConfig::from_config(
                &crate::config::AuthConfig::default(),
                crate::gateway::record_principal::TEST_RECORD_KEY,
            )),
        )),
        agent_auth: crate::gateway::oauth::AgentAuthState::new(false, Arc::default()),
    }
}

/// A judge that answers with whatever it was last told to.
pub(super) struct Fake(
    parking_lot::Mutex<Option<ViewDigest>>,
    parking_lot::Mutex<DeadReason>,
);

impl Fake {
    pub(super) fn answering(served: &str, shown: &str) -> Arc<Self> {
        let judge = Arc::new(Self(
            parking_lot::Mutex::new(None),
            parking_lot::Mutex::new(DeadReason::Bearer),
        ));
        judge.say(served, shown);
        judge
    }

    pub(super) fn say(&self, served: &str, shown: &str) {
        *self.0.lock() = Some(ViewDigest {
            served: served.to_owned(),
            shown: shown.to_owned(),
        });
    }

    fn die(&self) {
        self.die_as(DeadReason::Bearer);
    }

    fn die_as(&self, reason: DeadReason) {
        *self.0.lock() = None;
        *self.1.lock() = reason;
    }
}

impl ViewJudge for Fake {
    fn resolve<'a>(
        &'a self,
        _: &'a AuthState,
        _: (Option<&'a HeldCredential>, &'a ViewSubject),
    ) -> futures::future::BoxFuture<'a, Judged<ResolvedCaller>> {
        Box::pin(async move {
            if self.0.lock().is_none() {
                return Judged::Dead(*self.1.lock());
            }
            Judged::Live(ResolvedCaller {
                client: crate::gateway::auth::anonymous_client(),
                identity: None,
                agent: None,
            })
        })
    }

    fn digest(&self, _: &ResolvedCaller, _: &ViewSubject, _: &str, _: &str) -> ViewDigest {
        self.0.lock().clone().expect("a live fake answers")
    }

    fn baseline(
        &self,
        _: &ResolvedCaller,
        _: &ViewSubject,
        _: &str,
    ) -> HashMap<String, ViewDigest> {
        HashMap::new()
    }
}

pub(super) fn view(judge: &Arc<Fake>) -> StreamView {
    let view = StreamView::new(
        Arc::new(ViewSubject::default()),
        Arc::new(ViewRecord::default()),
        Arc::clone(judge) as Arc<dyn ViewJudge>,
    );
    // Stamp 0: the record's own reads start at 1, as they do after an attach.
    view.record.state().baseline(
        0,
        HashMap::from([(
            "a".to_owned(),
            ViewDigest {
                served: "s0".to_owned(),
                shown: "x".to_owned(),
            },
        )]),
    );
    view
}

#[tokio::test]
async fn a_caller_that_no_longer_resolves_closes_the_stream() {
    let judge = Fake::answering("s0", "x");
    let view = view(&judge);
    judge.die();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer dead"),
    );
    let held = crate::gateway::auth::live::held_credential(&headers);
    assert_eq!(
        view.decide(&auth(), held.as_ref(), "", "a").await,
        Decision::Close
    );
}

#[tokio::test]
async fn a_view_that_returned_to_what_it_was_told_is_not_written() {
    let judge = Fake::answering("s1", "x2");
    let view = view(&judge);
    // The fan-out saw a moved view; by the time the stream writes, it is
    // back where the caller was told.
    judge.say("s0", "x");
    assert_eq!(view.decide(&auth(), None, "", "a").await, Decision::Skip);
}

#[tokio::test]
async fn two_copies_of_one_moved_view_are_written_once() {
    let judge = Fake::answering("s1", "x2");
    let view = view(&judge);
    assert_eq!(view.decide(&auth(), None, "", "a").await, Decision::Write);
    assert_eq!(view.decide(&auth(), None, "", "a").await, Decision::Skip);
}

#[tokio::test]
async fn a_commit_read_before_a_newer_write_is_refused() {
    let judge = Fake::answering("s1", "x2");
    let view = view(&judge);
    let auth = auth();
    let Judged::Live(Some(older)) = view.owed(&auth, None, "", "a").await else {
        panic!("the first read is owed");
    };
    judge.say("s2", "x3");
    let Judged::Live(Some(newer)) = view.owed(&auth, None, "", "a").await else {
        panic!("the second read is owed");
    };
    assert!(view.commit(&newer));
    assert!(!view.commit(&older), "the slow reader must not roll back");
}

#[tokio::test]
async fn a_read_gets_its_stamp_only_when_it_holds_the_gate() {
    let record = Arc::new(ViewRecord::default());
    let held = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let first = {
        let (record, held, release) =
            (Arc::clone(&record), Arc::clone(&held), Arc::clone(&release));
        tokio::spawn(async move {
            record
                .read(async {
                    held.notify_one();
                    release.notified().await;
                })
                .await
                .0
        })
    };
    held.notified().await;
    let second = {
        let record = Arc::clone(&record);
        tokio::spawn(async move { record.read(async {}).await.0 })
    };
    // The second read cannot start while the first is mid-capture.
    tokio::task::yield_now().await;
    assert!(
        !second.is_finished(),
        "the gate was not held across the capture"
    );
    release.notify_one();
    let (a, b) = (first.await.expect("first"), second.await.expect("second"));
    assert!(a < b, "stamp order is capture order: {a} then {b}");
}

/// R14 (D17h): a listing the caller never got is not recorded as told, so the
/// change it hid is still owed; a delivered one is recorded.
#[test]
fn a_withheld_listing_leaves_the_record_alone_and_a_delivered_one_moves_it() {
    let moved = ViewDigest {
        served: "s1".to_owned(),
        shown: "x2".to_owned(),
    };
    let held = |record: &Arc<ViewRecord>| {
        PendingRefresh(Some((
            Arc::clone(record),
            record.epoch(),
            5,
            HashMap::from([("a".to_owned(), moved.clone())]),
        )))
    };
    let judge = Fake::answering("s0", "x");
    let withheld = view(&judge);
    held(&withheld.record).settle(false);
    assert_eq!(
        withheld.record.state().peek(6, "a", &moved),
        Peek::Owed,
        "the withheld listing must not have told the caller"
    );

    let delivered = view(&judge);
    held(&delivered.record).settle(true);
    assert_eq!(delivered.record.state().peek(6, "a", &moved), Peek::Quiet);
}

#[cfg(feature = "metrics")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_caller_dead_at_attach_gets_no_stream_and_is_counted() {
    let multiplexer = NotificationMultiplexer::new(
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::StreamingConfig::default(),
    );
    multiplexer.set_authorizer(auth());
    let owner = crate::gateway::session_id::SessionOwner::Credential("k".to_owned());
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer dead"),
    );
    let held = crate::gateway::auth::live::held_credential(&headers);
    let (session, _rx) = multiplexer.get_or_create_session_scoped(Some("s"), &owner, held);
    let judge = Fake::answering("s0", "x");
    judge.die();
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let attached = telemetry_metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(multiplexer.attach_view(
                &session,
                ViewSubject::default(),
                judge,
            ))
        })
    });
    assert!(matches!(attached, Err(DeadReason::Bearer)));
    let text = handle.render();
    assert!(
        text.lines().any(
            |l| l.starts_with(r#"mcp_view_liveness_dead_total{reason="bearer"} "#)
                && l.ends_with(" 1")
        ),
        "{text}"
    );
}

#[tokio::test]
async fn a_caller_that_presented_nothing_keeps_its_stream_at_attach() {
    let multiplexer = NotificationMultiplexer::new(
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::StreamingConfig::default(),
    );
    multiplexer.set_authorizer(auth());
    let owner = crate::gateway::session_id::SessionOwner::Anonymous;
    let (session, _rx) = multiplexer.get_or_create_session_scoped(Some("s"), &owner, None);
    let judge = Fake::answering("s0", "x");
    judge.die();
    let attached = multiplexer
        .attach_view(&session, ViewSubject::default(), judge)
        .await;
    assert!(matches!(attached, Ok(Some(_))));
}

/// Every reason a held credential can die for refuses the attach and says so
/// (the handler answers each with the one invalid-credential refusal).
#[tokio::test]
async fn a_credentialed_caller_dead_for_any_reason_is_refused_at_attach() {
    for reason in [DeadReason::Bearer, DeadReason::Adapter, DeadReason::Cf] {
        let multiplexer = NotificationMultiplexer::new(
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::StreamingConfig::default(),
        );
        multiplexer.set_authorizer(auth());
        let owner = crate::gateway::session_id::SessionOwner::Credential("k".to_owned());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer dead"),
        );
        let held = crate::gateway::auth::live::held_credential(&headers);
        let (session, _rx) = multiplexer.get_or_create_session_scoped(Some("s"), &owner, held);
        let judge = Fake::answering("s0", "x");
        judge.die_as(reason);
        let attached = multiplexer
            .attach_view(&session, ViewSubject::default(), judge)
            .await;
        assert_eq!(attached.err(), Some(reason));
    }
}

/// A key that may reach `beta` only, bearer `narrow`.
fn narrow_auth() -> AuthState {
    let config = crate::config::AuthConfig {
        enabled: true,
        api_keys: vec![crate::config::ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(b"narrow")),
            expires_at: None,
            name: "narrow".to_owned(),
            rate_limit: 0,
            backends: vec!["beta".to_owned()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
            ..Default::default()
        }],
        ..crate::config::AuthConfig::default()
    };
    AuthState {
        live_config: Arc::new(crate::config_reload::LiveConfig::with_auth(
            crate::config::Config::default(),
            Arc::new(crate::gateway::auth::ResolvedAuthConfig::from_config(
                &config,
                crate::gateway::record_principal::TEST_RECORD_KEY,
            )),
        )),
        ..auth()
    }
}

/// R9-legacy (D17f): a hint for a backend the caller cannot reach is still
/// judged, not skipped before it: a view that moved when scope narrowed is
/// owed once. A caller whose view did not move is told nothing (the judge
/// decides, not the scope check alone).
#[tokio::test]
async fn a_hint_for_a_backend_out_of_scope_is_still_judged() {
    let multiplexer = NotificationMultiplexer::new(
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::StreamingConfig::default(),
    );
    multiplexer.set_authorizer(narrow_auth());
    let owner = crate::gateway::session_id::SessionOwner::Credential("narrow".to_owned());
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer narrow"),
    );
    let held = crate::gateway::auth::live::held_credential(&headers);
    let (session, _rx) = multiplexer.get_or_create_session_scoped(Some("s"), &owner, held);
    let judge = Fake::answering("s0", "x");
    let attached = multiplexer
        .attach_view(&session, ViewSubject::default(), judge.clone())
        .await;
    assert!(matches!(attached, Ok(Some(_))), "premise: a baselined view");
    let hint = TaggedNotification {
        source: "alpha".to_owned(),
        event_type: "message".to_owned(),
        data: serde_json::json!({
            "jsonrpc": "2.0", "method": "notifications/tools/list_changed"
        }),
        event_id: None,
    };
    let reached = multiplexer
        .broadcast_to_backend_judged(&hint, "alpha", &*judge)
        .await;
    assert_eq!(
        reached, 1,
        "alpha is out of the key's scope, yet its view moved"
    );
}

/// A hint read for one caller, then the session's credential is replaced: the
/// read describes the old caller and is never recorded for the new one, even
/// though its stamp is newer than the new caller's baseline.
#[tokio::test]
async fn a_hint_read_before_a_rekey_is_not_recorded_after_it() {
    let judge = Fake::answering("s0", "x");
    let view = view(&judge);
    let old_epoch = view.record.epoch();
    view.record.clear();
    let new_view = ViewDigest {
        served: "s0".to_owned(),
        shown: "x".to_owned(),
    };
    view.record
        .state()
        .baseline(10, HashMap::from([("a".to_owned(), new_view.clone())]));
    let stale = Owed {
        backend: "a".to_owned(),
        digest: ViewDigest {
            served: "s9".to_owned(),
            shown: "y".to_owned(),
        },
        stamp: 50,
        epoch: old_epoch,
    };
    assert!(!view.commit(&stale), "a read of the old caller is refused");
    assert_eq!(
        view.record.state().peek(51, "a", &new_view),
        Peek::Quiet,
        "the new caller's record is untouched"
    );
}

/// The same for a refresh read before a rekey and settled after it.
#[tokio::test]
async fn a_refresh_read_before_a_rekey_is_not_settled_after_it() {
    let judge = Fake::answering("s0", "x");
    let view = view(&judge);
    let old_epoch = view.record.epoch();
    view.record.clear();
    let new_view = ViewDigest {
        served: "s0".to_owned(),
        shown: "x".to_owned(),
    };
    view.record
        .state()
        .baseline(10, HashMap::from([("a".to_owned(), new_view.clone())]));
    let stale = ViewDigest {
        served: "s9".to_owned(),
        shown: "y".to_owned(),
    };
    PendingRefresh(Some((
        Arc::clone(&view.record),
        old_epoch,
        50,
        HashMap::from([("a".to_owned(), stale)]),
    )))
    .settle(true);
    assert_eq!(
        view.record.state().peek(51, "a", &new_view),
        Peek::Quiet,
        "a refresh of the old caller does not overwrite the new record"
    );
}
