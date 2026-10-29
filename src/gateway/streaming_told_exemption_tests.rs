// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows on the "presented nothing" exemption: `dead_at_attach` admits
//! anonymously only a subject that carries no credential, and an anonymous
//! `Dead`(`Bearer`) hint is `Skip`, never `Close`.

use super::*;

fn auth() -> AuthState {
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
struct Fake(
    parking_lot::Mutex<Option<ViewDigest>>,
    parking_lot::Mutex<DeadReason>,
);

impl Fake {
    fn answering(served: &str, shown: &str) -> Arc<Self> {
        let judge = Arc::new(Self(
            parking_lot::Mutex::new(None),
            parking_lot::Mutex::new(DeadReason::Bearer),
        ));
        judge.say(served, shown);
        judge
    }

    fn say(&self, served: &str, shown: &str) {
        *self.0.lock() = Some(ViewDigest {
            served: served.to_owned(),
            shown: shown.to_owned(),
        });
    }

    fn die(&self) {
        *self.0.lock() = None;
        *self.1.lock() = DeadReason::Bearer;
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

fn adapter_assertion() -> crate::gateway::openwebui_adapter::AdapterAssertion {
    crate::gateway::openwebui_adapter::AdapterAssertion::for_test(0, 0)
}

async fn attached(subject: ViewSubject) -> std::result::Result<Option<StreamView>, DeadReason> {
    let multiplexer = NotificationMultiplexer::new(
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::StreamingConfig::default(),
    );
    multiplexer.set_authorizer(auth());
    let owner = crate::gateway::session_id::SessionOwner::Anonymous;
    let (session, _rx) = multiplexer.get_or_create_session_scoped(Some("s"), &owner, None);
    let judge = Fake::answering("s0", "x");
    judge.die();
    multiplexer.attach_view(&session, subject, judge).await
}

#[tokio::test]
async fn a_subject_with_only_a_cf_assertion_is_refused_at_attach() {
    let subject = ViewSubject {
        identity_source: HeldSource::Cloudflare(
            crate::key_server::oidc::VerifiedAssertion::for_test("assertion"),
        ),
        ..ViewSubject::default()
    };
    assert!(matches!(attached(subject).await, Err(DeadReason::Bearer)));
}

#[tokio::test]
async fn a_subject_with_only_a_certificate_is_refused_at_attach() {
    let subject = ViewSubject {
        cert: Some(crate::mtls::CertIdentity {
            common_name: Some("svc".to_owned()),
            display_name: "svc".to_owned(),
            ..Default::default()
        }),
        ..ViewSubject::default()
    };
    assert!(matches!(attached(subject).await, Err(DeadReason::Bearer)));
}

#[tokio::test]
async fn a_subject_with_only_an_adapter_assertion_is_refused_at_attach() {
    let subject = ViewSubject {
        adapter: Some(adapter_assertion()),
        ..ViewSubject::default()
    };
    assert!(matches!(attached(subject).await, Err(DeadReason::Bearer)));
}

#[tokio::test]
async fn a_subject_with_only_an_oauth_agent_is_refused_at_attach() {
    let subject = ViewSubject {
        oauth_agent: Some(crate::gateway::oauth::OAuthAgentIdentity {
            client_id: "agent".to_owned(),
            agent_name: "agent".to_owned(),
            scopes: Vec::new(),
            raw_scopes: Vec::new(),
            quota_principal: None,
        }),
        ..ViewSubject::default()
    };
    assert!(matches!(attached(subject).await, Err(DeadReason::Bearer)));
}

#[tokio::test]
async fn a_subject_with_no_credential_keeps_its_stream_at_attach() {
    assert!(matches!(
        attached(ViewSubject::default()).await,
        Ok(Some(_))
    ));
}

#[tokio::test]
async fn an_anonymous_dead_bearer_hint_is_skipped_never_closed() {
    let judge = Fake::answering("s0", "x");
    judge.die();
    let view = StreamView::new(
        Arc::new(ViewSubject::default()),
        Arc::new(ViewRecord::default()),
        Arc::clone(&judge) as Arc<dyn ViewJudge>,
    );
    assert_eq!(view.decide(&auth(), None, "", "a").await, Decision::Skip);
}

/// An anonymous session that opened a stream is not reached by a judged hint:
/// the fan-out finds no moved view for it (silence), so it counts no copy.
#[tokio::test]
async fn an_anonymous_session_is_not_reached_by_a_judged_hint() {
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
        .attach_view(&session, ViewSubject::default(), judge.clone())
        .await;
    assert!(
        matches!(attached, Ok(Some(_))),
        "premise: its stream opened"
    );
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
    assert_eq!(reached, 0, "an anonymous session is told nothing");
}
