// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: the session stream's write gate and a GET's admission, at the
//! branches the stream rows do not reach: a frame whose backend left the
//! caller's scope after it was queued, and an admission with no authorizer.

use std::collections::HashMap;
use std::sync::Arc;

use super::{Gate, write_gate};
use crate::backend::BackendRegistry;
use crate::config::{ApiKeyConfig, AuthConfig, StreamingConfig};
use crate::gateway::auth::live::{HeldCredential, held_credential};
use crate::gateway::auth::{AuthState, DashboardBootstrap, ResolvedAuthConfig};
use crate::gateway::streaming::{
    Judged, NotificationMultiplexer, ResolvedCaller, TaggedNotification, ViewDigest, ViewJudge,
    ViewSubject,
};

/// An authorizer whose one key, `scope-key`, may reach `backends`.
fn authorizer(backends: &[&str]) -> AuthState {
    let config = AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(b"scope-key")),
            expires_at: None,
            name: "scope-client".to_string(),
            rate_limit: 0,
            backends: backends.iter().map(|b| (*b).to_string()).collect(),
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
            ..Default::default()
        }],
        ..AuthConfig::default()
    };
    AuthState {
        key_server: None,
        dashboard_bootstrap: Arc::new(DashboardBootstrap::new()),
        tls_enabled: false,
        live_config: Arc::new(crate::config_reload::LiveConfig::with_auth(
            crate::config::Config::default(),
            Arc::new(ResolvedAuthConfig::from_config(
                &config,
                crate::gateway::record_principal::TEST_RECORD_KEY,
            )),
        )),
        agent_auth: crate::gateway::oauth::AgentAuthState::new(false, Arc::default()),
    }
}

fn multiplexer() -> Arc<NotificationMultiplexer> {
    Arc::new(NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        StreamingConfig::default(),
    ))
}

fn scope_key() -> Option<HeldCredential> {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer scope-key".parse().expect("a header value"),
    );
    held_credential(&headers)
}

fn update() -> TaggedNotification {
    TaggedNotification {
        source: "alpha".to_string(),
        event_type: "message".to_string(),
        data: serde_json::json!({"jsonrpc": "2.0", "method": "notifications/resources/updated"}),
        event_id: None,
    }
}

/// A frame queued for a backend the caller could reach, then written after
/// the caller's scope moved off that backend (an auth reload in between), is
/// skipped: not written, and the stream is not closed for it. Under the scope
/// it was queued with, the same frame is written.
/// Mutant: an out-of-scope frame written, or the stream closed for it.
#[tokio::test(flavor = "current_thread")]
async fn a_frame_whose_backend_left_the_callers_scope_is_skipped_not_written() {
    let mux = multiplexer();
    mux.set_authorizer(authorizer(&["alpha"]));
    let owner = crate::gateway::session_id::SessionOwner::Credential("scope".to_string());
    let (id, mut rx) = mux.get_or_create_session_scoped(None, &owner, scope_key());
    let reached = mux.broadcast_to_backend(&update(), "alpha").await;
    assert_eq!(reached, 1, "VOID: the in-scope update is queued");
    let frame = rx.try_recv().expect("VOID: the queued frame");
    let session = mux
        .sessions
        .read()
        .get(id.as_str())
        .map(Arc::clone)
        .expect("VOID: the session exists");

    let in_scope = write_gate(&mux, &session, None, &frame).await;
    assert!(
        matches!(in_scope, Gate::Write),
        "VOID: in scope, the frame is written"
    );
    mux.set_authorizer(authorizer(&["beta"]));
    let moved = write_gate(&mux, &session, None, &frame).await;
    assert!(
        matches!(moved, Gate::Skip),
        "a frame whose backend left the caller's scope must be skipped, not written or closed"
    );
}

/// A judge that must not be asked: an admission with no authorizer installed
/// judges nothing.
struct NeverAsked;

impl ViewJudge for NeverAsked {
    fn resolve<'a>(
        &'a self,
        _auth: &'a AuthState,
        _caller: (Option<&'a HeldCredential>, &'a ViewSubject),
    ) -> futures::future::BoxFuture<'a, Judged<ResolvedCaller>> {
        panic!("no caller is resolved without an authorizer")
    }

    fn digest(
        &self,
        _caller: &ResolvedCaller,
        _subject: &ViewSubject,
        _session_id: &str,
        _backend: &str,
    ) -> ViewDigest {
        panic!("no view is digested without an authorizer")
    }

    fn baseline(
        &self,
        _caller: &ResolvedCaller,
        _subject: &ViewSubject,
        _session_id: &str,
    ) -> HashMap<String, ViewDigest> {
        panic!("no view is baselined without an authorizer")
    }
}

/// With no authorizer installed, a GET's admission judges nothing and admits
/// the stream unjudged, and the stream then opens with no view: nothing is
/// resolved, baselined or registered for it.
/// Mutant: an unjudged admission refused, or resolved anyway.
#[tokio::test(flavor = "current_thread")]
async fn without_an_authorizer_a_get_is_admitted_unjudged_and_gets_no_view() {
    let mux = multiplexer();
    let judge: Arc<dyn ViewJudge> = Arc::new(NeverAsked);
    let subject = ViewSubject::default();
    let admitted = mux
        .admit_view(&subject, scope_key().as_ref(), judge.as_ref())
        .await
        .expect("an unjudged GET is admitted, not refused");
    let owner = crate::gateway::session_id::SessionOwner::Credential("bare".to_string());
    let (id, _rx) = mux.get_or_create_session_scoped(None, &owner, None);
    let view = mux
        .attach_admitted(id.as_str(), Arc::new(subject), judge, admitted)
        .await;
    assert!(view.is_none(), "an unjudged stream opens with no view");
}
