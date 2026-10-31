// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 C0c: raw Cloudflare subject custody of a real stream body.

use std::sync::Weak;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use axum::response::IntoResponse as _;
use futures::StreamExt as _;
use serde_json::{Value, json};

use super::*;
use crate::gateway::auth::live::{current_caller, held_credential};
use crate::gateway::streaming::create_sse_response_with_view;
use crate::gateway::streaming::told_cf_grace_tests::custody_tests::grace_history_challenge;
use crate::key_server::oidc::{OidcError, OidcVerifier};
use crate::key_server::oidc_test_harness::{Harness, ISS_A, config_yaml};

const BACKEND: &str = "demo";
const WITHIN: Duration = Duration::from_secs(5);
static NONCE: AtomicU64 = AtomicU64::new(0);

fn custody_auth(token: &str) -> AuthState {
    let config = crate::config::AuthConfig {
        enabled: true,
        bearer_token: Some(token.to_owned()),
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
        ..super::decision_tests::auth()
    }
}

fn held(token: &str) -> HeldCredential {
    let mut headers = axum::http::HeaderMap::new();
    let value = format!("Bearer {token}")
        .parse()
        .unwrap_or_else(|_| panic!("VOID: custody bearer header must parse"));
    headers.insert(axum::http::header::AUTHORIZATION, value);
    held_credential(&headers).unwrap_or_else(|| panic!("VOID: custody bearer must be held"))
}

fn receipt_fp(subject: &ViewSubject) -> String {
    let HeldSource::Cloudflare(receipt) = &subject.identity_source else {
        panic!("VOID: custody subject holds no Cloudflare receipt");
    };
    crate::hashing::sha256_hex(receipt.expose().as_bytes())
}

fn holds_live_cf(subject: &ViewSubject) -> bool {
    match &subject.identity_source {
        HeldSource::Cloudflare(receipt) => receipt.live(),
        _ => false,
    }
}

async fn admit(harness: &Harness) -> (ViewSubject, OidcVerifier) {
    let nonce = NONCE.fetch_add(1, Ordering::SeqCst);
    let token = harness.mint(ISS_A, "alice", &json!({"jti": format!("custody-{nonce}")}));
    let verifier =
        OidcVerifier::with_http_client(harness.ks.config.oidc.clone(), reqwest::Client::new());
    let age = crate::config::KeyServerOidcConfig {
        token_age: crate::key_server::TokenAgeCap::ExpOnly,
    };
    let receipt = match verifier.verify_checked(token, &age).await {
        Ok((_identity, receipt)) => receipt,
        Err(error) => panic!("VOID: genuine custody admission failed: {error}"),
    };
    let subject = ViewSubject {
        identity_source: HeldSource::Cloudflare(receipt),
        ..ViewSubject::default()
    };
    (subject, verifier)
}

/// Real judge: only its digest data and current verifier are controlled.
pub(in crate::gateway::streaming) struct CfJudge {
    verifier: parking_lot::RwLock<Arc<OidcVerifier>>,
    digest: parking_lot::Mutex<ViewDigest>,
    resolves: AtomicUsize,
    completed_verifications: AtomicUsize,
}

impl CfJudge {
    fn new(verifier: OidcVerifier) -> Arc<Self> {
        Arc::new(Self {
            verifier: parking_lot::RwLock::new(Arc::new(verifier)),
            digest: parking_lot::Mutex::new(ViewDigest {
                served: "s0".to_owned(),
                shown: "x".to_owned(),
            }),
            resolves: AtomicUsize::new(0),
            completed_verifications: AtomicUsize::new(0),
        })
    }
}

impl ViewJudge for CfJudge {
    fn resolve<'a>(
        &'a self,
        auth: &'a AuthState,
        caller: (Option<&'a HeldCredential>, &'a ViewSubject),
    ) -> futures::future::BoxFuture<'a, Judged<ResolvedCaller>> {
        Box::pin(async move {
            self.resolves.fetch_add(1, Ordering::SeqCst);
            let Some(found) = current_caller(auth, caller.0).await else {
                return Judged::Dead(DeadReason::Bearer);
            };
            let verifier = Arc::clone(&self.verifier.read());
            let identity_cfg = crate::security::caller_identity::CallerIdentityConfig::default();
            let ctx = LiveCtx {
                agent: None,
                caller_identity: &identity_cfg,
                cf_verifier: Some(&verifier),
            };
            let verification = caller.1.verify_held_cf(&ctx).await;
            self.completed_verifications.fetch_add(1, Ordering::SeqCst);
            if let Err(reason) = verification {
                return Judged::Dead(reason);
            }
            if let Err(reason) = caller.1.live(&ctx) {
                return Judged::Dead(reason);
            }
            Judged::Live(ResolvedCaller {
                client: found.client,
                identity: found.identity,
                agent: None,
            })
        })
    }

    fn digest(
        &self,
        _caller: &ResolvedCaller,
        _subject: &ViewSubject,
        _session_id: &str,
        _backend: &str,
    ) -> ViewDigest {
        self.digest.lock().clone()
    }

    fn baseline(
        &self,
        _caller: &ResolvedCaller,
        _subject: &ViewSubject,
        _session_id: &str,
    ) -> HashMap<String, ViewDigest> {
        HashMap::from([(BACKEND.to_owned(), self.digest.lock().clone())])
    }
}

/// One attachment's secret-free identity and every raw-owner witness.
pub(in crate::gateway::streaming) struct Attachment {
    witnesses: Vec<Weak<ViewSubject>>,
    receipt_fp: String,
    grace: Weak<parking_lot::Mutex<CfGrace>>,
    record: Arc<ViewRecord>,
    key: String,
}

impl Attachment {
    pub(in crate::gateway::streaming) fn assert_witnesses_live_cf(&self) {
        std::assert!(
            !self.witnesses.is_empty(),
            "VOID: custody witness set is empty"
        );
        for witness in &self.witnesses {
            let upgraded = witness
                .upgrade()
                .unwrap_or_else(|| panic!("VOID: a custody witness died before close"));
            std::assert!(
                holds_live_cf(&upgraded),
                "VOID: a custody witness holds no live Cloudflare receipt"
            );
            drop(upgraded);
        }
    }

    pub(in crate::gateway::streaming) fn all_owners_dead(&self) -> bool {
        !self.witnesses.is_empty()
            && self
                .witnesses
                .iter()
                .all(|witness| witness.upgrade().is_none())
    }

    fn assert_original_live(&self) {
        let first = self
            .witnesses
            .first()
            .unwrap_or_else(|| panic!("VOID: custody witness set is empty"));
        std::assert!(
            first.upgrade().is_some(),
            "VOID: the surviving stream lost its original subject owner"
        );
    }
}

/// Typed complete-frame reader over a native SSE response body.
pub(in crate::gateway::streaming) struct CustodyBody {
    body: axum::body::BodyDataStream,
    buffer: Vec<u8>,
    ended: bool,
}

pub(in crate::gateway::streaming) enum Frame {
    Message(Value),
    Eof,
}

impl CustodyBody {
    fn take_frame(&mut self) -> Option<Value> {
        loop {
            let end = self.buffer.windows(2).position(|pair| pair == b"\n\n")?;
            let block: Vec<u8> = self.buffer.drain(..end + 2).collect();
            let text = String::from_utf8(block)
                .unwrap_or_else(|error| panic!("VOID: custody frame must be UTF-8: {error}"));
            let data: Vec<&str> = text
                .lines()
                .filter_map(|line| line.strip_prefix("data: "))
                .collect();
            if data.is_empty() {
                continue;
            }
            let payload = data.join("\n");
            return Some(serde_json::from_str(&payload).unwrap_or_else(|error| {
                panic!("VOID: custody frame must be JSON ({error}): {payload}")
            }));
        }
    }

    pub(in crate::gateway::streaming) async fn next(&mut self) -> Frame {
        let deadline = tokio::time::Instant::now() + WITHIN;
        loop {
            if let Some(message) = self.take_frame() {
                return Frame::Message(message);
            }
            if self.ended {
                std::assert!(
                    self.buffer.is_empty(),
                    "VOID: custody EOF carried an unterminated partial frame"
                );
                return Frame::Eof;
            }
            match tokio::time::timeout_at(deadline, self.body.next()).await {
                Err(elapsed) => {
                    panic!("VOID: custody stream timed out after {WITHIN:?}: {elapsed}")
                }
                Ok(None) => self.ended = true,
                Ok(Some(Ok(chunk))) => self.buffer.extend_from_slice(&chunk),
                Ok(Some(Err(error))) => panic!("VOID: custody body failed: {error}"),
            }
        }
    }

    pub(in crate::gateway::streaming) async fn expect_connected(&mut self) {
        match self.next().await {
            Frame::Message(frame) => std::assert!(
                frame["session_id"]
                    .as_str()
                    .is_some_and(|id| !id.is_empty()),
                "VOID: first custody frame is not connected: {frame}"
            ),
            Frame::Eof => panic!("VOID: custody stream ended before connected"),
        }
    }

    pub(in crate::gateway::streaming) async fn expect_hint(&mut self) {
        match self.next().await {
            Frame::Message(frame) => std::assert_eq!(
                frame["method"],
                json!("notifications/tools/list_changed"),
                "VOID: expected the judged hint: {frame}"
            ),
            Frame::Eof => panic!("VOID: custody stream ended before the hint"),
        }
    }
}

fn hint() -> TaggedNotification {
    TaggedNotification {
        source: BACKEND.to_owned(),
        event_type: "message".to_owned(),
        data: json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
        event_id: None,
    }
}

/// Cohesive real custody fixture. Holds no strong subject, view, raw
/// receipt, or closure capturing one.
pub(in crate::gateway::streaming) struct CustodyFixture {
    mux: Arc<NotificationMultiplexer>,
    session_id: String,
    judge: Arc<CfJudge>,
    primary: Attachment,
    _bare: tokio::sync::broadcast::Receiver<crate::gateway::streaming::SessionFrame>,
}

impl CustodyFixture {
    pub(in crate::gateway::streaming) async fn attach(
        subject: ViewSubject,
        verifier: OidcVerifier,
    ) -> (Self, StreamView) {
        let authorizer = custody_auth("custody-key");
        let credential = held("custody-key");
        let caller = current_caller(&authorizer, Some(&credential))
            .await
            .unwrap_or_else(|| panic!("VOID: custody bearer must resolve before attach"));
        std::assert!(
            caller.client.authenticated && !caller.client.principal.is_empty(),
            "VOID: custody bearer did not authenticate"
        );
        let owner = crate::gateway::session_id::SessionOwner::Credential(
            caller.client.principal.storage_form().to_owned(),
        );
        let mux = Arc::new(NotificationMultiplexer::new(
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::StreamingConfig::default(),
        ));
        mux.set_authorizer(authorizer);
        let (session_id, bare) = mux.get_or_create_session_scoped(None, &owner, Some(credential));
        let judge = CfJudge::new(verifier);
        let fixture = Self {
            mux,
            session_id,
            judge,
            primary: Attachment {
                witnesses: Vec::new(),
                receipt_fp: String::new(),
                grace: Weak::new(),
                record: Arc::new(ViewRecord::default()),
                key: String::new(),
            },
            _bare: bare,
        };
        let (view, primary) = fixture.attach_subject(subject).await;
        let mut fixture = fixture;
        fixture.primary = primary;
        fixture.primary.assert_witnesses_live_cf();
        (fixture, view)
    }

    pub(in crate::gateway::streaming) async fn attach_more(
        &self,
        subject: ViewSubject,
    ) -> (StreamView, Attachment) {
        let (view, attachment) = self.attach_subject(subject).await;
        attachment.assert_witnesses_live_cf();
        (view, attachment)
    }

    async fn attach_subject(&self, subject: ViewSubject) -> (StreamView, Attachment) {
        let key = subject.key();
        let fp = receipt_fp(&subject);
        let grace = Arc::downgrade(&subject.cf_grace);
        let view = match self
            .mux
            .attach_view(
                &self.session_id,
                subject,
                Arc::clone(&self.judge) as Arc<dyn ViewJudge>,
            )
            .await
        {
            Ok(Some(view)) => view,
            Ok(None) => panic!("VOID: custody attach produced no view"),
            Err(reason) => panic!("VOID: custody attach refused: {reason:?}"),
        };
        let mut witnesses = vec![Arc::downgrade(&view.subject)];
        {
            let sessions = self.mux.sessions.read();
            let session = sessions
                .get(self.session_id.as_str())
                .unwrap_or_else(|| panic!("VOID: custody session vanished"));
            for entry in session.records.read().iter() {
                if entry.key != key {
                    continue;
                }
                for active in &entry.active {
                    let weak = active.subject_weak();
                    let matching = weak
                        .upgrade()
                        .is_some_and(|upgraded| receipt_fp(&upgraded) == fp);
                    if matching {
                        witnesses.push(weak);
                    }
                }
            }
        }
        let attachment = Attachment {
            witnesses,
            receipt_fp: fp,
            grace,
            record: Arc::clone(&view.record),
            key,
        };
        (view, attachment)
    }

    pub(in crate::gateway::streaming) fn body(&self, view: StreamView) -> CustodyBody {
        let response = create_sse_response_with_view(
            Arc::clone(&self.mux),
            self.session_id.clone(),
            (None, Duration::from_secs(3600)),
            Some(view),
        )
        .unwrap_or_else(|| panic!("VOID: custody SSE response was not built"))
        .into_response();
        CustodyBody {
            body: response.into_body().into_data_stream(),
            buffer: Vec::new(),
            ended: false,
        }
    }

    pub(in crate::gateway::streaming) fn set_verifier(&self, verifier: OidcVerifier) {
        *self.judge.verifier.write() = Arc::new(verifier);
    }

    pub(in crate::gateway::streaming) fn set_digest(&self, served: &str, shown: &str) {
        *self.judge.digest.lock() = ViewDigest {
            served: served.to_owned(),
            shown: shown.to_owned(),
        };
    }

    pub(in crate::gateway::streaming) fn resolves(&self) -> usize {
        self.judge.resolves.load(Ordering::SeqCst)
    }

    pub(in crate::gateway::streaming) fn completed_verifications(&self) -> usize {
        self.judge.completed_verifications.load(Ordering::SeqCst)
    }

    pub(in crate::gateway::streaming) async fn broadcast(&self) -> usize {
        self.mux
            .broadcast_to_backend_judged(&hint(), BACKEND, &*self.judge)
            .await
    }

    pub(in crate::gateway::streaming) fn primary(&self) -> &Attachment {
        &self.primary
    }

    fn revoke_bearer(&self) {
        self.mux.set_authorizer(custody_auth("revoked-other-key"));
    }

    fn queue_any_frame(&self) {
        let note = TaggedNotification {
            source: BACKEND.to_owned(),
            event_type: "message".to_owned(),
            data: json!({"jsonrpc": "2.0", "method": "notifications/message"}),
            event_id: None,
        };
        std::assert!(
            self.mux.send_to_session(&self.session_id, note),
            "VOID: the Any frame was not queued"
        );
    }

    fn assert_session_retained(&self) {
        let sessions = self.mux.sessions.read();
        let session = sessions
            .get(self.session_id.as_str())
            .unwrap_or_else(|| panic!("VOID: custody session was removed"));
        std::assert!(
            session.credential.read().is_some(),
            "VOID: custody credential was cleared"
        );
        let retained = session.records.read().iter().any(|entry| {
            entry.key == self.primary.key
                && Arc::as_ptr(&entry.record) == Arc::as_ptr(&self.primary.record)
        });
        std::assert!(retained, "VOID: custody record was not retained");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_polled_cf_stream_drops_all_raw_subject_owners_on_body_drop() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let (subject, verifier) = admit(&harness).await;
    let (fixture, view) = CustodyFixture::attach(subject, verifier).await;
    let mut body = fixture.body(view);
    body.expect_connected().await;
    drop(body);
    fixture.assert_session_retained();
    std::assert!(
        fixture.primary().all_owners_dead(),
        "a polled CF stream must drop every raw subject owner"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn an_unpolled_cf_stream_drops_all_raw_subject_owners_on_body_drop() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let (subject, verifier) = admit(&harness).await;
    let (fixture, view) = CustodyFixture::attach(subject, verifier).await;
    let body = fixture.body(view);
    drop(body);
    fixture.assert_session_retained();
    std::assert!(
        fixture.primary().all_owners_dead(),
        "an unpolled CF stream must drop every raw subject owner"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn an_ended_cf_stream_releases_custody_with_body_allocation_retained() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let (subject, verifier) = admit(&harness).await;
    let (fixture, view) = CustodyFixture::attach(subject, verifier).await;
    let mut body = fixture.body(view);
    body.expect_connected().await;
    fixture.revoke_bearer();
    fixture.queue_any_frame();
    match body.next().await {
        Frame::Eof => {}
        Frame::Message(frame) => {
            panic!("VOID: revoked custody stream wrote a frame instead of ending: {frame}")
        }
    }
    fixture.assert_session_retained();
    std::assert!(
        fixture.primary().all_owners_dead(),
        "an ended CF stream must release custody while its body is retained"
    );
    drop(body);
}

#[tokio::test(flavor = "current_thread")]
async fn same_key_cf_streams_keep_independent_custody_and_history() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let (first_subject, verifier) = admit(&harness).await;
    let (fixture, first_view) = CustodyFixture::attach(first_subject, verifier).await;
    let (second_subject, second_verifier) = admit(&harness).await;
    std::assert_eq!(
        second_subject.key(),
        fixture.primary().key,
        "VOID: independently signed receipts must share the subject key"
    );
    let (second_view, second) = fixture.attach_more(second_subject).await;
    std::assert_ne!(
        fixture.primary().receipt_fp,
        second.receipt_fp,
        "VOID: same-key streams must hold distinct signed receipts"
    );
    std::assert!(
        !Weak::ptr_eq(&fixture.primary().grace, &second.grace),
        "VOID: same-key streams must hold distinct grace state"
    );
    std::assert!(
        Arc::ptr_eq(&fixture.primary().record, &second.record),
        "VOID: same-key streams must share the durable record"
    );
    grace_history_challenge(&first_view.subject, &second_view.subject, &second_verifier).await;
    let mut first_body = fixture.body(first_view);
    first_body.expect_connected().await;
    let mut second_body = fixture.body(second_view);
    second_body.expect_connected().await;
    drop(first_body);
    std::assert!(
        fixture.primary().all_owners_dead(),
        "closing the first same-key stream must drop its own raw owners"
    );
    second.assert_original_live();
    let resolves_before = fixture.resolves();
    fixture.set_digest("s1", "x2");
    std::assert_eq!(
        fixture.broadcast().await,
        1,
        "VOID: surviving same-key stream was not reached"
    );
    second_body.expect_hint().await;
    std::assert!(
        fixture.resolves() > resolves_before,
        "VOID: surviving stream did not genuinely re-verify"
    );
    drop(second_body);
    std::assert!(
        second.all_owners_dead(),
        "closing the second same-key stream must drop its own raw owners"
    );
    fixture.assert_session_retained();
}

#[tokio::test(flavor = "current_thread")]
async fn a_resumed_cf_stream_uses_only_its_new_receipt_and_grace() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let t0 = crate::clock::unix_secs()
        .unwrap_or_else(|_| panic!("VOID: custody clock must read after the epoch"));
    let held_at_t0 = crate::clock::test_clock::at_secs(t0);
    let (subject, verifier) = admit(&harness).await;
    let (fixture, view) = CustodyFixture::attach(subject, verifier).await;
    let mut body = fixture.body(view);
    body.expect_connected().await;
    fixture.set_digest("s1", "x2");
    std::assert_eq!(
        fixture.broadcast().await,
        1,
        "VOID: initial stream was not reached"
    );
    body.expect_hint().await;
    drop(held_at_t0);
    let _past = crate::clock::test_clock::at_secs(t0 + 361);
    {
        let good =
            OidcVerifier::with_http_client(harness.ks.config.oidc.clone(), reqwest::Client::new());
        let upgraded = fixture
            .primary()
            .witnesses
            .first()
            .unwrap_or_else(|| panic!("VOID: custody witness set is empty"))
            .upgrade()
            .unwrap_or_else(|| panic!("VOID: the original subject died before its stream closed"));
        let HeldSource::Cloudflare(receipt) = &upgraded.identity_source else {
            panic!("VOID: custody subject holds no Cloudflare receipt");
        };
        std::assert!(
            !receipt.live(),
            "VOID: the original receipt must be expired at t0 + 361"
        );
        let age = crate::config::KeyServerOidcConfig {
            token_age: crate::key_server::TokenAgeCap::ExpOnly,
        };
        match good.verify(receipt.expose(), &age).await {
            Err(OidcError::JwtError(_)) => {}
            Err(error) => {
                panic!("VOID: good verifier expected a JwtError refusal, got: {error}")
            }
            Ok(_) => panic!("VOID: good verifier accepted the expired original receipt"),
        }
    }
    drop(body);
    std::assert!(
        fixture.primary().all_owners_dead(),
        "closing the expired original stream must drop every old raw subject owner"
    );
    fixture.assert_session_retained();
    let (new_subject, _verifier) = admit(&harness).await;
    std::assert_eq!(
        new_subject.key(),
        fixture.primary().key,
        "VOID: resumed receipt must keep the subject key"
    );
    let (new_view, resumed) = fixture.attach_more(new_subject).await;
    std::assert_ne!(
        fixture.primary().receipt_fp,
        resumed.receipt_fp,
        "a resumed stream must use a newly signed receipt, not borrow the old one"
    );
    std::assert!(
        !Weak::ptr_eq(&fixture.primary().grace, &resumed.grace),
        "a resumed stream must use fresh grace state"
    );
    std::assert!(
        Arc::ptr_eq(&fixture.primary().record, &resumed.record),
        "VOID: resumed stream lost the durable record"
    );
    let mut resumed_body = fixture.body(new_view);
    resumed_body.expect_connected().await;
    std::assert_eq!(
        fixture.broadcast().await,
        0,
        "VOID: resumed stream was re-told history it already held"
    );
    fixture.set_digest("s2", "x3");
    std::assert_eq!(
        fixture.broadcast().await,
        1,
        "VOID: resumed stream was not reached after a real move"
    );
    resumed_body.expect_hint().await;
    drop(resumed_body);
    std::assert!(
        resumed.all_owners_dead(),
        "closing the resumed CF stream must drop every new raw subject owner"
    );
    fixture.assert_session_retained();
}

#[path = "streaming_told_cold_history_tests.rs"]
mod cold_history_tests;

#[path = "streaming_told_close_race_tests.rs"]
mod close_race_tests;
