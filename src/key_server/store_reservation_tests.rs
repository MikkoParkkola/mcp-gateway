// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The mint's reservation protocol: a token counts against its identity's
//! cap from reservation, becomes valid only at activation, and a mint that
//! ends early gives its slot back.

use std::sync::Arc;

use super::{MintReservation, issue};
use crate::key_server::oidc::VerifiedIdentity;
use crate::key_server::store::{
    ActivateError, InMemoryTokenStore, ReservationId, ReservationRequest, ReserveError,
    TemporaryToken, TokenScopes, TokenStore,
};

const ISS: &str = "https://issuer.invalid";
const OTHER_ISS: &str = "https://other.invalid";
const SUB: &str = "sub";
const T0: u64 = 1_800_000_000;
const TTL: u64 = 3600;
/// The pending window, pinned here rather than read from the store.
const WINDOW: u64 = 30;

fn identity(issuer: &str, subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.to_string(),
        email: "u@corp.invalid".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: issuer.to_string(),
    }
}

fn request(issuer: &str, jti: &str) -> ReservationRequest {
    ReservationRequest {
        issuer: issuer.to_string(),
        subject: SUB.to_string(),
        jti: jti.to_string(),
    }
}

/// The token a reservation for `jti` activates into at `now`.
fn token(issuer: &str, jti: &str, now: u64) -> TemporaryToken {
    TemporaryToken {
        jti: jti.to_string(),
        token: format!("mcpgw_{jti}"),
        identity: identity(issuer, SUB),
        scopes: TokenScopes::default(),
        iat: now,
        exp: now + TTL,
        client_ip: None,
    }
}

fn store(cap: usize) -> Arc<InMemoryTokenStore> {
    Arc::new(InMemoryTokenStore::new(cap, TTL))
}

/// Whether the store would take one more reservation for `issuer` at `now`
/// (the probe's own slot is given back).
fn has_room(store: &InMemoryTokenStore, issuer: &str, now: u64) -> bool {
    match store.reserve(request(issuer, "probe"), now) {
        Ok(id) => {
            store.abort(&id);
            true
        }
        Err(ReserveError::CapReached) => false,
        Err(other) => panic!("probe refused for another reason: {other:?}"),
    }
}

/// Active plus pending never passes the cap; the excess is refused, nothing
/// is evicted; a pending token is invisible to bearer lookup and JTI
/// liveness; the same subject under another issuer has its own cap.
/// Mutant: count only active tokens in the reservation check.
#[tokio::test]
async fn pending_slots_count_against_the_cap_and_stay_invisible() {
    const CAP: usize = 2;
    let s = store(CAP);
    let first = s.reserve(request(ISS, "j1"), T0).expect("first slot");
    s.activate(&first, token(ISS, "j1", T0), T0).expect("activates");
    let pending = s.reserve(request(ISS, "j2"), T0).expect("second slot");
    for extra in ["j3", "j4", "j5"] {
        assert_eq!(
            s.reserve(request(ISS, extra), T0),
            Err(ReserveError::CapReached),
            "{extra}: active + pending fill the cap"
        );
    }
    assert!(s.get("mcpgw_j1").await.is_some(), "the active token was not evicted");
    assert!(s.get("mcpgw_j2").await.is_none(), "a pending bearer is not valid");
    assert!(!s.live_jti("j2", T0).await, "a pending JTI is not live");
    let other = s.reserve(request(OTHER_ISS, "k1"), T0).expect("another issuer's own cap");
    s.abort(&other);
    s.abort(&pending);
    assert!(has_room(&s, ISS, T0), "the aborted slot came back");
}

/// A pending slot past its window is reclaimed by the next reservation,
/// with no background reaper; the stale owner's activation is refused.
/// Mutant: reap only in the background task.
#[tokio::test]
async fn an_expired_pending_slot_is_reclaimed_by_the_cap_check() {
    let s = store(1);
    let stale = s.reserve(request(ISS, "j1"), T0).expect("slot");
    assert!(!has_room(&s, ISS, T0 + WINDOW - 1), "still pending inside the window");
    let fresh = s.reserve(request(ISS, "j2"), T0 + WINDOW).expect("the expired slot was reclaimed");
    assert_eq!(
        s.activate(&stale, token(ISS, "j1", T0 + WINDOW), T0 + WINDOW),
        Err(ActivateError::Expired)
    );
    s.activate(&fresh, token(ISS, "j2", T0 + WINDOW), T0 + WINDOW).expect("the new owner activates");
}

/// The deadline is `now` + the pending window (not the token lifetime); a
/// token whose `iat`/`exp` are not `now`/`now` + TTL is refused and the slot
/// released; an id the store never handed out activates nothing.
/// Mutant: derive the deadline from the token TTL.
#[tokio::test]
async fn reserve_and_activate_hold_the_store_contract() {
    let s = store(1);
    let id = s.reserve(request(ISS, "j1"), T0).expect("slot");
    assert_eq!(
        s.activate(&id, token(ISS, "j1", T0 + WINDOW), T0 + WINDOW),
        Err(ActivateError::Expired),
        "the deadline is now + {WINDOW} s"
    );
    let id = s.reserve(request(ISS, "j2"), T0).expect("slot");
    s.activate(&id, token(ISS, "j2", T0 + WINDOW - 1), T0 + WINDOW - 1)
        .expect("activates one second before the deadline");
    assert!(s.revoke_by_jti("j2").await);

    for (label, mut bad) in [
        ("iat", token(ISS, "j3", T0)),
        ("exp", token(ISS, "j3", T0)),
        ("jti", token(ISS, "j3", T0)),
        ("issuer", token(OTHER_ISS, "j3", T0)),
    ] {
        match label {
            "iat" => bad.iat = T0 - 1,
            "exp" => bad.exp = T0 + TTL + 1,
            "jti" => bad.jti = "other".to_string(),
            _ => {}
        }
        let id = s.reserve(request(ISS, "j3"), T0).expect("slot");
        let refusal = s.activate(&id, bad, T0).expect_err(label);
        assert!(
            matches!(refusal, ActivateError::Timestamps | ActivateError::Mismatch),
            "{label}: {refusal:?}"
        );
        assert!(has_room(&s, ISS, T0), "{label}: the refused slot was released");
    }
    assert_eq!(
        s.activate(&ReservationId::from_raw(u64::MAX), token(ISS, "j4", T0), T0),
        Err(ActivateError::Missing)
    );
    assert!(s.get("mcpgw_j4").await.is_none());
}

/// A guard dropped before activation gives its slot back once; after
/// activation neither the guard nor a later abort touches the active token.
/// Mutant: release the slot in Drop even after activation.
#[tokio::test]
async fn the_mint_guard_releases_only_an_unactivated_slot() {
    let s = store(1);
    let dyn_store: Arc<dyn TokenStore> = s.clone();
    let guard = MintReservation::reserve(&dyn_store, request(ISS, "j1"), T0).expect("slot");
    assert!(!has_room(&s, ISS, T0));
    drop(guard);
    assert!(has_room(&s, ISS, T0), "Drop released the pending slot");

    let guard = MintReservation::reserve(&dyn_store, request(ISS, "j2"), T0).expect("slot");
    let raw = ReservationId::from_raw(guard.id.raw());
    guard.activate(token(ISS, "j2", T0), T0).expect("activates");
    s.abort(&raw);
    assert!(s.get("mcpgw_j2").await.is_some(), "a later abort left the active token");
    assert!(!has_room(&s, ISS, T0), "the active token still holds the slot");
}

/// The store, recording when `reserve` has returned.
struct Watched {
    inner: Arc<InMemoryTokenStore>,
    reserved: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl TokenStore for Watched {
    fn reserve(&self, request: ReservationRequest, now: u64) -> Result<ReservationId, ReserveError> {
        let id = self.inner.reserve(request, now);
        self.reserved.store(true, std::sync::atomic::Ordering::SeqCst);
        id
    }
    fn activate(&self, id: &ReservationId, token: TemporaryToken, now: u64) -> Result<(), ActivateError> {
        self.inner.activate(id, token, now)
    }
    fn abort(&self, id: &ReservationId) {
        self.inner.abort(id);
    }
    async fn get(&self, bearer: &str) -> Option<TemporaryToken> {
        self.inner.get(bearer).await
    }
    async fn live_jti(&self, jti: &str, now: u64) -> bool {
        self.inner.live_jti(jti, now).await
    }
    async fn revoke_by_jti(&self, jti: &str) -> bool {
        self.inner.revoke_by_jti(jti).await
    }
    async fn revoke_by_subject(&self, issuer: &str, subject: &str) -> usize {
        self.inner.revoke_by_subject(issuer, subject).await
    }
    async fn count_for_subject(&self, issuer: &str, subject: &str) -> usize {
        self.inner.count_for_subject(issuer, subject).await
    }
    async fn reap_expired(&self) -> usize {
        self.inner.reap_expired().await
    }
}

fn key_server(store: Arc<dyn TokenStore>) -> crate::key_server::KeyServer {
    let mut ks = crate::key_server::KeyServer::new(
        crate::config::KeyServerConfig::default(),
        crate::key_server::email_hash::EmailHashKey::for_test(),
    );
    assert_eq!(ks.config.token_ttl_secs, TTL, "the store's lifetime is the config's");
    ks.store = store;
    ks
}

/// A mint dropped at its first pending poll after `reserve` returned leaks
/// no slot: the guard owns the id before the mint can yield. The row polls
/// by hand and adds no await of its own.
/// Mutant: a yield between `reserve` and the guard.
#[test]
fn a_mint_cancelled_right_after_reserve_leaks_no_slot() {
    use std::future::Future;
    let inner = store(1);
    let watched = Arc::new(Watched {
        inner: inner.clone(),
        reserved: std::sync::atomic::AtomicBool::new(false),
    });
    let ks = key_server(watched.clone());
    let mut mint = Box::pin(issue(&ks, identity(ISS, SUB), TokenScopes::default(), None));
    let waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let finished = loop {
        match mint.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(response) => break Some(response),
            std::task::Poll::Pending if watched.reserved.load(std::sync::atomic::Ordering::SeqCst) => {
                break None;
            }
            std::task::Poll::Pending => {}
        }
    };
    drop(mint);
    assert!(watched.reserved.load(std::sync::atomic::Ordering::SeqCst), "the mint reserved");
    #[allow(clippy::disallowed_methods, reason = "the store's reads use the host clock")]
    let now = crate::clock::unix_secs().expect("a readable clock");
    match finished {
        Some(response) => {
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            assert!(!has_room(&inner, ISS, now), "the finished mint's token holds the slot");
        }
        None => assert!(has_room(&inner, ISS, now), "the cancelled mint's slot came back"),
    }
}

/// Revoking a pending reservation by JTI counts as a revocation; again, it
/// is gone; bulk revocation counts active and pending; an active token is
/// still revocable.
/// Mutant: omit pending slots from the bulk count.
#[tokio::test]
async fn revocation_reaches_pending_reservations() {
    let s = store(3);
    let _pending = s.reserve(request(ISS, "j1"), T0).expect("slot");
    assert!(s.revoke_by_jti("j1").await, "a pending JTI is revoked");
    assert!(!s.revoke_by_jti("j1").await, "a second revoke finds nothing");

    let active = s.reserve(request(ISS, "j2"), T0).expect("slot");
    s.activate(&active, token(ISS, "j2", T0), T0).expect("activates");
    let pending = s.reserve(request(ISS, "j3"), T0).expect("slot");
    assert_eq!(s.revoke_by_subject(ISS, SUB).await, 2, "one active + one pending");
    assert_eq!(s.revoke_by_subject(ISS, SUB).await, 0, "nothing left");
    assert!(s.get("mcpgw_j2").await.is_none());
    assert_eq!(
        s.activate(&pending, token(ISS, "j3", T0), T0),
        Err(ActivateError::Revoked)
    );
}

/// What happens to a reservation between `reserve` and `activate`.
#[derive(Clone, Copy)]
enum Meddle {
    /// Nothing: record the activation's `now` and token.
    None,
    /// The identity is revoked before activation.
    Revoke,
    /// The slot is reserved a full window early, so it expires on arrival.
    Stale,
}

/// The store, interfering with each mint as `meddle` says.
struct Meddling {
    inner: Watched,
    meddle: Meddle,
    activated: std::sync::Mutex<Option<(u64, u64, u64)>>,
}

#[async_trait::async_trait]
impl TokenStore for Meddling {
    fn reserve(&self, request: ReservationRequest, now: u64) -> Result<ReservationId, ReserveError> {
        let now = match self.meddle {
            Meddle::Stale => now - WINDOW,
            _ => now,
        };
        self.inner.reserve(request, now)
    }
    fn activate(&self, id: &ReservationId, token: TemporaryToken, now: u64) -> Result<(), ActivateError> {
        if let Meddle::Revoke = self.meddle {
            let revoked = futures::executor::block_on(
                self.inner.revoke_by_subject(token.identity.issuer(), token.identity.subject()),
            );
            assert_eq!(revoked, 1, "the pending mint was revoked");
        }
        *self.activated.lock().expect("unpoisoned") = Some((now, token.iat, token.exp));
        self.inner.activate(id, token, now)
    }
    fn abort(&self, id: &ReservationId) {
        self.inner.abort(id);
    }
    async fn get(&self, bearer: &str) -> Option<TemporaryToken> {
        self.inner.get(bearer).await
    }
    async fn live_jti(&self, jti: &str, now: u64) -> bool {
        self.inner.live_jti(jti, now).await
    }
    async fn revoke_by_jti(&self, jti: &str) -> bool {
        self.inner.revoke_by_jti(jti).await
    }
    async fn revoke_by_subject(&self, issuer: &str, subject: &str) -> usize {
        self.inner.revoke_by_subject(issuer, subject).await
    }
    async fn count_for_subject(&self, issuer: &str, subject: &str) -> usize {
        self.inner.count_for_subject(issuer, subject).await
    }
    async fn reap_expired(&self) -> usize {
        self.inner.reap_expired().await
    }
}

fn meddling(meddle: Meddle) -> (Arc<Meddling>, crate::key_server::KeyServer) {
    let store = Arc::new(Meddling {
        inner: Watched {
            inner: store(5),
            reserved: std::sync::atomic::AtomicBool::new(false),
        },
        meddle,
        activated: std::sync::Mutex::new(None),
    });
    let ks = key_server(store.clone());
    (store, ks)
}

async fn body(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 16).await.expect("body");
    serde_json::from_slice(&bytes).expect("a JSON body")
}

/// Revoked mid-mint answers 403; a pending deadline passed answers 503 with
/// Retry-After 1; neither returns a bearer or leaves a token.
/// Mutant: answer 500 for both.
#[tokio::test]
async fn a_mint_whose_reservation_is_lost_answers_why() {
    for (meddle, status) in [(Meddle::Revoke, 403), (Meddle::Stale, 503)] {
        let (store, ks) = meddling(meddle);
        let response = issue(&ks, identity(ISS, SUB), TokenScopes::default(), None).await;
        assert_eq!(response.status().as_u16(), status);
        let retry = response.headers().get(axum::http::header::RETRY_AFTER).cloned();
        assert_eq!(retry.as_ref().map(|v| v.to_str().expect("ascii")), (status == 503).then_some("1"));
        let body = body(response).await;
        assert!(body.get("access_token").is_none(), "{status}: no bearer: {body}");
        assert_eq!(store.count_for_subject(ISS, SUB).await, 0, "{status}: no token stored");
    }
}

/// The handler passes its one activation clock read to `activate` and
/// builds `expires_in` from it, though the clock ticks on every read.
/// Mutant: read the clock again inside activation.
#[tokio::test]
async fn activation_uses_the_handlers_own_clock_read() {
    let (store, ks) = meddling(Meddle::None);
    let reads: Vec<Option<u64>> = (0..16).map(|i| Some(T0 + i)).collect();
    let response = {
        let _clock = crate::clock::test_clock::queued(&reads);
        issue(&ks, identity(ISS, SUB), TokenScopes::default(), None).await
    };
    assert_eq!(response.status().as_u16(), 200);
    let (now, iat, exp) = store.activated.lock().expect("unpoisoned").expect("activated");
    assert!(now > T0, "activation read the clock after the reservation did");
    assert_eq!((iat, exp), (now, now + TTL), "the token is dated by that read");
    let body = body(response).await;
    assert_eq!(body["expires_in"], serde_json::json!(exp - now));
}

/// A mint whose activation comes well after its reservation dates the
/// token from the activation read, never the reservation read.
/// Mutant: set `iat` at reservation time.
#[tokio::test]
async fn a_delayed_activation_dates_the_token_fresh() {
    const DELAY: u64 = 20;
    let (store, ks) = meddling(Meddle::None);
    let mut reads = vec![Some(T0)];
    reads.extend(std::iter::repeat_n(Some(T0 + DELAY), 15));
    let response = {
        let _clock = crate::clock::test_clock::queued(&reads);
        issue(&ks, identity(ISS, SUB), TokenScopes::default(), None).await
    };
    assert_eq!(response.status().as_u16(), 200);
    let activated = *store.activated.lock().expect("unpoisoned");
    assert_eq!(activated, Some((T0 + DELAY, T0 + DELAY, T0 + DELAY + TTL)));
    assert_eq!(body(response).await["expires_in"], serde_json::json!(TTL));
}

/// Over the routes: a pending mint revoked by JTI answers 204 with exactly
/// one signal from this key server; again, 404 and none; the bulk count is
/// active plus pending, with one signal; an empty bulk sends none.
/// Mutant: no signal for a pending-only JTI revoke.
#[tokio::test]
async fn revoking_pending_mints_over_the_routes_signals_once() {
    use crate::key_server::oidc_test_harness::{Harness, ISS_A, config_yaml};
    use std::sync::atomic::Ordering::SeqCst;
    let h = Harness::start(&config_yaml("[]", "")).await;
    let signals = || h.ks.revocation_signals.load(SeqCst);
    #[allow(clippy::disallowed_methods, reason = "the store's reads use the host clock")]
    let now = crate::clock::unix_secs().expect("a readable clock");

    let _pending = h.ks.store.reserve(request(ISS_A, "j1"), now).expect("slot");
    assert_eq!(h.revoke_jti("j1").await, 204);
    assert_eq!(signals(), 1, "one signal for the pending JTI");
    assert_eq!(h.revoke_jti("j1").await, 404);
    assert_eq!(signals(), 1, "no signal for a JTI already gone");

    let active = h.ks.store.reserve(request(ISS_A, "j2"), now).expect("slot");
    h.ks.store.activate(&active, token(ISS_A, "j2", now), now).expect("activates");
    let _pending = h.ks.store.reserve(request(ISS_A, "j3"), now).expect("slot");
    let issuer: String = url::form_urlencoded::byte_serialize(ISS_A.as_bytes()).collect();
    let query = format!("issuer={issuer}&subject={SUB}");
    let (status, body) = h.revoke(&query).await;
    assert_eq!((status, body["revoked"].clone()), (200, serde_json::json!(2)), "{body}");
    assert_eq!(signals(), 2, "one signal for the bulk revoke");
    let (status, body) = h.revoke(&query).await;
    assert_eq!((status, body["revoked"].clone()), (200, serde_json::json!(0)), "{body}");
    assert_eq!(signals(), 2, "no signal for an empty bulk revoke");
}
