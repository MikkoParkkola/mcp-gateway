// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Lease custody at the store: install and replace, the per-subscriber cap,
//! wipe and drain, races between a replace and an expiry, and the refusal
//! without the core-dump guard.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use super::{LeaseKey, LeaseRefusal, LeaseState, LeaseStore, MAX_LEASE_TTL_SECS, WipeReason};
use crate::security::dump_guard::DumpGuard;
use crate::transport::upstream_tap::CredentialedSend;

const FAR: u64 = u64::MAX / 2;

fn now() -> u64 {
    crate::clock::unix_secs().expect("clock")
}

fn jwt(claims: &str) -> Zeroizing<String> {
    let part = |s: &str| URL_SAFE_NO_PAD.encode(s);
    Zeroizing::new(format!(
        "Bearer {}.{}.sig",
        part(r#"{"alg":"RS256"}"#),
        part(claims)
    ))
}

fn token_until(exp: u64) -> Zeroizing<String> {
    jwt(&format!(r#"{{"sub":"p","exp":{exp}}}"#))
}

fn key(obs: &str) -> LeaseKey {
    LeaseKey {
        backend: "b".into(),
        obs: obs.into(),
    }
}

fn store() -> LeaseStore {
    LeaseStore::with_guard(|| DumpGuard::Applied)
}

fn ok_response() -> reqwest::Response {
    reqwest::Response::from(
        axum::http::Response::builder()
            .status(200)
            .body(Vec::new())
            .expect("fixture response builds"),
    )
}

/// A send that records the headers it was given and how often it ran.
fn recording(
    seen: Arc<std::sync::Mutex<Vec<String>>>,
    calls: Arc<AtomicUsize>,
) -> CredentialedSend<'static> {
    Box::new(move |headers| {
        calls.fetch_add(1, Ordering::SeqCst);
        seen.lock()
            .unwrap()
            .extend(headers.iter().map(|(_, v)| v.clone()));
        Box::pin(async { Ok(ok_response()) })
    })
}

#[tokio::test]
async fn lease_t1_a_token_without_a_numeric_exp_is_refused() {
    let s = store();
    for token in [
        Zeroizing::new("opaque-token".to_string()),
        jwt(r#"{"sub":"p"}"#),
        jwt(r#"{"sub":"p","exp":"soon"}"#),
        jwt(r#"{"sub":"p","exp":-5}"#),
    ] {
        assert_eq!(
            s.install(key("p"), token, FAR, 0).await,
            Err(LeaseRefusal::NoExpiry)
        );
    }
    assert_eq!(s.state(&key("p")).await, LeaseState::CredentialNeeded);
}

#[tokio::test]
async fn an_expired_or_too_short_token_is_refused() {
    let s = store();
    assert_eq!(
        s.install(key("p"), token_until(now() - 10), FAR, 0).await,
        Err(LeaseRefusal::Expired)
    );
    assert_eq!(
        s.install(key("p"), token_until(now() + 30), FAR, 60).await,
        Err(LeaseRefusal::Expired),
        "less than the minimum left"
    );
    assert_eq!(
        s.install(key("p"), token_until(now() + 3600), now() + 30, 60)
            .await,
        Err(LeaseRefusal::Expired),
        "the subscription ends first"
    );
}

#[tokio::test]
async fn lease_t10_no_lease_without_the_core_dump_guard() {
    for (guard, detail) in [
        (
            (|| DumpGuard::Failed("setrlimit_core")) as fn() -> DumpGuard,
            "setrlimit_core",
        ),
        (|| DumpGuard::Failed("prctl_dumpable"), "prctl_dumpable"),
        (|| DumpGuard::Unsupported, "platform_unsupported"),
    ] {
        let s = LeaseStore::with_guard(guard);
        let refusal = s
            .install(key("p"), token_until(now() + 3600), FAR, 0)
            .await
            .expect_err("guard not applied");
        assert_eq!(refusal, LeaseRefusal::CoreDumpGuard(detail));
        assert_eq!(
            refusal.reason(),
            ("core_dump_guard_unavailable", Some(detail))
        );
    }
}

#[tokio::test]
async fn c3_a_lease_is_capped_at_twelve_hours() {
    let s = store();
    s.install(key("p"), token_until(FAR), FAR, 0).await.unwrap();
    let LeaseState::Active { expires_at } = s.state(&key("p")).await else {
        panic!("lease held");
    };
    assert!(expires_at <= now() + MAX_LEASE_TTL_SECS);
}

#[tokio::test]
async fn a_current_lease_sends_its_own_token_only() {
    let s = store();
    let p_token = token_until(now() + 3600);
    let p_text = p_token.to_string();
    let pg = s.install(key("p"), p_token, FAR, 0).await.unwrap();
    let q_token = jwt(&format!(r#"{{"sub":"q","exp":{}}}"#, now() + 3600));
    let q_text = q_token.to_string();
    s.install(key("q"), q_token, FAR, 0).await.unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls = Arc::new(AtomicUsize::new(0));
    s.with_credential(&key("p"), pg, recording(seen.clone(), calls.clone()))
        .await
        .unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(seen[0] == p_text, "P's lease sends P's token");
    assert!(seen[0] != q_text, "never Q's token");
}

#[tokio::test]
async fn lease_t3_after_a_wipe_no_send_runs() {
    let s = store();
    let g = s
        .install(key("p"), token_until(now() + 3600), FAR, 0)
        .await
        .unwrap();
    s.wipe(&key("p"), WipeReason::Released).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    assert!(
        s.with_credential(&key("p"), g, recording(seen, calls.clone()))
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(s.state(&key("p")).await, LeaseState::CredentialNeeded);
}

#[tokio::test]
async fn lease_t4_a_rejection_wipes_and_marks_rejected() {
    let s = store();
    let g = s
        .install(key("p"), token_until(now() + 3600), FAR, 0)
        .await
        .unwrap();
    s.on_rejection(&key("p"), g).await;
    assert_eq!(s.generation(&key("p")).await, None);
    assert_eq!(s.state(&key("p")).await, LeaseState::CredentialRejected);
}

#[tokio::test]
async fn e5_a_stale_rejection_leaves_the_newer_lease() {
    let s = store();
    let old = s
        .install(key("p"), token_until(now() + 3600), FAR, 0)
        .await
        .unwrap();
    let new = s
        .install(key("p"), token_until(now() + 7200), FAR, 0)
        .await
        .unwrap();
    assert_ne!(old, new, "a replace gets a fresh generation");
    s.on_rejection(&key("p"), old).await;
    assert_eq!(s.generation(&key("p")).await, Some(new));
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    assert!(
        s.with_credential(&key("p"), old, recording(seen, calls.clone()))
            .await
            .is_err(),
        "the old generation cannot send"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// E5, replace racing replace: B replaces the original while its drain is
/// held open, and C queues behind B on the store lock (tokio's mutex is
/// fair, so C runs after B). The last replace wins, exactly one lease is
/// held, and B's generation can no longer send.
#[tokio::test]
async fn e5_a_replace_racing_a_replace_leaves_the_last_one() {
    let s = Arc::new(store());
    s.install(key("p"), token_until(now() + 3600), FAR, 0)
        .await
        .unwrap();
    let (token, old_cancel) = {
        let held = s.held.lock().await;
        let h = held.get(&key("p")).expect("held");
        (Arc::clone(&h.token), h.cancel.clone())
    };
    let in_flight = token.read_owned().await;
    let replace = |exp: u64| {
        let s = s.clone();
        tokio::spawn(async move { s.install(key("p"), token_until(exp), FAR, 0).await })
    };
    let b = replace(now() + 7200);
    let mut turns = 0;
    while !old_cancel.is_cancelled() {
        assert!(turns < 10_000, "B never reached the drain");
        turns += 1;
        tokio::task::yield_now().await;
    }
    let c = replace(now() + 9000);
    tokio::task::yield_now().await;
    assert!(!b.is_finished() && !c.is_finished(), "premise: both wait");
    drop(in_flight);
    let b = b.await.unwrap().unwrap();
    let c = c.await.unwrap().unwrap();
    assert_ne!(b, c, "two replaces, two generations");
    assert_eq!(
        s.held_generation(&key("p")),
        Some(c),
        "the last replace wins"
    );
    assert_eq!(s.held.lock().await.len(), 1, "exactly one lease");
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    assert!(
        s.with_credential(&key("p"), b, recording(seen, calls.clone()))
            .await
            .is_err(),
        "B's generation is refused"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "and never sends");
}

/// D1: a wipe cancels a send that is still in flight, waits for it to let
/// go of the token, and only then completes.
#[tokio::test]
async fn d1_a_wipe_cancels_and_drains_an_in_flight_send() {
    let s = Arc::new(store());
    let g = s
        .install(key("p"), token_until(now() + 3600), FAR, 0)
        .await
        .unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
    let send: CredentialedSend<'static> = Box::new(move |_headers| {
        Box::pin(async move {
            let _ = started_tx.send(());
            std::future::pending::<crate::Result<reqwest::Response>>().await
        })
    });
    let in_flight = {
        let s = s.clone();
        tokio::spawn(async move { s.with_credential(&key("p"), g, send).await })
    };
    started_rx.await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        s.wipe(&key("p"), WipeReason::Released),
    )
    .await
    .expect("the wipe drains instead of deadlocking");
    assert!(in_flight.await.unwrap().is_err(), "the send was cancelled");
    assert_eq!(s.generation(&key("p")).await, None);
}

/// LEASE-T7, bump order (design §3.5): a replace bumps the generation before
/// it drains the old lease's sends, so while they drain a record observed
/// under the old generation no longer reads as live, and no new delivery
/// handoff for it can begin. The drain is held open by holding the old
/// token's read guard, as an in-flight send not yet polled since its cancel.
#[tokio::test]
async fn lease_t7_a_replace_bumps_the_generation_before_it_drains() {
    let s = Arc::new(store());
    let old = s
        .install(key("p"), token_until(now() + 3600), FAR, 0)
        .await
        .unwrap();
    let (token, old_cancel) = {
        let held = s.held.lock().await;
        let h = held.get(&key("p")).expect("held");
        (Arc::clone(&h.token), h.cancel.clone())
    };
    let in_flight = token.read_owned().await;
    let replace = {
        let s = s.clone();
        tokio::spawn(async move { s.install(key("p"), token_until(now() + 7200), FAR, 0).await })
    };
    // The replace has fired the old cancel and now waits on the drain.
    let mut turns = 0;
    while !old_cancel.is_cancelled() {
        assert!(turns < 10_000, "the replace never reached the drain");
        turns += 1;
        tokio::task::yield_now().await;
    }
    assert!(!replace.is_finished(), "premise: the drain is held open");
    // Between the old lease and the new no lease is held, so a delivery
    // check and a listener start both fail closed (credential needed).
    assert_eq!(
        s.held_generation(&key("p")),
        None,
        "while the old lease drains, no generation reads as live"
    );
    assert!(!s.is_held(&key("p")), "no lease is held in the window");
    // A send that asks in the window waits out the drain, then is refused:
    // it neither runs nor hangs.
    let calls = Arc::new(AtomicUsize::new(0));
    let late = {
        let (s, calls) = (s.clone(), calls.clone());
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        tokio::spawn(async move {
            s.with_credential(&key("p"), old, recording(seen, calls))
                .await
        })
    };
    drop(in_flight);
    let new = replace.await.unwrap().unwrap();
    assert_eq!(s.held_generation(&key("p")), Some(new));
    assert!(
        late.await.unwrap().is_err(),
        "the old generation is refused"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "and never sends");
}

/// LEASE-T7 for a wipe: `wipe_by` wipes the lease of generation `g` while a
/// send still holds its token, and the generation must already be retired,
/// so no new handoff begins under a lease that is being wiped.
async fn retired_before_the_drain(
    wipe_by: impl FnOnce(Arc<LeaseStore>, u128) -> tokio::task::JoinHandle<()>,
) {
    let s = Arc::new(store());
    let old = s
        .install(key("p"), token_until(now() + 3600), FAR, 0)
        .await
        .unwrap();
    let (token, old_cancel) = {
        let held = s.held.lock().await;
        let h = held.get(&key("p")).expect("held");
        (Arc::clone(&h.token), h.cancel.clone())
    };
    let in_flight = token.read_owned().await;
    let wiping = wipe_by(s.clone(), old);
    let mut turns = 0;
    while !old_cancel.is_cancelled() {
        assert!(turns < 10_000, "the wipe never reached the drain");
        turns += 1;
        tokio::task::yield_now().await;
    }
    assert!(!wiping.is_finished(), "premise: the drain is held open");
    assert_ne!(
        s.held_generation(&key("p")),
        Some(old),
        "while the lease drains, its generation no longer reads as live"
    );
    drop(in_flight);
    wiping.await.unwrap();
    assert_eq!(s.held_generation(&key("p")), None);
}

/// Revocation, the last row gone or a config change.
#[tokio::test]
async fn lease_t7_a_wipe_retires_the_generation_before_it_drains() {
    retired_before_the_drain(|s, _| {
        tokio::spawn(async move { s.wipe(&key("p"), WipeReason::Released).await })
    })
    .await;
}

/// A backend that refused the token.
#[tokio::test]
async fn lease_t7_a_rejection_retires_the_generation_before_it_drains() {
    retired_before_the_drain(|s, g| {
        tokio::spawn(async move { s.on_rejection(&key("p"), g).await })
    })
    .await;
}

/// A lease past its deadline.
#[tokio::test]
async fn lease_t7_an_expiry_retires_the_generation_before_it_drains() {
    retired_before_the_drain(|s, _| tokio::spawn(async move { s.wipe_expired(u64::MAX).await }))
        .await;
}

#[test]
fn the_store_debug_shows_no_lease() {
    let rendered = format!("{:?}", store());
    assert_eq!(rendered, "LeaseStore { .. }");
}

/// E5 replace plus expiry: an expiry seen by a send of the old generation,
/// arriving after a replace, leaves the new lease alone.
#[tokio::test]
async fn e5_a_stale_expiry_leaves_the_newer_lease() {
    let s = store();
    let old = s
        .install(key("p"), token_until(now() + 3600), FAR, 0)
        .await
        .unwrap();
    let new = s
        .install(key("p"), token_until(now() + 7200), FAR, 0)
        .await
        .unwrap();
    s.wipe_generation(&key("p"), old, WipeReason::Released)
        .await;
    assert_eq!(s.generation(&key("p")).await, Some(new));
    assert!(matches!(
        s.state(&key("p")).await,
        LeaseState::Active { .. }
    ));
}

/// LEASE-T6 / L3 source scan: the lease code holds a token and nothing else
/// may: no `Serialize` derive, no `Clone` on a type that holds it, and no log
/// macro or `format!` anywhere a token is in scope. The derives the module
/// keeps are named here, so a new one fails until it is judged.
#[test]
fn lease_t6_the_lease_code_cannot_write_or_log_a_token() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/events");
    for file in ["lease.rs", "lease_rpc.rs"] {
        let text = std::fs::read_to_string(dir.join(file)).expect("read");
        // Code only: a doc comment may say what the code never does.
        let source: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for banned in [
            "Serialize",
            "tracing::",
            "debug!",
            "info!",
            "warn!",
            "error!",
            "trace!",
            "println!",
            "eprintln!",
            "format!",
        ] {
            assert!(!source.contains(banned), "{file} uses {banned}");
        }
        let derives: Vec<&str> = source
            .lines()
            .filter(|l| l.trim_start().starts_with("#[derive("))
            .map(str::trim)
            .collect();
        let allowed = [
            // LeaseKey, LeaseState, LeaseRefusal, WipeReason: no token in them.
            "#[derive(Debug, Clone, PartialEq, Eq, Hash)]",
            "#[derive(Debug, Clone, Copy, PartialEq, Eq)]",
        ];
        for derive in derives {
            assert!(allowed.contains(&derive), "{file}: {derive}");
        }
    }
}

/// The token is zeroized at its deadline with no send asking for it, and the
/// sweep then drops the expired entry.
#[tokio::test(start_paused = true)]
async fn an_unused_lease_is_zeroized_at_its_deadline() {
    let s = store();
    s.install(key("p"), token_until(now() + 3600), now() + 120, 60)
        .await
        .unwrap();
    let token = {
        let held = s.held.lock().await;
        Arc::clone(&held.get(&key("p")).expect("held").token)
    };
    assert!(token.read().await.is_some());
    tokio::time::sleep(std::time::Duration::from_secs(121)).await;
    tokio::task::yield_now().await;
    assert!(token.read().await.is_none(), "zeroized at the deadline");
    s.wipe_expired(now() + 121).await;
    assert_eq!(s.generation(&key("p")).await, None);
    assert!(!s.is_held(&key("p")));
}

/// LEASE-T3 at the deadline: a lease past it holds no generation at once,
/// before any expiry sweep, so delivery refuses its records and its
/// listener's session ends at its next check.
#[tokio::test]
async fn an_expired_lease_holds_no_generation_before_the_sweep() {
    let s = store();
    let exp = now() + 3600;
    let g = s.install(key("p"), token_until(exp), FAR, 0).await.unwrap();
    {
        let _clock = crate::clock::test_clock::at_secs(exp - 1);
        assert_eq!(s.held_generation(&key("p")), Some(g), "a second before");
    }
    let _clock = crate::clock::test_clock::at_secs(exp);
    assert_eq!(
        s.held_generation(&key("p")),
        None,
        "at the deadline, before any sweep"
    );
    assert!(
        s.held.lock().await.contains_key(&key("p")),
        "premise: no sweep ran"
    );
}

/// A replace whose call is dropped during the drain leaves no lease: neither
/// the old generation nor the new one reads as held, and the rows ask for a
/// credential again.
#[tokio::test]
async fn a_replace_dropped_during_the_drain_leaves_no_lease() {
    let s = Arc::new(store());
    s.install(key("p"), token_until(now() + 3600), FAR, 0)
        .await
        .unwrap();
    let (token, old_cancel) = {
        let held = s.held.lock().await;
        let h = held.get(&key("p")).expect("held");
        (Arc::clone(&h.token), h.cancel.clone())
    };
    let in_flight = token.read_owned().await;
    let replace = {
        let s = s.clone();
        tokio::spawn(async move { s.install(key("p"), token_until(now() + 7200), FAR, 0).await })
    };
    let mut turns = 0;
    while !old_cancel.is_cancelled() {
        assert!(turns < 10_000, "the replace never reached the drain");
        turns += 1;
        tokio::task::yield_now().await;
    }
    replace.abort();
    assert!(
        replace.await.is_err_and(|e| e.is_cancelled()),
        "premise: dropped mid-drain"
    );
    drop(in_flight);
    assert_eq!(s.held_generation(&key("p")), None);
    assert!(
        !s.held.lock().await.contains_key(&key("p")),
        "no lease was installed"
    );
    assert_eq!(s.state(&key("p")).await, LeaseState::CredentialNeeded);
}

/// A lease lends a non-empty `Authorization` or nothing: an empty token is
/// never installed, and with no current lease of the generation the send
/// never runs. A per-user slot of a required binding takes a lease-lent send
/// as the subscriber's own, so this source is where "never lend empty" is
/// held.
#[tokio::test]
async fn a_lease_lends_a_credential_or_nothing() {
    let s = store();
    assert_eq!(
        s.install(key("p"), Zeroizing::new(String::new()), FAR, 0)
            .await,
        Err(LeaseRefusal::NoExpiry),
        "an empty token is never leased"
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    assert!(
        s.with_credential(&key("p"), 7, recording(seen.clone(), calls.clone()))
            .await
            .is_err(),
        "no lease: refused"
    );
    let g = s
        .install(key("p"), token_until(now() + 3600), FAR, 0)
        .await
        .unwrap();
    assert!(
        s.with_credential(&key("p"), g ^ 1, recording(seen.clone(), calls.clone()))
            .await
            .is_err(),
        "another generation: refused"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a refused lend ran its send"
    );
    s.with_credential(&key("p"), g, recording(seen.clone(), calls.clone()))
        .await
        .unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(!seen[0].is_empty(), "a lent credential is never empty");
}
