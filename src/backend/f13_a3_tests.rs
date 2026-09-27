// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F13 Amendment A3, backend half: under `closed`, a cold-slot fill that
//! fails on transport returns the transport error (the caller answers as a
//! failed dispatch would), and a reachable backend whose list cannot be read
//! keeps text U. The cooldown's fast-fail answers as the failure it stands in
//! for. `standard` forwards either way.

use super::*;

/// A3-T4a: a transport failure, then a cold call inside the cooldown: both
/// return the transport class, and only one list went out. New-API row (base
/// answers text U); mutants M15 (map transport to text U) and M17 (drop the
/// stamp's transport bit) redden it.
#[tokio::test(start_paused = true)]
async fn a3_t4a_a_transport_failure_and_its_cooldown_answer_as_transport() {
    let lister = Lister::new(Mode::Down);
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    let first = check(&backend, "edit", &undeclared()).await;
    assert!(
        matches!(first, Err(crate::Error::TransportConnect(_))),
        "{first:?}"
    );
    tokio::time::advance(Duration::from_millis(10)).await;
    let second = check(&backend, "edit", &undeclared()).await;
    assert!(
        matches!(second, Err(crate::Error::TransportConnect(ref m)) if m == "list down"),
        "the cooldown fast-fail must answer as the transport failure: {second:?}"
    );
    assert_eq!(lister.lists(), 1, "a list went out inside the cooldown");
}

/// A3-T3 / A3-T4b: a reachable backend whose `tools/list` answers with a
/// JSON-RPC error keeps text U, and so does its cooldown fast-fail. Mutant
/// M18 (class `JsonRpc` as transport) reddens the first call; M17 the second.
#[tokio::test(start_paused = true)]
async fn a3_t4b_an_unreadable_list_and_its_cooldown_keep_text_u() {
    let lister = Lister::new(Mode::Fail);
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    let unavailable = Some(TEXT_UNAVAILABLE.to_owned());
    for _ in 0..2 {
        let answer = check(&backend, "edit", &undeclared()).await;
        assert_eq!(answer.expect("text U is a result"), unavailable);
        tokio::time::advance(Duration::from_millis(10)).await;
    }
    assert_eq!(lister.lists(), 1);
}

/// A3-T5 (backend half): under `standard` a transport failure forwards
/// (`Ok(None)`), so the dispatch fails on its own and is charged once. Mutant:
/// dropping the `closed` condition from the A3 arm reddens it.
#[tokio::test(start_paused = true)]
async fn a3_t5_standard_forwards_a_transport_failure() {
    let lister = Lister::new(Mode::Down);
    let backend = backend(InputSchemaEnforcement::Standard, &no_breaker(), &lister);
    let answer = check(&backend, "edit", &undeclared()).await;
    assert!(matches!(answer, Ok(None)), "{answer:?}");
}

/// Review fold: under `standard`, a reachable backend whose list is unreadable
/// still gets its call. The list failure is not a breaker failure (the backend
/// answered), so a threshold-1 breaker stays closed. Mutant M22 (record every
/// fill error on the breaker) reddens it.
#[tokio::test(start_paused = true)]
async fn a3_t6_an_unreadable_list_does_not_trip_the_breaker() {
    let lister = Lister::new(Mode::Fail);
    let reset = Duration::from_secs(60);
    let backend = backend(
        InputSchemaEnforcement::Standard,
        &hair_trigger(reset),
        &lister,
    );
    let answer = check(&backend, "edit", &undeclared()).await;
    assert!(matches!(answer, Ok(None)), "{answer:?}");
    assert!(
        !backend.is_circuit_tripped(),
        "an answered list opened the breaker"
    );
}

/// Review fold: a backend that cannot be started as this caller (config or
/// OAuth) answers as the dispatch would, variant kept across the cooldown.
/// Mutant M23 (drop the start-failure variants) reddens it.
#[test]
fn a3_t7_start_failures_answer_as_the_dispatch() {
    use crate::backend::fill_check::{Replay, is_transport_failure};
    for error in [
        crate::Error::Config("profile rejected".into()),
        crate::Error::ConfigValidation("bad url".into()),
        crate::Error::OAuth("token store unavailable".into()),
    ] {
        assert!(is_transport_failure(&error), "not transport-class");
        let replay = Replay::of(&error).expect("replayed");
        let message = error.to_string();
        let kept = message.split(": ").nth(1).unwrap_or(&message);
        assert!(format!("{replay:?}").contains(kept), "{replay:?}");
    }
}

/// Review fold: a readable direct-route list ends the slot's fill cooldown, so
/// the next cold call lists again instead of fast-failing. Mutant M24 (keep
/// the stamp in `remember_listed_tools`) reddens it.
#[tokio::test(start_paused = true)]
async fn a3_t8_a_direct_list_ends_the_cooldown() {
    let lister = Lister::new(Mode::Down);
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    let _ = check(&backend, "edit", &undeclared()).await;
    // An empty readable list: stored (ending the cooldown), then discardable.
    backend.remember_listed_tools(None, false, &[]).await;
    backend.invalidate_tools_cache();
    lister.set(Mode::Serve);
    let answer = check(&backend, "edit", &undeclared()).await;
    assert!(matches!(answer, Ok(Some(_))), "{answer:?}");
    assert_eq!(
        lister.lists(),
        2,
        "the cold call fast-failed after a direct list"
    );
}

/// A `tools/list` answer with neither `result` nor `error`.
struct Bare;

#[async_trait]
impl crate::transport::Transport for Bare {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let mut bare = JsonRpcResponse::success(RequestId::Number(1), json!(null));
        bare.result = None;
        Ok(bare)
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Review fold: a result-less first page is unreadable (text U), not a
/// complete empty list (text A for every tool). Mutant M25 (restore the
/// page-0 `break`) reddens it.
#[tokio::test]
async fn a3_t9_a_resultless_first_page_is_unreadable() {
    let backend = Arc::new(Backend::new(
        "f13",
        BackendConfig::default(),
        &no_breaker(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Bare));
    let answer = check(&backend, "edit", &undeclared()).await;
    assert_eq!(
        answer.expect("text U is a result"),
        Some(TEXT_UNAVAILABLE.to_owned())
    );
}

/// Review fold: an error whose source cannot be cloned (here `Io`) stamps no
/// cooldown, so the next call lists again and gets the backend's own error,
/// not a lookalike with another code or text. Mutant M27 (stamp it as
/// `Transport`) reddens it.
#[tokio::test(start_paused = true)]
async fn a3_t10_an_unreplayable_failure_is_not_replayed() {
    let lister = Lister::new(Mode::Io);
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    for _ in 0..2 {
        let answer = check(&backend, "edit", &undeclared()).await;
        assert!(
            matches!(answer, Err(crate::Error::Io(_))),
            "not the original error"
        );
        tokio::time::advance(Duration::from_millis(10)).await;
    }
    assert_eq!(
        lister.lists(),
        2,
        "the second call was answered from a cooldown"
    );
}

/// A backend on the `Shared` slot with a 50 ms cache TTL (A4 cells).
fn short_ttl(lister: &Arc<Lister>) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        "f13",
        BackendConfig::default(),
        &no_breaker(),
        Duration::from_millis(50),
    ));
    backend.set_transport_for_test(Arc::clone(lister) as Arc<dyn crate::transport::Transport>);
    backend
}

/// A4-T1: a hit on a stale slot refreshes once, so a key the backend added
/// after the first fill is accepted. Mutant M28 (judge stale hits from the
/// cache) keeps refusing it.
#[tokio::test]
async fn a4_t1_a_stale_hit_refreshes_once() {
    let lister = Lister::new(Mode::Serve);
    let backend = short_ttl(&lister);
    let first = check(&backend, "edit", &json!({"edits": []})).await;
    assert!(matches!(first, Ok(None)), "{first:?}");
    let v2 = json!({"type": "object", "properties": {"edits": {"type": "array"}, "note": {}}});
    *lister.pages.lock() = vec![(vec![json!({"name": "edit", "inputSchema": v2})], None)];
    tokio::time::sleep(Duration::from_millis(80)).await;
    let added = check(&backend, "edit", &json!({"edits": [], "note": 1})).await;
    assert!(
        matches!(added, Ok(None)),
        "the added key was judged stale: {added:?}"
    );
    assert_eq!(lister.lists(), 2, "a stale hit must refresh exactly once");
}

/// A4-T2: when the stale hit's refresh fails, the call is judged from the held
/// schema (design E), and a second stale hit within the cooldown does not
/// list. Mutant M29 (propagate the refresh error) reddens it.
#[tokio::test]
async fn a4_t2_a_failed_refresh_falls_back_to_the_held_schema() {
    let lister = Lister::new(Mode::Serve);
    let backend = short_ttl(&lister);
    let _ = check(&backend, "edit", &json!({"edits": []})).await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    lister.set(Mode::Down);
    for _ in 0..2 {
        let held = check(&backend, "edit", &undeclared()).await;
        assert!(
            matches!(held, Ok(Some(ref t)) if t.contains("zzinvented")),
            "{held:?}"
        );
    }
    assert_eq!(
        lister.lists(),
        2,
        "the second stale hit listed inside the cooldown"
    );
}

/// A4-T3 (review fold): concurrent stale hits whose refresh fails with an
/// error that starts no fill cooldown (`Io`) still list once: waiters inside
/// the fill honour the stale-refresh stamp at admission. Mutant M30 (drop that
/// admission check) sends one list per waiter.
#[tokio::test]
async fn a4_t3_concurrent_stale_hits_refresh_once() {
    let lister = Lister::new(Mode::Serve);
    let backend = short_ttl(&lister);
    let _ = check(&backend, "edit", &json!({"edits": []})).await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    lister.set(Mode::Io);
    let args = undeclared();
    let calls = (0..8).map(|_| check(&backend, "edit", &args));
    for held in futures::future::join_all(calls).await {
        assert!(
            matches!(held, Ok(Some(ref t)) if t.contains("zzinvented")),
            "{held:?}"
        );
    }
    assert_eq!(lister.lists(), 2, "each waiter retried the failed refresh");
}

/// Review fold: a handshake failure (`Protocol`, e.g. `initialize` refused)
/// answers as the dispatch would, and its cooldown replays it as is. Mutant
/// M35 (drop `Protocol` from the transport class) reddens it.
#[tokio::test(start_paused = true)]
async fn a3_t11_a_handshake_failure_answers_as_the_dispatch() {
    let lister = Lister::new(Mode::Handshake);
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    for _ in 0..2 {
        let answer = check(&backend, "edit", &undeclared()).await;
        assert!(
            matches!(answer, Err(crate::Error::Protocol(ref m)) if m == "initialize refused"),
            "{answer:?}"
        );
        tokio::time::advance(Duration::from_millis(10)).await;
    }
    assert_eq!(
        lister.lists(),
        1,
        "the second call was not answered from the cooldown"
    );
}

/// Review fold: a fill voided by a newer direct-route list does not restart
/// the cooldown that list ended. Mutant M33 (ignore the direct-list epoch)
/// reddens it.
#[tokio::test]
async fn a3_t12_a_fill_voided_by_a_direct_list_stamps_nothing() {
    let lister = Lister::new(Mode::Serve);
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    let entry = backend.pooled_entry(&PoolKey::Shared);
    let mut guard = super::super::fill_check::FillGuard::arm(Arc::clone(&entry));
    backend.remember_listed_tools(None, false, &[]).await;
    guard.end(super::super::fill_check::FillEnd::Drained);
    drop(guard);
    assert!(
        entry.tools_fill_failed_at.lock().is_none(),
        "the cooldown was restarted"
    );
}

/// Review fold: a readable direct-route list also ends a stale-refresh
/// cooldown (A4). Mutant M34 (keep that stamp) reddens it.
#[tokio::test]
async fn a3_t13_a_direct_list_ends_the_stale_refresh_cooldown() {
    let lister = Lister::new(Mode::Serve);
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    let entry = backend.pooled_entry(&PoolKey::Shared);
    *entry.tools_refresh_failed_at.lock() = Some(tokio::time::Instant::now());
    backend.remember_listed_tools(None, false, &[]).await;
    assert!(
        entry.tools_refresh_failed_at.lock().is_none(),
        "the stale-refresh stamp survived"
    );
}

/// Review fold: a fill voided by a newer direct-route list is judged from
/// that newer list, not the superseded one. Here the newer schema declares
/// the key the fill's list lacks, so the call is forwarded. Mutant M36 (judge
/// from the superseded list) refuses it.
#[test]
fn a3_t14_a_fill_voided_by_a_newer_list_is_judged_from_it() {
    let (out, _) = metered(true, async {
        let lister = Lister::new(Mode::Barrier);
        let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
        let newer = json!({"name": "edit", "inputSchema": {"type": "object",
            "properties": {"edits": {"type": "array"}, "zzinvented": {}}}});
        let arguments = undeclared();
        let (out, ()) = tokio::join!(check(&backend, "edit", &arguments), async {
            lister.started.notified().await;
            backend.remember_listed_tools(None, false, &[newer]).await;
            lister.release.notify_one();
        });
        out
    });
    assert!(
        matches!(out, Ok(None)),
        "judged from the superseded list: {out:?}"
    );
}
