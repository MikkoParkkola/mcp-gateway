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
    backend.remember_listed_tools(None, false, &[]);
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

/// Review fold: a failed stale refresh that starts no fill cooldown (`Io`),
/// then a discovery fill that succeeds: once that list is stale, the next
/// stale hit refreshes again. Mutant M43 (a stored fill keeps the refresh
/// stamp) holds it off the wire.
#[tokio::test]
async fn a4_t4_a_stored_fill_ends_the_refresh_hold_off() {
    let lister = Lister::new(Mode::Serve);
    let backend = short_ttl(&lister);
    let _ = check(&backend, "edit", &json!({"edits": []})).await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    lister.set(Mode::Io);
    let _ = check(&backend, "edit", &undeclared()).await;
    lister.set(Mode::Serve);
    let fill = backend.get_tools_for_binding(None, &[]).await;
    fill.expect("the discovery fill succeeds");
    let before = lister.lists();
    tokio::time::sleep(Duration::from_millis(80)).await;
    let _ = check(&backend, "edit", &undeclared()).await;
    assert_eq!(lister.lists(), before + 1, "the stale hit did not refresh");
}

/// Review fold: a stale refresh that fails after a direct list replaced the
/// slot judges the call from that newer list, not the stale clone: a tool it
/// dropped is text A. Mutant M52 (judge the clone) reddens it.
#[tokio::test]
async fn a4_t5_a_failed_refresh_judges_a_newer_list() {
    let lister = Lister::new(Mode::Serve);
    let backend = short_ttl(&lister);
    let _ = check(&backend, "edit", &json!({"edits": []})).await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    lister.set(Mode::Barrier);
    // The TTL runs on the wall clock; from here the refresh's hour-long page
    // times out on tokio's, paused so it auto-advances.
    tokio::time::pause();
    let other = json!({"name": "other", "inputSchema": {"type": "object"}});
    let args = undeclared();
    let (out, ()) = tokio::join!(check(&backend, "edit", &args), async {
        lister.started.notified().await;
        backend.remember_listed_tools(None, false, &[other]);
        *lister.sleep_per_page.lock() = Duration::from_secs(3600);
        lister.release.notify_one();
    });
    let text = super::super::fill_check::text_absent("edit");
    assert_eq!(
        out.expect("a result"),
        Some(text),
        "judged from the stale clone"
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
/// the cooldown that list ended: the slot holds a value when the voided guard
/// drops. Mutant M33 (stamp whatever the slot holds) reddens it.
#[tokio::test]
async fn a3_t12_a_fill_voided_by_a_direct_list_stamps_nothing() {
    let lister = Lister::new(Mode::Serve);
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    let entry = backend.shared_entry();
    let mut guard = super::super::fill_check::FillGuard::arm(Arc::clone(&entry));
    backend.remember_listed_tools(None, false, &[]);
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
    let entry = backend.shared_entry();
    *entry.tools_refresh_failed_at.lock() = Some(tokio::time::Instant::now());
    backend.remember_listed_tools(None, false, &[]);
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
            backend.remember_listed_tools(None, false, &[newer]);
            lister.release.notify_one();
        });
        out
    });
    assert!(
        matches!(out, Ok(None)),
        "judged from the superseded list: {out:?}"
    );
}

/// Delta-review fold: a newer direct list that no longer carries the tool
/// makes a voided fill's call a complete-list miss (text A), not a judgement
/// against the superseded schema. Mutant M36 reddens it too.
#[test]
fn a3_t15_a_newer_list_without_the_tool_is_a_miss() {
    let (out, _) = metered(true, async {
        let lister = Lister::new(Mode::Barrier);
        let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
        let other = json!({"name": "other", "inputSchema": {"type": "object"}});
        let arguments = json!({"edits": []});
        let (out, ()) = tokio::join!(check(&backend, "edit", &arguments), async {
            lister.started.notified().await;
            backend.remember_listed_tools(None, false, &[other]);
            lister.release.notify_one();
        });
        out
    });
    let text = super::super::fill_check::text_absent("edit");
    assert_eq!(
        out.expect("a result"),
        Some(text),
        "judged from the superseded list"
    );
}

/// Review fold: a discovery fill voided by a direct list must not restore a
/// resend permission that list revoked. Mutant M50 (publish the fill's set
/// before its store) reddens it.
#[tokio::test]
async fn a_voided_fill_does_not_restore_a_revoked_resend() {
    let lister = Lister::new(Mode::Barrier);
    let safe = json!({"name": "edit", "inputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": true}});
    *lister.pages.lock() = vec![(vec![safe], None)];
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    let unsafe_now = json!({"name": "edit", "inputSchema": {"type": "object"}});
    let (fill, ()) = tokio::join!(backend.get_tools_for_binding(None, &[]), async {
        lister.started.notified().await;
        backend.remember_listed_tools(None, false, &[unsafe_now]);
        lister.release.notify_one();
    });
    let _ = fill;
    assert!(
        !backend.resend_permitted_snapshot().contains("edit"),
        "the voided fill restored the resend"
    );
}

/// Review fold: a protocol-version rejection is replayed from the cooldown,
/// variant and versions intact, instead of listing again. Mutant M51 (leave
/// it unreplayable) reddens it.
#[tokio::test(start_paused = true)]
async fn a3_t16_a_version_rejection_is_replayed_from_the_cooldown() {
    let lister = Lister::new(Mode::Version);
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    for _ in 0..2 {
        let answer = check(&backend, "edit", &undeclared()).await;
        assert!(
            matches!(answer, Err(crate::Error::ProtocolVersionRejected { ref supported })
                if supported == &["2025-06-18"]),
            "{answer:?}"
        );
        tokio::time::advance(Duration::from_millis(10)).await;
    }
    assert_eq!(lister.lists(), 1, "the second call listed again");
}

/// H1 (MIK-8361 ORACLE.2, codex review of #3872): with the shared slot stale
/// and its refresh cooling after a transport failure, a withheld listed name
/// and a missing name are answered alike under `closed`. The withheld name
/// must not be answered from the stale list while the missing one meets the
/// failed fill.
#[tokio::test]
async fn h1_a_cooling_stale_slot_answers_withheld_and_missing_alike() {
    use crate::backend::Lens;
    let lister = Lister::new(Mode::Serve);
    // A zero TTL: the slot is stale from its first fill (`elapsed() < ttl`
    // never holds), so no wall-clock wait is needed.
    let backend = Arc::new(Backend::new(
        "f13",
        BackendConfig::default(),
        &no_breaker(),
        Duration::ZERO,
    ));
    backend.set_transport_for_test(Arc::clone(&lister) as Arc<dyn crate::transport::Transport>);
    let _ = check(&backend, "edit", &json!({"edits": []})).await;
    lister.set(Mode::Down);
    // A stale hit whose refresh fails starts the cooldown (A4-T2's premise).
    let _ = check(&backend, "edit", &json!({"edits": []})).await;
    let lists = lister.lists();
    let answer = |tool: &'static str, lens: Lens| {
        let backend = Arc::clone(&backend);
        async move {
            let answered = backend
                .catalogue_refusal(
                    (None, crate::transport::LentCredential::default()),
                    tool,
                    &json!({}),
                    lens,
                )
                .await;
            format!("{answered:?}").replace(tool, "<tool>")
        }
    };
    let withheld = answer("edit", Lens::Withheld).await;
    let missing = answer("not_listed", Lens::Catalogue).await;
    // Anchored: both forwarded (`Ok(None)`) would be equal too.
    assert!(
        missing.contains("TransportConnect(\"list down\")"),
        "the shared answer is the failed refill's: {missing}"
    );
    assert_eq!(
        withheld, missing,
        "a withheld name and a missing one answer alike on a cooling stale slot"
    );
    assert_eq!(
        lister.lists(),
        lists,
        "no list went out inside the cooldown"
    );
}

/// A `tools/list` upstream that answers the marked busy error (or the same
/// variant unmarked), so the fill's breaker and cooldown treatment is pinned
/// without a lease or a token exchange (MIK-8619 T13f).
struct BusyLister {
    lists: AtomicUsize,
    marked: bool,
}

#[async_trait]
impl crate::transport::Transport for BusyLister {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        if method != "tools/list" {
            return Ok(JsonRpcResponse::success(RequestId::Number(1), json!({})));
        }
        self.lists.fetch_add(1, Ordering::SeqCst);
        tokio::task::yield_now().await;
        Err(if self.marked {
            crate::oauth::client::busy_error_for_test("the token step holds the lease")
        } else {
            crate::Error::BackendUnavailable("x".to_string())
        })
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

/// A `Closed` backend on the `Shared` slot with `failsafe`, wired to `lister`.
fn busy_backend(failsafe: &FailsafeConfig, lister: Arc<BusyLister>) -> Arc<Backend> {
    let config = BackendConfig {
        input_schema_enforcement: InputSchemaEnforcement::Closed,
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "f13",
        config,
        failsafe,
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(lister as Arc<dyn crate::transport::Transport>);
    backend
}

/// T13f: a tools fill whose `tools/list` answers the marked busy error takes
/// no breaker sample and stamps no cooldown (`FillEnd::Pending`, like an
/// authorization wait). One failure is seeded first, so a wrong success sample
/// (a reset to zero) fails as well as a sampled failure. An unmarked
/// `BackendUnavailable` still samples and stamps, so a blanket skip of the
/// variant fails. RED now: `record_fill` samples and `FillEnd::of` stamps.
#[tokio::test(start_paused = true)]
async fn t13f_fill_over_a_busy_lock_takes_no_sample_and_no_cooldown() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut failsafe = hair_trigger(Duration::from_secs(3600));
        failsafe.circuit_breaker.failure_threshold = 5;
        // Marked: no sample, no cooldown.
        let marked_lister = Arc::new(BusyLister {
            lists: AtomicUsize::new(0),
            marked: true,
        });
        let marked_backend = busy_backend(&failsafe, Arc::clone(&marked_lister));
        // A seeded failure: the count must stay put, so a reset fails too.
        marked_backend
            .shared_entry()
            .failsafe
            .circuit_breaker
            .record_failure("seed", Duration::ZERO);
        let before = marked_backend.circuit_breaker_stats().current_failures;
        assert_eq!(before, 1, "the seed did not land: {before}");
        let first = check(&marked_backend, "edit", &undeclared()).await;
        let Err(marked_error) = first else {
            panic!("no tools cross a busy lock");
        };
        assert!(
            crate::oauth::client::is_credential_lock_busy(&marked_error),
            "not the marked error: {marked_error}"
        );
        assert!(
            matches!(marked_error, crate::Error::BackendUnavailable(_)),
            "not the variant: {marked_error:?}"
        );
        assert_eq!(
            marked_backend.circuit_breaker_stats().current_failures,
            before,
            "a busy lock sampled as a backend failure"
        );
        assert!(
            !marked_backend.is_circuit_tripped(),
            "the fill tripped the breaker on a busy lock"
        );
        let marked_fresh =
            crate::oauth::client::busy_error_for_test("the token step holds the lease");
        let marked_end = super::super::fill_check::FillEnd::of::<()>(&Err(marked_fresh));
        assert!(
            matches!(&marked_end, super::super::fill_check::FillEnd::Pending),
            "a busy lock stamped the cooldown: {marked_end:?}"
        );
        tokio::time::advance(Duration::from_millis(10)).await;
        let second = check(&marked_backend, "edit", &undeclared()).await;
        assert!(
            matches!(second, Err(crate::Error::BackendUnavailable(_))),
            "not the busy error again: {second:?}"
        );
        assert_eq!(
            marked_lister.lists.load(Ordering::SeqCst),
            2,
            "the second call fast-failed inside a cooldown"
        );

        // Unmarked control: the same variant without the marker still samples
        // and stamps.
        let plain_lister = Arc::new(BusyLister {
            lists: AtomicUsize::new(0),
            marked: false,
        });
        let plain_backend = busy_backend(&failsafe, Arc::clone(&plain_lister));
        let before = plain_backend.circuit_breaker_stats().current_failures;
        let first = check(&plain_backend, "edit", &undeclared()).await;
        let Err(plain_error) = first else {
            panic!("no tools cross a failed list");
        };
        assert!(
            !crate::oauth::client::is_credential_lock_busy(&plain_error),
            "an unmarked error reads busy: {plain_error}"
        );
        assert!(
            plain_backend.circuit_breaker_stats().current_failures > before,
            "an unmarked failure was not sampled"
        );
        let plain_fresh = crate::Error::BackendUnavailable("x".to_string());
        let plain_end = super::super::fill_check::FillEnd::of::<()>(&Err(plain_fresh));
        assert!(
            !matches!(&plain_end, super::super::fill_check::FillEnd::Pending),
            "an unmarked failure stamped nothing: {plain_end:?}"
        );
        tokio::time::advance(Duration::from_millis(10)).await;
        let second = check(&plain_backend, "edit", &undeclared()).await;
        assert!(
            matches!(second, Err(crate::Error::BackendUnavailable(_))),
            "not the replayed failure: {second:?}"
        );
        assert_eq!(
            plain_lister.lists.load(Ordering::SeqCst),
            1,
            "the second call listed again inside the cooldown"
        );

        the_busy_predicate_needs_the_colon();
    })
    .await
    .expect("both fills answer at once");
}

fn the_busy_predicate_needs_the_colon() {
    // The predicate needs the colon: a message starting with the marker
    // text but without it is not busy. RED now: the `BackendUnavailable`
    // arm matches the bare prefix.
    let near = crate::Error::BackendUnavailable("credential lock busy without a colon".to_string());
    assert!(
        !crate::oauth::client::is_credential_lock_busy(&near),
        "a colonless marker reads busy: {near}"
    );
    let positive = crate::oauth::client::busy_error_for_test("the token step holds the lease");
    assert!(
        crate::oauth::client::is_credential_lock_busy(&positive),
        "the marked error does not read busy: {positive}"
    );
}
