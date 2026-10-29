// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Check-site fills judged from a voided or truncated drain: the returned list decides.

use serde_json::json;

use super::{
    Arc, Backend, BackendConfig, Duration, InputSchemaEnforcement, LIST_FILL_COOLDOWN, Lister,
    Mode, Ordering, PoolKey, TEXT_UNAVAILABLE, Voider, backend, check, kind, metered, no_breaker,
    text_partial, undeclared, voided_check,
};

/// F13-T7c: an invalidation lands while the drain is on the wire. The call is
/// judged from the list the fill returned (the key refusal, not text U); the
/// slot stays cold; `fetched` +1, `fetch_failed` +0; and the voided store
/// stamps the cooldown: a second cold call within the window sends no list
/// and gets text U, and after the window one list goes out. Red on base: no
/// fetch. Mutants M6b (re-read the slot) and M5b/M5c (no stamp on a void).
#[test]
fn f13_t7c_a_voided_store_is_judged_from_the_returned_list_and_stamps() {
    let ((first, cold, second, lists_in_window, lists_after), rendered) = metered(true, async {
        let lister = Lister::new(Mode::Barrier);
        let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
        let first = voided_check(&backend, &lister, "edit", Voider::Invalidate).await;
        let cold = backend.cached_tools_count() == 0;
        lister.set(Mode::Serve);
        let second = check(&backend, "edit", &undeclared()).await.expect("ok");
        let lists_in_window = lister.lists();
        tokio::time::advance(LIST_FILL_COOLDOWN).await;
        let _ = check(&backend, "edit", &undeclared()).await;
        (first, cold, second, lists_in_window, lister.lists())
    });
    assert!(
        first.as_deref().is_some_and(|t| t.contains("zzinvented")),
        "not judged from the returned list: {first:?}"
    );
    assert!(cold, "the voided store landed");
    assert_eq!(second, Some(TEXT_UNAVAILABLE.to_owned()));
    assert_eq!(lists_in_window, 1, "the void did not stamp the cooldown");
    assert_eq!(lists_after, 2, "no list after the cooldown");
    // One for the voided drain, one for the stored drain after the window.
    assert_eq!(kind(&rendered, "input_schema_fetched"), 2, "{rendered}");
    assert_eq!(
        kind(&rendered, "input_schema_fetch_failed"),
        0,
        "{rendered}"
    );
}

/// F13-T7d: an invented tool name, with the store voided mid-drain by an
/// invalidation or by a direct-route `replace`: `closed` refuses with text U,
/// never text A after an invalidation, because absence from a list the slot
/// does not hold proves nothing (`Completeness::Unknown`). A replacement is a
/// newer complete list, so absence from it is text A, as in the control.
/// New-API row: `Completeness` has no base counterpart. Proven by mutants
/// M6c (completeness without `ptr_eq`) and M6d (judge a void from the side
/// bit), which turn the voided arms into text A.
#[test]
fn f13_t7d_absence_from_a_voided_list_is_unavailable_not_absent() {
    for voider in [Voider::Invalidate, Voider::Replace, Voider::Nothing] {
        let (out, rendered) = metered(true, async move {
            let lister = Lister::new(Mode::Barrier);
            let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
            voided_check(&backend, &lister, "nosuch", voider).await
        });
        // A replacement is a newer complete list: absence from it is text A.
        let (text, refused, other) = match voider {
            Voider::Nothing | Voider::Replace => (
                crate::backend::fill_check::text_absent("nosuch"),
                "input_schema_refused_absent",
                "input_schema_refused_unavailable",
            ),
            Voider::Invalidate => (
                TEXT_UNAVAILABLE.to_owned(),
                "input_schema_refused_unavailable",
                "input_schema_refused_absent",
            ),
        };
        assert_eq!(out, Some(text), "{voider:?}");
        assert_eq!(kind(&rendered, refused), 1, "{voider:?}: {rendered}");
        assert_eq!(kind(&rendered, other), 0, "{voider:?}: {rendered}");
    }
}

/// Why a drain stopped early (the three `tools_truncated` causes).
#[derive(Clone, Copy, Debug)]
enum Stop {
    /// 33+ pages: the `LIST_MAX_PAGES` cap.
    PageCap,
    /// Page 2 repeats page 1's `nextCursor`.
    CursorRepeat,
    /// 10 s pages, past the 120 s `CACHE_LIST_DRAIN_BUDGET`.
    FillBudget,
}

/// A backend whose `tools/list` stops at `stop`; `edit` is never served.
/// `per_user` puts the caller on its own `PerUser` slot. The call timeout is
/// raised above the drain budget, so the budget, not the timeout, stops it.
fn truncating(
    stop: Stop,
    mode: InputSchemaEnforcement,
    per_user: bool,
) -> (Arc<Backend>, Option<&'static str>) {
    let lister = Lister::new(Mode::Serve);
    match stop {
        Stop::PageCap => lister.endless.store(true, Ordering::SeqCst),
        Stop::CursorRepeat => {
            let tool = |n: &str| json!({"name": n, "inputSchema": {"type": "object"}});
            *lister.pages.lock() = vec![
                (vec![tool("t0")], Some("c1")),
                (vec![tool("t1")], Some("c1")),
            ];
        }
        Stop::FillBudget => {
            lister.endless.store(true, Ordering::SeqCst);
            *lister.sleep_per_page.lock() = Duration::from_secs(10);
        }
    }
    let identity_propagation =
        per_user.then(|| crate::identity_propagation::IdentityPropagationConfig {
            strategy: crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
            audience: "f13".to_string(),
            required: true,
            session_mode: crate::identity_propagation::SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        });
    let config = BackendConfig {
        input_schema_enforcement: mode,
        timeout: Duration::from_secs(600),
        identity_propagation,
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "f13",
        config,
        &no_breaker(),
        Duration::from_secs(300),
    ));
    let wire = lister as Arc<dyn crate::transport::Transport>;
    if per_user {
        let binding = "alpha@f13".to_owned();
        backend.set_pooled_transport_for_test(&PoolKey::PerUser { binding }, wire);
        (backend, Some("alpha@f13"))
    } else {
        backend.set_transport_for_test(wire);
        (backend, None)
    }
}

/// F13-T10: a drain that stops structurally leaves a truncated slot, and a
/// tool not in the pages kept cannot be checked. One row per stop cause, on
/// a `Shared` slot (no credential) and on a `PerUser` slot. `closed`: text P
/// exactly as rendered from `LIST_MAX_PAGES` (no config key),
/// `input_schema_refused_truncated` +1. `standard`: forwarded,
/// `input_schema_truncated_forward` +1, `input_schema_unknown` +0. Red on
/// base: no fetch, the call is forwarded. Mutants M6 (forward truncated under
/// `closed`), M6e (hard-coded page count) and M10 (count it `unknown`).
#[test]
fn f13_t10_absence_from_a_truncated_list_is_its_own_outcome() {
    let modes = [
        InputSchemaEnforcement::Closed,
        InputSchemaEnforcement::Standard,
    ];
    for stop in [Stop::PageCap, Stop::CursorRepeat, Stop::FillBudget] {
        for per_user in [false, true] {
            for mode in modes {
                let (out, rendered) = metered(true, async move {
                    let (backend, binding) = truncating(stop, mode, per_user);
                    let headers = if per_user {
                        vec![("Authorization".to_owned(), "Bearer alpha".to_owned())]
                    } else {
                        Vec::new()
                    };
                    backend
                        .undeclared_key_refusal(
                            binding,
                            crate::transport::LentCredential::unchecked(&headers),
                            "edit",
                            &undeclared(),
                        )
                        .await
                        .expect("no failsafe refusal")
                });
                let row = format!("{stop:?} per_user={per_user} {mode:?}");
                if mode == InputSchemaEnforcement::Closed {
                    assert_eq!(out, Some(text_partial()), "{row}");
                    assert!(!text_partial().contains("input_schema_enforcement"));
                    let cap = format!("{}-page cap", crate::backend::LIST_MAX_PAGES);
                    assert!(text_partial().contains(&cap), "{row}: names another cap");
                    let refused = kind(&rendered, "input_schema_refused_truncated");
                    assert_eq!(refused, 1, "{row}: {rendered}");
                } else {
                    assert_eq!(out, None, "{row}");
                    let forwarded = kind(&rendered, "input_schema_truncated_forward");
                    assert_eq!(forwarded, 1, "{row}: {rendered}");
                    assert_eq!(kind(&rendered, "input_schema_unknown"), 0, "{row}");
                }
            }
        }
    }
}
