// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F13 cells on a cold slot: a per-user slot refuses after one list on both
//! routes, a shared slot with no credential lists once, and a failed fetch
//! answers per mode (moved from `f13_fetch_on_miss_tests.rs`).

use super::*;

/// T1/T2 body: alpha's `PerUser` slot is cold, `closed`, nested invented key.
async fn cold_per_user_refuses(route: Route) {
    let gw = per_user(&["alpha"]).await;
    let (_, body) = call(&gw.router, route, "edit", &nested_invented(), Some("alpha")).await;
    let alpha = &gw.slots[0];
    assert!(
        refused_with(&body, "edits[0].type"),
        "{route:?}: forwarded instead of refused: {body}"
    );
    assert_eq!(
        alpha.lists(),
        1,
        "{route:?}: alpha's slot was not listed once"
    );
    assert_eq!(
        alpha.calls() + gw.shared.calls(),
        0,
        "{route:?}: the backend saw the call"
    );
}

/// F13-T1: cold `PerUser` slot on the Meta-MCP route (`gateway_invoke`):
/// refused after one `tools/list`, zero `tools/call`. Red on base: the check
/// counts `input_schema_unknown` and forwards, and no list is sent.
#[tokio::test]
async fn f13_t1_cold_per_user_meta_refuses_after_one_list() {
    cold_per_user_refuses(Route::Meta).await;
}

/// F13-T2: T1 on the direct `/mcp/edits` route. Red on base: forwarded
/// unchecked, no list sent.
#[tokio::test]
async fn f13_t2_cold_per_user_direct_refuses_after_one_list() {
    cold_per_user_refuses(Route::Direct).await;
}

/// F13-T8b (and T1's `Shared` form): `Shared` slot, no caller credential,
/// cold, `closed`, on both routes: exactly one `tools/list`, then judged.
/// Red on base: no list, forwarded.
#[tokio::test]
async fn f13_t8b_cold_shared_no_credential_lists_once_then_judges() {
    for route in [Route::Meta, Route::Direct] {
        let fx = cold(InputSchemaEnforcement::Closed, ListMode::Serve).await;
        let (_, body) = call(&fx.router, route, "edit", &nested_invented(), None).await;
        assert!(refused_with(&body, "edits[0].type"), "{route:?}: {body}");
        assert_eq!(fx.rec.lists(), 1, "{route:?}");
        assert_eq!(fx.rec.calls(), 0, "{route:?}: the backend saw the call");
    }
}

/// F13-T4, transport failure: `closed` the dispatch's error (A3), no call,
/// `fetch_failed`; `standard` forwards, `unknown`; `off` never lists.
#[cfg(feature = "metrics")]
#[test]
fn f13_t4_failed_fetch_per_mode() {
    let row = |mode| {
        metered(async move {
            let fx = cold(mode, ListMode::Fail).await;
            let args = nested_invented();
            let (_, body) = call(&fx.router, Route::Direct, "edit", &args, None).await;
            (body, fx.rec.lists(), fx.rec.calls())
        })
    };
    let ((body, lists, calls), rendered) = row(InputSchemaEnforcement::Closed);
    assert!(as_dispatch(&body), "closed: {body}");
    assert_eq!((lists, calls), (1, 0), "closed");
    let label = "input_schema_fetch_failed";
    assert!(kind_counted(&rendered, label), "{label}: {rendered}");
    let label = "input_schema_refused_unavailable";
    assert!(!kind_counted(&rendered, label), "{label}: {rendered}");
    let ((body, lists, calls), rendered) = row(InputSchemaEnforcement::Standard);
    assert!(!is_error(&body), "standard: {body}");
    assert_eq!((lists, calls), (1, 1), "standard");
    assert!(
        kind_counted(&rendered, "input_schema_unknown"),
        "{rendered}"
    );
    let ((body, lists, calls), _) = row(InputSchemaEnforcement::Off);
    assert!(!is_error(&body), "off: {body}");
    assert_eq!((lists, calls), (0, 1), "off must not fetch");
}
