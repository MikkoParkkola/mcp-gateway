// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F13 cells on a filled catalogue: an absent forward has its own label, the
//! first cold call carries its parameter mirror, and a cold caller fetches
//! its own catalogue (moved from `f13_fetch_on_miss_tests.rs`).

use super::*;

/// F13-T10b: complete slot, invented name, `standard`: the gateway answers text A,
/// never forwarded, counted `input_schema_refused_absent` and no other kind.
#[cfg(feature = "metrics")]
#[test]
fn f13_t10b_absent_forward_is_its_own_label() {
    let ((body, rec), rendered) = metered(async {
        let fx = build(Setup {
            config: BackendConfig {
                input_schema_enforcement: InputSchemaEnforcement::Standard,
                ..BackendConfig::default()
            },
            warm: true,
            ..Setup::default()
        })
        .await;
        let (_, body) = call(&fx.router, Route::Direct, "nosuch", &json!({}), None).await;
        (body, fx.rec)
    });
    let absent = crate::backend::text_absent("nosuch");
    assert!(refused_with(&body, &absent), "{body}");
    assert_eq!(rec.calls(), 0, "a complete list's lack must not forward");
    let counted = |k: &str| kind_counted(&rendered, k);
    let refused = counted("input_schema_refused_absent");
    let others = counted("input_schema_absent_forward") || counted("input_schema_unknown");
    assert!(refused && !others, "{rendered}");
}

/// F13-T11: the first cold call carries its `Mcp-Param-*` mirror, because the
/// fill warmed the slot `param_header_set` reads. Red on base: the slot is
/// cold at dispatch, so the first call carries no mirror.
#[tokio::test]
async fn f13_t11_first_cold_call_carries_its_param_mirror() {
    let fx = cold(InputSchemaEnforcement::Closed, ListMode::Serve).await;
    let schema = json!({"type": "object", "properties": {
        "edits": {"type": "array"},
        "note": {"type": "string", "x-mcp-header": "Note"}
    }});
    fx.rec.serve(json!([tool("edit", &schema)]));
    let args = json!({"edits": [], "note": "n1"});
    let (_, body) = call(&fx.router, Route::Direct, "edit", &args, None).await;
    assert!(!is_error(&body), "{body}");
    let sent = fx.rec.headers_of("tools/call");
    assert_eq!(sent.len(), 1, "{body}");
    let mirrored = has_header(&sent[0], "Mcp-Param-Note", "n1");
    assert!(mirrored, "the first call carried no mirror: {sent:?}");
}

/// F13-T9 (A3), on both routes: alpha's slot is warm with a schema that
/// declares `zzextra`; beta's is cold and its catalogue does not. Beta's cold
/// call fetches with beta's own minted token and is judged against beta's
/// schema. Red on base: beta's slot is never listed and the call forwards.
#[tokio::test]
async fn f13_t9_cold_caller_fetches_its_own_catalogue_with_its_own_token() {
    for route in [Route::Meta, Route::Direct] {
        let gw = per_user(&["alpha", "beta"]).await;
        let (alpha, beta) = (&gw.slots[0], &gw.slots[1]);
        let with_extra = json!({"type": "object", "properties": {
            "edits": {"type": "array"}, "zzextra": {"type": "integer"}}});
        let without = json!({"type": "object", "properties": {"edits": {"type": "array"}}});
        alpha.serve(json!([tool("edit", &with_extra)]));
        beta.serve(json!([tool("edit", &without)]));
        let list = json!({"jsonrpc": "2.0", "id": 33, "method": "tools/list"});
        let (status, _) = post(&gw.router, "/mcp/edits", &list, Some("alpha")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(alpha.lists(), 1, "{route:?}: alpha did not warm its slot");

        let args = json!({"edits": [], "zzextra": 1});
        let (_, body) = call(&gw.router, route, "edit", &args, Some("beta")).await;
        assert!(refused_with(&body, "zzextra"), "{route:?}: {body}");
        assert_eq!(beta.lists(), 1, "{route:?}: beta's slot was not listed");
        let token = beta.headers_of("tools/list");
        let as_beta = has_header(&token[0], "Authorization", "Bearer minted-for-beta");
        assert!(
            as_beta,
            "{route:?}: beta's list was not fetched as beta: {token:?}"
        );
        let calls = beta.calls() + alpha.calls() + gw.shared.calls();
        assert_eq!((calls, gw.shared.lists()), (0, 0), "{route:?}");
    }
}
