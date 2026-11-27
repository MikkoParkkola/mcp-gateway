// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Route rows assert the contract, never the temporary 501 answer.
use super::{
    NOT_AUDITED, OUTSIDE_CHANGE_APPLIED, SettingsStoreForTest, restart_fields, test_support::*,
};
use crate::config_reload::FileRevision;
use crate::gateway::ui::admin_audit::AuditDetail;
use axum::http::StatusCode;
use serde_json::{Map, Value, json};
use std::sync::Arc;

/// S1: red oracle is the exact zero-context budget diff and original revision.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn s1_budget_diff() {
    let route = Route::new(BUDGET).await;
    let (status, body) = route
        .diff(json!([set("cost_governance.budgets.daily", &json!(12.5))]))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"revision": route.revision(), "diff":
        "--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -7,1 +7,1 @@\n-    daily: 10.0 # <comment>\n+    daily: 12.5 # <comment>\n"})
    );
    assert_eq!(route.text(), BUDGET);
}

/// S2: red oracle is a masked new secret in a successful preview.
#[tokio::test]
async fn s2_secret_diff() {
    let route = Route::new(BASE).await;
    let (status, body) = route
        .diff(json!([{"field":"auth.bearer_token","value":{"secret":true}}]))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revision"], route.revision());
    assert!(
        body["diff"]
            .as_str()
            .expect("diff")
            .contains("<new secret>")
    );
    assert_eq!(route.text(), BASE);
}

/// S3: red oracle is `invalid_body` for a secret literal sent to diff, before store access.
#[tokio::test]
async fn s3_diff_rejects_secret_bytes() {
    let mut route = Route::new(BASE).await;
    let store = super::route_secret_tests::recording(&route, None);
    route.store = Some(SettingsStoreForTest::Store(store.clone()));
    let body = refused(
        route.diff(json!([secret("secret-diff-canary")])).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_body",
    );
    assert_eq!(body, json!({"error":"invalid_body"}));
    assert_eq!(store.calls(), 0);
    assert_eq!(route.text(), BASE);
}

/// S4: red oracle is the complete successful save body, exact bytes, and published budget.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn s4_budget_save() {
    let route = Route::new(BUDGET).await;
    let next = BUDGET.replace("10.0", "12.5");
    let (status, body) = route
        .save(json!([set("cost_governance.budgets.daily", &json!(12.5))]))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"revision": FileRevision::of(next.as_bytes()).as_str(),
        "changed":true, "reload":{"changes":"profiles/meta config changed","restart_required":false},
        "restart_required":[], "comments":"kept",
        "notices":[{"code":NOT_AUDITED.0,"message":NOT_AUDITED.1}]})
    );
    assert_eq!(route.text(), next);
    let running = serde_json::to_value(route.ctx.live_config.get().as_ref()).expect("config JSON");
    assert_eq!(running["cost_governance"]["budgets"]["daily"], 12.5);
}

/// S5: red oracle is 500 failed after a refusing reload, with byte-exact rollback.
#[tokio::test]
async fn s5_refusing_reload() {
    let route = Route::with_reload(BASE, true).await;
    refused(
        route
            .save(json!([set("environment", &json!("prod"))]))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed",
    );
    assert_eq!(route.text(), BASE);
    assert_eq!(
        route.ctx.live_config.get().environment.as_deref(),
        Some("dev")
    );
}

/// S6: red oracle is the complete in-place refusal patch, with no write.
#[tokio::test]
async fn s6_anchored_key() {
    let text = BASE.replace("environment: \"dev\"", "environment: &env \"dev\"");
    let route = Route::new(&text).await;
    let body = refused(
        route
            .save(json!([set("environment", &json!("prod"))]))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "not_in_place",
    );
    assert_eq!(
        body,
        json!({"error":"not_in_place", "patch":[{
            "op":"set", "path":"environment", "value":"\"prod\"", "code":"anchor",
            "reason":"the value has an anchor, a tag or an alias"
        }]})
    );
    assert_eq!(route.text(), text);
}

/// S7: red oracle is the whole reload and the auth parent naming auth.enabled pending.
#[tokio::test]
async fn s7_restart_parent() {
    let route = Route::new(BASE).await;
    let next = BASE.replace("enabled: false", "enabled: true");
    let (status, body) = route.save(json!([set("auth.enabled", &json!(true))])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The advice keys a pending restart adds are R2's (restart_advice_route_tests.rs);
    // start_refusal is not removed, so a refusal here still fails this row.
    let mut body = body;
    for key in ["restart_advice", "start_command"] {
        body.as_object_mut().expect("an object").remove(key);
    }
    assert_eq!(
        body,
        json!({"revision": FileRevision::of(next.as_bytes()).as_str(), "changed":true,
        "reload":{"changes":"profiles/meta config changed — NOT YET APPLIED, restart required for: auth",
            "restart_required":true,"restart_reason":"config changed in fields that only a restart applies",
            "pending_restart_fields":["auth"]},
        "restart_required":["auth.enabled"], "comments":"kept",
        "notices":[{"code":NOT_AUDITED.0,"message":NOT_AUDITED.1}]})
    );
    assert_eq!(
        crate::config_reload::ui_fields::FieldId::of("auth.enabled")
            .expect("field")
            .spec()
            .apply,
        crate::config_reload::ui_fields::Apply::Restart
    );
    assert_eq!(route.text(), next);
}

/// S8: red oracle includes Live fields beneath pending parents, excludes near names and unrelated fields.
#[test]
fn s8_restart_matches_whole_segments() {
    let mut reload = crate::config_reload::ReloadOutcome::no_changes();
    reload.pending_restart_fields = vec!["backends".into(), "authx".into()];
    assert_eq!(
        restart_fields(&["backends.owner", "environment", "auth.enabled"], &reload),
        vec!["backends.owner".to_owned()]
    );
    reload.pending_restart_fields = vec!["backends.owner".into()];
    assert_eq!(
        restart_fields(&["backends.owner"], &reload),
        vec!["backends.owner".to_owned()]
    );
    // A pending name that is a string prefix of a field id, but not a whole
    // segment of it, names a different section: never listed.
    reload.pending_restart_fields = vec!["cost".into()];
    assert!(restart_fields(&["cost_governance.enabled"], &reload).is_empty());
    reload.pending_restart_fields.clear();
    assert!(restart_fields(&["backends.owner"], &reload).is_empty());
}

/// S9: red oracle is typed `posture_refused` on both routes after an outside publication edit.
#[tokio::test]
async fn s9_network_posture() {
    let route = Route::new(BASE).await;
    let outside = format!("{BASE}server:\n  public_url: https://public.example.test\n");
    route.write(&outside);
    for save in [false, true] {
        let fields = json!([set("environment", &json!("prod"))]);
        let answer = if save {
            route.save(fields).await
        } else {
            route.diff(fields).await
        };
        refused(answer, StatusCode::CONFLICT, "posture_refused");
        assert_eq!(route.text(), outside);
        assert_eq!(
            route.ctx.live_config.get().environment.as_deref(),
            Some("dev")
        );
        assert!(route.ctx.live_config.get().server.public_url.is_none());
    }
}

/// S9b: red oracle is invalid for malformed config, separately from post-write Internal (S5).
#[tokio::test]
async fn s9b_invalid_config() {
    for outside in [
        format!("{BASE}server: [\n"),
        format!("{BASE}server:\n  port: 999999\n"),
    ] {
        let route = Route::new(BASE).await;
        route.write(&outside);
        for save in [false, true] {
            let fields = json!([set("environment", &json!("prod"))]);
            let answer = if save {
                route.save(fields).await
            } else {
                route.diff(fields).await
            };
            refused(answer, StatusCode::UNPROCESSABLE_ENTITY, "invalid");
            assert_eq!(route.text(), outside);
        }
    }
}

/// S9b: red oracle is 500, never 422, for an injected post-write Internal refusal.
#[tokio::test]
async fn s9b_internal_after_write() {
    let route = Route::with_reload(BASE, true).await;
    refused(
        route
            .save(json!([set("environment", &json!("prod"))]))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed",
    );
    assert_eq!(route.text(), BASE);
    assert_eq!(
        route.ctx.live_config.get().environment.as_deref(),
        Some("dev")
    );
}

/// S9c: red oracle is 409 after a publication edit at the existing writer/reload pause, then rollback.
#[tokio::test]
async fn s9c_post_write_posture() {
    let route = Route::new(BASE).await;
    let pause = crate::config_reload::arm_reload_pause(&route.path());
    let save = route.save(json!([set("environment", &json!("prod"))]));
    tokio::pin!(save);
    tokio::select! {
        result = &mut save => panic!("S9c: save answered before reaching the reload: {result:?}"),
        () = pause.reached.notified() => {},
        () = tokio::time::sleep(crate::test_wait::HANG_BOUND) => panic!("S9c: reload not reached"),
    }
    assert!(route.text().contains("prod"), "write precedes the seam");
    route.write(&format!(
        "{}server:\n  public_url: https://public.example.test\n",
        route.text()
    ));
    pause.release.notify_one();
    refused(save.await, StatusCode::CONFLICT, "posture_refused");
    assert_eq!(route.text(), BASE);
    assert_eq!(
        route.ctx.live_config.get().environment.as_deref(),
        Some("dev")
    );
}

/// S10: guard oracle is 403 for API-key and OIDC developers even without a readable file.
/// This security control is already green because admission is intentionally not stubbed.
#[tokio::test]
async fn s10_non_admin() {
    let route = Route::new(BASE).await;
    std::fs::remove_file(route.path()).expect("remove the read target");
    for kind in [
        crate::security::audit::CredentialKind::ApiKey,
        crate::security::audit::CredentialKind::OidcBearer,
    ] {
        for save in [false, true] {
            let mut who = client(false);
            who.credential_kind = kind;
            let (status, body) = route.raw(save, "{}", who).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            assert_eq!(body, json!({"error":"Admin authentication required"}));
        }
    }
}

/// S11: red oracle is `unknown_field` at entry 2, without repeating the submitted id.
#[tokio::test]
async fn s11_unknown_field() {
    let route = Route::new(BASE).await;
    for save in [false, true] {
        let fields = json!([
            set("environment", &json!("dev")),
            set("auth.enabled", &json!(false)),
            set("unknown-id-canary", &json!(true))
        ]);
        let answer = if save {
            route.save(fields).await
        } else {
            route.diff(fields).await
        };
        assert_eq!(
            refused(answer, StatusCode::UNPROCESSABLE_ENTITY, "unknown_field"),
            json!({"error":"unknown_field", "entry":2})
        );
    }
}

/// S12: red oracle is `bad_value` for each wrong scalar type on both routes.
#[tokio::test]
async fn s12_wrong_scalar_types() {
    let route = Route::new(BASE).await;
    let mut fields = vec![
        set("auth.enabled", &json!("true")),
        set("environment", &json!(42)),
    ];
    #[cfg(feature = "cost-governance")]
    fields.extend([
        set("cost_governance.budgets.daily", &json!("12.5")),
        json!({"field":"cost_governance.alerts.at_percent","index":0,"value":{"set":12.5}}),
        json!({"field":"cost_governance.alerts.action","index":0,"value":{"set":false}}),
    ]);
    for field in fields.drain(..) {
        for save in [false, true] {
            let fields = json!([field]);
            let answer = if save {
                route.save(fields).await
            } else {
                route.diff(fields).await
            };
            let body = refused(answer, StatusCode::UNPROCESSABLE_ENTITY, "bad_value");
            assert_eq!(body["field"], field["field"]);
        }
    }
}

/// S12: red oracle is successful numeric conversion for an integer budget.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn s12_num_accepts_integer() {
    let route = Route::new(BUDGET).await;
    for save in [false, true] {
        let fields = json!([set("cost_governance.budgets.daily", &json!(12))]);
        let (status, body) = if save {
            route.save(fields).await
        } else {
            route.diff(fields).await
        };
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

/// S13: red oracle is the full stale answer with the new revision and a fresh diff.
#[tokio::test]
async fn s13_stale() {
    let route = Route::new(BASE).await;
    let body = route.saved_body(&json!([set("environment", &json!("prod"))]));
    let outside = BASE.replace("\"dev\"", "\"staging\"");
    route.write(&outside);
    let answer = route.raw(true, &body.to_string(), client(true)).await;
    assert_eq!(
        refused(answer, StatusCode::CONFLICT, "stale"),
        json!({"error":"stale",
        "current": route.revision(), "diff":"--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -2,1 +2,1 @@\n-environment: \"staging\" # <comment>\n+environment: \"prod\" # <comment>\n"})
    );
    assert_eq!(route.text(), outside);
}

/// S14: red oracle is `audit_log_required` when running auth is on and no logger exists.
#[tokio::test]
async fn s14_audit_required() {
    let text = BASE.replace("enabled: false", "enabled: true");
    let mut route = Route::new(&text).await;
    Arc::get_mut(&mut route.state)
        .expect("unique state")
        .live_config = Arc::clone(&route.ctx.live_config);
    assert!(route.state.live_config.running().auth.enabled);
    assert!(route.state.transparency_log.is_none());
    let body = refused(
        route
            .save(json!([set("environment", &json!("prod"))]))
            .await,
        StatusCode::CONFLICT,
        "audit_log_required",
    );
    assert_eq!(
        body,
        json!({"error":"audit_log_required", "message":crate::config_reload::NO_AUDIT_LOG})
    );
    assert_eq!(route.text(), text);
}

/// S15: red oracle is 503 from a secret save whose opener times out, with no write.
#[tokio::test]
async fn s15_store_open_timeout() {
    let mut route = Route::new(BASE).await;
    route.store = Some(SettingsStoreForTest::OpenRefused(
        super::super::secret_slots::Unopened::TimedOut,
    ));
    let (status, body) = route.save(json!([secret("open-timeout-canary")])).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(
        body,
        json!({"error": "the secret store did not answer; retry"})
    );
    assert!(!body.to_string().contains("open-timeout-canary"));
    assert_eq!(route.text(), BASE);
}

/// S16: red oracle is two successful requests, no diff audit record and exactly one save record.
#[tokio::test]
async fn s16_admin_audit() {
    use tower::ServiceExt as _;
    let mut route = Route::new(BASE).await;
    let log = route.audit();
    let router = super::super::admin_audit::behind_admin_layer_for_test(
        super::super::api_router(),
        &route.state,
    )
    .with_state(route.state.clone())
    .layer(axum::Extension(route.state.live_config.generation()));
    for save in [false, true] {
        let path = if save {
            crate::gateway::routes::UI_SETTINGS
        } else {
            crate::gateway::routes::UI_SETTINGS_DIFF
        };
        let fields = json!([set("environment", &json!("prod"))]);
        let body = if save {
            route.saved_body(&fields)
        } else {
            json!({"fields":fields})
        };
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .expect("request");
        request.extensions_mut().insert(client(true));
        let (status, body) = decode(router.clone().oneshot(request).await.expect("route")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let records: Vec<Value> = std::fs::read_to_string(log.path())
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|entry| entry["event"] == "admin_action")
            .collect();
        assert_eq!(records.len(), usize::from(save));
        if save {
            assert_eq!(records[0]["route"], path);
            assert_eq!(records[0]["http_status"], 200);
            assert_eq!(records[0]["who"]["account"], "settings-route");
        }
    }
}

/// S17: red oracle is one fixed `invalid_body` for malformed JSON, unknown members and bad revisions.
#[tokio::test]
async fn s17_invalid_bodies() {
    let route = Route::new(BASE).await;
    for save in [false, true] {
        let valid = if save {
            route.saved_body(&json!([]))
        } else {
            json!({"fields":[]})
        };
        let mut extra = valid.clone();
        extra["unexpected"] = json!("body-canary");
        let mut nested = valid.clone();
        nested["fields"] =
            json!([{"field":"environment","value":{"set":"prod"},"unexpected":"body-canary"}]);
        for raw in [
            "{body-canary".to_owned(),
            extra.to_string(),
            nested.to_string(),
        ] {
            assert_eq!(
                refused(
                    route.raw(save, &raw, client(true)).await,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "invalid_body"
                ),
                json!({"error":"invalid_body"})
            );
        }
    }
    assert_eq!(
        refused(
            route
                .raw(
                    true,
                    r#"{"base_revision":"body-canary","fields":[]}"#,
                    client(true)
                )
                .await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_body"
        ),
        json!({"error":"invalid_body"})
    );
}

/// One save of `environment = value`: its status, its answer, and the
/// detail its admin record carries.
async fn save_env(route: &Route, value: &str) -> (StatusCode, Value, Map<String, Value>) {
    let body = route.saved_body(&json!([set("environment", &json!(value))]));
    let response = route.response(true, &body.to_string(), client(true)).await;
    let detail = response.extensions().get::<AuditDetail>().cloned();
    let AuditDetail(detail) = detail.expect("every save answer carries its detail");
    let (status, answer) = decode(response).await;
    (status, answer, detail)
}

/// The codes in the answer's `notices`, in order.
fn codes(answer: &Value) -> Vec<String> {
    let notices = answer["notices"].as_array().expect("a notices array");
    notices
        .iter()
        .map(|notice| notice["code"].as_str().expect("a code").to_owned())
        .collect()
}

/// The hash of the one save intent in the route's log.
fn intent_hash(route: &Route) -> Value {
    let log = std::fs::read_to_string(route.dir.path().join("audit.jsonl")).expect("the log");
    let intents: Vec<Value> = log
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["event"] == "config_save_intent")
        .collect();
    assert_eq!(intents.len(), 1, "one save intent:\n{log}");
    intents[0]["entry_hash"].clone()
}

#[test]
fn the_notice_codes_are_their_names() {
    assert_eq!(OUTSIDE_CHANGE_APPLIED.0, "OUTSIDE_CHANGE_APPLIED");
    assert_eq!(NOT_AUDITED.0, "NOT_AUDITED");
}

/// W3 (a): an outside edit, then a save of the value the file already holds.
/// No byte changed, the reload took the edit up: applied, and said once.
#[tokio::test]
async fn w3_an_outside_edit_the_save_took_up_is_said() {
    let mut route = Route::new(BASE).await;
    route.audit();
    route.write(&BASE.replace("\"dev\"", "\"staging\""));
    let (status, answer, detail) = save_env(&route, "staging").await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["changed"], false, "{answer}");
    assert_eq!(codes(&answer), [OUTSIDE_CHANGE_APPLIED.0], "{answer}");
    assert!(answer.get("reload").is_some(), "{answer}");
    assert_eq!(detail["save_outcome"], "applied", "{detail:?}");
}

/// W3 (b): the same with no audit log: both notices, neither overwriting.
#[tokio::test]
async fn w3_both_notices_stand_on_one_save() {
    let route = Route::new(BASE).await;
    route.write(&BASE.replace("\"dev\"", "\"staging\""));
    let (status, answer, _) = save_env(&route, "staging").await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    // A set (test plan W3(b)): the spec fixes which notices, not their order.
    let mut got = codes(&answer);
    got.sort_unstable();
    let mut want = [OUTSIDE_CHANGE_APPLIED.0, NOT_AUDITED.0];
    want.sort_unstable();
    assert_eq!(got, want, "{answer}");
}

/// W3 (c): a restart-only outside edit (the port) counts as applied; the
/// reload outcome says it waits for a restart.
#[tokio::test]
async fn w3_a_restart_only_outside_edit_is_said_and_waits() {
    let mut route = Route::new(BASE).await;
    route.audit();
    route.write(&format!("{BASE}server:\n  port: 39401\n"));
    let (status, answer, detail) = save_env(&route, "dev").await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(codes(&answer), [OUTSIDE_CHANGE_APPLIED.0], "{answer}");
    assert_eq!(answer["reload"]["restart_required"], true, "{answer}");
    let reason = &answer["reload"]["restart_reason"];
    assert_eq!(reason, "server_address_changed", "{answer}");
    assert_eq!(detail["save_outcome"], "applied", "{detail:?}");
}

/// W3 (d), the control: no outside edit, the same no-op save. Unchanged,
/// no notice, and the unchanged save's intent id is on its record.
#[tokio::test]
async fn w3_a_no_op_save_with_no_outside_edit_is_unchanged() {
    let mut route = Route::new(BASE).await;
    route.audit();
    let (status, answer, detail) = save_env(&route, "dev").await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(codes(&answer), Vec::<String>::new(), "{answer}");
    assert_eq!(detail["save_outcome"], "unchanged", "{detail:?}");
    assert_eq!(detail["intent_id"], intent_hash(&route), "{detail:?}");
}

/// W2 (j): auth off and no audit log: the save goes ahead, its record's
/// detail says applied with no intent id, and its answer says it is not
/// audited.
#[tokio::test]
async fn w2_an_unaudited_save_says_not_audited() {
    let route = Route::new(BASE).await;
    let (status, answer, detail) = save_env(&route, "prod").await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(detail["save_outcome"], "applied", "{detail:?}");
    assert!(detail.get("intent_id").is_none(), "{detail:?}");
    assert_eq!(codes(&answer), [NOT_AUDITED.0], "{answer}");
}

/// Review r1 (gpt): through the routes, a gateway.yaml the guarded read
/// refuses answers the diff (a read) 503 with no `Retry-After`, and the save
/// (nothing attempted) 409 with the same body.
#[cfg(unix)]
#[tokio::test]
async fn an_unreadable_file_is_503_on_the_diff_and_409_on_the_save() {
    use std::os::unix::fs::PermissionsExt as _;
    let route = Route::new(BASE).await;
    std::fs::set_permissions(route.path(), std::fs::Permissions::from_mode(0o664))
        .expect("group-writable");
    let fields = json!([set("environment", &json!("prod"))]);
    let body = json!({"fields": fields}).to_string();
    let read = route.response(false, &body, client(true)).await;
    assert_eq!(read.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!read.headers().contains_key(axum::http::header::RETRY_AFTER));
    let (_, read) = decode(read).await;
    let (status, saved) = route.save(fields).await;
    assert_eq!(status, StatusCode::CONFLICT, "{saved}");
    assert_eq!(read, json!({"error": "gateway.yaml could not be loaded"}));
    assert_eq!(saved, read);
}
