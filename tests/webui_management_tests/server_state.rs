// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8857.API4.1/API4.3/API4.5 through the router: the server state on the
//! status rows, the refusals route, and the unchanged status shape.

use super::*;

const CANARY: &str = "refusal-route-canary-5d1e";

async fn with_reload() -> (axum::Router, std::path::PathBuf, TempDir) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("gateway.yaml");
    let yaml = crate::yaml::to_string(&Config::default()).unwrap();
    write_owner_only(&path, &yaml).unwrap();
    let (state, _live, _store) =
        make_app_state_with_reload(Config::default(), None, path.clone()).await;
    (create_router(state), path, tmp)
}

#[tokio::test]
async fn api4_5_and_api4_1_status_rows_keep_every_old_key_and_add_the_state() {
    let (state, _store) = make_app_state(None, None).await;
    register_http_backend(&state, "inventory");
    let router = create_router(state);
    let (status, body) = send_json(&router, Method::GET, "/ui/api/status", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let row = &body["servers"][0];
    // Every key the row carried before this change, with its JSON type.
    for (key, is_type) in [
        ("name", Value::is_string as fn(&Value) -> bool),
        ("running", Value::is_boolean),
        ("transport", Value::is_string),
        ("tools_cached", Value::is_u64),
        ("request_count", Value::is_u64),
        ("circuit_state", Value::is_string),
        ("circuit_trips", Value::is_u64),
        ("current_failures", Value::is_u64),
        ("healthy", Value::is_boolean),
        ("success_count", Value::is_u64),
        ("failure_count", Value::is_u64),
    ] {
        assert!(is_type(&row[key]), "{key} changed: {row}");
    }
    for key in ["latency_p50_ms", "latency_p95_ms", "latency_p99_ms"] {
        assert!(row.get(key).is_some(), "{key} gone: {row}");
    }
    // The new fields.
    assert_eq!(row["state"], "dormant", "{row}");
    assert!(
        row["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "{row}"
    );
    assert!(row["next_retry_at"].is_null(), "{row}");
    assert_eq!(row["cleartext_credentials_accepted"], false, "{row}");
}

#[tokio::test]
async fn api4_3_a_refused_add_leaves_gateway_yaml_unchanged_and_is_listed_without_its_values() {
    let (router, path, _tmp) = with_reload().await;
    let before = std::fs::read(&path).unwrap();

    let (status, body) = send_json(
        &router,
        Method::POST,
        "/ui/api/backends",
        Some(json!({
            "name": "inventory",
            "url": format!("http://10.0.4.7/mcp?token={CANARY}"),
        })),
    )
    .await;
    assert!(
        !status.is_success(),
        "the add must be refused: {status} {body}"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "a refused add must not change gateway.yaml"
    );

    let (status, body) = send_json(&router, Method::GET, "/ui/api/refusals", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let list = body["refusals"].as_array().expect("a list");
    assert_eq!(list.len(), 1, "{body}");
    assert_eq!(list[0]["kind"], "add");
    assert_eq!(list[0]["code"], "cleartext_credentials");
    assert_eq!(list[0]["backend"], "inventory");
    assert!(!body.to_string().contains(CANARY), "{body}");
}

#[tokio::test]
async fn api4_3_a_refused_reload_is_listed_and_an_applied_one_resolves_it() {
    let (router, path, _tmp) = with_reload().await;
    write_owner_only(
        &path,
        format!(
            "backends:\n  inventory:\n    http_url: \"http://10.0.4.7/mcp\"\n    headers:\n      \
             Authorization: \"Bearer {CANARY}\"\n"
        ),
    )
    .unwrap();
    let (status, _) = send_json(&router, Method::POST, "/ui/api/reload", None).await;
    assert!(!status.is_success(), "the reload must be refused");

    let (_, body) = send_json(&router, Method::GET, "/ui/api/refusals", None).await;
    let list = body["refusals"].as_array().expect("a list");
    assert_eq!(list.len(), 1, "{body}");
    assert_eq!(list[0]["kind"], "reload");
    assert_eq!(list[0]["code"], "cleartext_credentials");
    assert_eq!(list[0]["active"], true);
    assert!(!body.to_string().contains(CANARY), "{body}");

    write_owner_only(&path, crate::yaml::to_string(&Config::default()).unwrap()).unwrap();
    let (status, body) = send_json(&router, Method::POST, "/ui/api/reload", None).await;
    assert!(status.is_success(), "{body}");
    let (_, body) = send_json(&router, Method::GET, "/ui/api/refusals", None).await;
    assert_eq!(body["refusals"][0]["active"], false, "{body}");
}
