// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! STRICT.2: every UI write body refuses a top-level field it does not know,
//! and a body its callers send today still reaches the handler. Each row
//! sends one body twice as the admin, through the whole router: as callers
//! send it, and with `"extra": 1` added. The second must be refused naming
//! the field and change nothing the matrix fingerprint watches, nor any
//! capability directory. The bodies are built here; `valid_body` and the
//! matrix cells are untouched.

use super::*;

/// The body the route's own parser sends back for an unknown field.
const UNKNOWN: &str = "unknown field `extra`";

/// What the sign-in confirm answers for any body it cannot read.
const CONFIRM_UNREADABLE: &str = "expected a decision and an attempt_id";

/// `body` with one field no UI body declares.
fn with_extra(body: &Value) -> Value {
    let mut extended = body.clone();
    extended
        .as_object_mut()
        .expect("every UI write body is an object")
        .insert("extra".into(), json!(1));
    extended
}

/// A JSON request from this machine as the admin key.
fn admin(method: &str, uri: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN_KEY}"))
        .header(header::CONTENT_TYPE, "application/json")
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_346))))
        .body(Body::from(body.to_string()))
        .expect("a request")
}

/// Every file name in the gateway's capability directories.
fn capability_files(state: &AppState) -> Vec<String> {
    let mut names: Vec<String> = state
        .capability_dirs
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten()
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort_unstable();
    names
}

/// Send `known` and then `known` plus `"extra"` to `uri`; check the second is
/// refused with `refused` and a body naming `marker`, writing nothing, and
/// return the first answer for the row's own checks.
async fn strict(
    method: &str,
    uri: &str,
    known: &Value,
    refused: StatusCode,
    marker: &str,
) -> (StatusCode, String) {
    let fx = fixture(Gateway::On, true).await;
    let router = create_router(Arc::clone(&fx.state));
    let (status, body) = send(&router, admin(method, uri, known)).await;
    let first = (status, String::from_utf8_lossy(&body).into_owned());
    let before = (fingerprint(&fx.state), capability_files(&fx.state));
    let (status, body) = send(&router, admin(method, uri, &with_extra(known))).await;
    let text = String::from_utf8_lossy(&body);
    assert_eq!(
        status, refused,
        "{method} {uri} with an extra field: {text}"
    );
    assert!(
        text.contains(marker),
        "{method} {uri} with an extra field: {text}"
    );
    assert_eq!(
        before,
        (fingerprint(&fx.state), capability_files(&fx.state)),
        "{method} {uri}: a refused body changed the gateway"
    );
    first
}

/// The handler, not the parser, answered: a JSON body that names no unknown
/// field and is not the confirm's unreadable-body answer.
fn handled((status, body): &(StatusCode, String)) {
    assert!(
        serde_json::from_str::<Value>(body).is_ok(),
        "{status}: not the handler's JSON answer: {body}"
    );
    assert!(!body.contains(UNKNOWN), "{status}: {body}");
    assert!(!body.contains(CONFIRM_UNREADABLE), "{status}: {body}");
}

/// Every field the classic page's add and preview forms send, with an empty
/// name so the handler stops at its name check and nothing is written.
fn every_add_field() -> Value {
    json!({
        "name": "", "registry": "r", "command": "c", "url": "http://127.0.0.1:1/mcp",
        "description": "d", "env": { "K": "V" }, "allowed_tools": ["t"],
    })
}

/// S2: the add body, as the minimal probe and with every field callers send.
/// Each known body reaches the name check.
#[tokio::test]
async fn s2_the_add_body_refuses_an_unknown_field() {
    for known in [json!({ "name": "" }), every_add_field()] {
        let first = strict(
            "POST",
            routes::UI_BACKENDS,
            &known,
            StatusCode::UNPROCESSABLE_ENTITY,
            UNKNOWN,
        )
        .await;
        assert_eq!(
            first.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{known}: {}",
            first.1
        );
        handled(&first);
    }
}

/// S3: the preview body, which flattens the add body, so it needs its own
/// attribute; both shapes the page sends (with and without `confirm`).
#[tokio::test]
async fn s3_the_preview_body_refuses_an_unknown_field_in_both_shapes() {
    let mut full = every_add_field();
    full["confirm"] = json!("x");
    for known in [
        json!({ "name": "" }),
        json!({ "name": "", "confirm": "x" }),
        full,
    ] {
        let first = strict(
            "POST",
            routes::UI_PREVIEWS,
            &known,
            StatusCode::UNPROCESSABLE_ENTITY,
            UNKNOWN,
        )
        .await;
        handled(&first);
    }
}

/// S4: the edit body, on a backend that does not exist.
#[tokio::test]
async fn s4_the_edit_body_refuses_an_unknown_field() {
    let uri = routes::UI_BACKEND.replace("{name}", "absent-one");
    let first = strict(
        "PATCH",
        &uri,
        &json!({ "description": "x" }),
        StatusCode::UNPROCESSABLE_ENTITY,
        UNKNOWN,
    )
    .await;
    handled(&first);
}

/// A one-operation `OpenAPI` document, inline, so no row fetches anything.
const SPEC: &str = r#"{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/x":{"get":{"operationId":"getx","responses":{"200":{"description":"ok"}}}}}}"#;

/// S5: the import body on the preview route.
#[tokio::test]
async fn s5_the_import_preview_body_refuses_an_unknown_field() {
    let first = strict(
        "POST",
        routes::UI_IMPORT_PREVIEW,
        &json!({ "spec": SPEC }),
        StatusCode::UNPROCESSABLE_ENTITY,
        UNKNOWN,
    )
    .await;
    handled(&first);
}

/// S6: the import body on the write route; its known body is not a spec, so
/// the handler refuses it and nothing is imported either way.
#[tokio::test]
async fn s6_the_import_body_refuses_an_unknown_field() {
    let first = strict(
        "POST",
        routes::UI_IMPORT,
        &json!({ "spec": "not a spec" }),
        StatusCode::UNPROCESSABLE_ENTITY,
        UNKNOWN,
    )
    .await;
    handled(&first);
}

/// S7: the sign-in confirm keeps its own 400 for a body it cannot read (lead
/// ruling: an auth endpoint's status is not changed in this fix).
#[tokio::test]
async fn s7_the_signin_confirm_body_refuses_an_unknown_field() {
    let uri = routes::UI_BACKEND_SIGNIN_CONFIRM.replace("{name}", "absent-one");
    let known = json!({ "decision": "confirm", "attempt_id": "none" });
    let first = strict(
        "POST",
        &uri,
        &known,
        StatusCode::BAD_REQUEST,
        CONFIRM_UNREADABLE,
    )
    .await;
    handled(&first);
}

/// S8-S10: the three control-plane write bodies, top level only; their nested
/// types are shared with the store, which must keep reading every record.
#[tokio::test]
async fn s8_s10_the_control_plane_bodies_refuse_an_unknown_field() {
    for path in [
        routes::UI_CONTROL_PLANE_GRANTS,
        routes::UI_CONTROL_PLANE_POLICIES,
        routes::UI_CONTROL_PLANE_DECISIONS,
    ] {
        let known = valid_body(path).expect("the matrix's known body");
        let first = strict(
            "POST",
            path,
            &known,
            StatusCode::UNPROCESSABLE_ENTITY,
            UNKNOWN,
        )
        .await;
        assert_eq!(first.0, StatusCode::CONFLICT, "{path}: {}", first.1);
        handled(&first);
    }
}
