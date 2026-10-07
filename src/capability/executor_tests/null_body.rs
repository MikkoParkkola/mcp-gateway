// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7970: a null the property's schema admits is a value and reaches the
//! JSON body; any other null is not given and is left out.

use super::*;
use std::sync::Mutex;

type Seen = Arc<Mutex<Option<(String, String)>>>;

/// A loopback server that records the path and raw body of one POST.
async fn recording_server() -> (u16, Seen) {
    let seen: Seen = Arc::default();
    let record = Arc::clone(&seen);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let app = Router::new().fallback(move |uri: axum::http::Uri, body: String| {
            let record = Arc::clone(&record);
            async move {
                *record.lock().unwrap() = Some((uri.path().to_owned(), body));
                Json(serde_json::json!({ "ok": true }))
            }
        });
        axum::serve(listener, app).await.unwrap();
    });
    (port, seen)
}

/// Validate as a gateway call does, then execute; the path and JSON body.
async fn call(
    yaml: &str,
    arguments: serde_json::Value,
    seen: &Seen,
) -> (String, serde_json::Value) {
    let (path, body) = call_raw(yaml, arguments, seen).await;
    (path, serde_json::from_str(&body).expect("a JSON body"))
}

/// [`call`], with the body as sent.
async fn call_raw(yaml: &str, arguments: serde_json::Value, seen: &Seen) -> (String, String) {
    let capability = crate::capability::parse_capability(yaml).unwrap();
    let validation = crate::capability::validate_arguments(&arguments, &capability.schema.input);
    assert!(validation.is_valid(), "{:?}", validation.violations);
    let mut executor = CapabilityExecutor::new();
    executor.client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let context = CapabilityExecutionContext::default().with_isolated_loopback_egress();
    executor
        .execute_with_context(&capability, validation.coerced, context)
        .await
        .unwrap();
    seen.lock()
        .unwrap()
        .take()
        .expect("the backend saw the call")
}

/// A parameter in both the path and the body, with a schema default: the
/// caller's admitted null reaches the body; the URL takes the default.
#[tokio::test]
async fn an_admitted_null_beats_the_path_default_in_the_body() {
    let (port, seen) = recording_server().await;
    let yaml = format!(
        r#"
name: null_body_probe
description: probe
schema:
  input:
    type: object
    properties:
      id:
        type: [string, "null"]
        default: d
providers:
  primary:
    service: rest
    config:
      base_url: http://127.0.0.1:{port}
      path: /items/{{id}}
      method: POST
      body:
        id: "{{id}}"
"#
    );
    let (path, body) = call(&yaml, serde_json::json!({ "id": null }), &seen).await;
    assert_eq!(path, "/items/d");
    assert_eq!(body, serde_json::json!({ "id": null }));
}

/// An optional property whose type does not admit null: the validator lets
/// a null through as not given, and the body leaves it out.
#[tokio::test]
async fn a_null_the_schema_does_not_admit_stays_out_of_the_body() {
    let (port, seen) = recording_server().await;
    let yaml = format!(
        r#"
name: null_body_probe
description: probe
schema:
  input:
    type: object
    properties:
      note:
        type: string
      k:
        type: string
providers:
  primary:
    service: rest
    config:
      base_url: http://127.0.0.1:{port}
      path: /notes
      method: POST
      body:
        note: "{{note}}"
        k: "{{k}}"
        label: "n:{{note}}"
"#
    );
    let (_, body) = call(&yaml, serde_json::json!({ "note": null, "k": "v" }), &seen).await;
    // Inside a longer string a null still reads as empty text, as before.
    assert_eq!(body, serde_json::json!({ "k": "v", "label": "n:" }));
}

/// A null the caller never sent: a static param's, or a schema default the
/// URL takes. The schema admits null for both, and neither reaches the body.
#[tokio::test]
async fn a_null_the_caller_did_not_send_stays_out_of_the_body() {
    let (port, seen) = recording_server().await;
    let yaml = format!(
        r#"
name: null_body_probe
description: probe
schema:
  input:
    type: object
    properties:
      id:
        type: [string, "null"]
        default: null
      tag:
        type: [string, "null"]
providers:
  primary:
    service: rest
    config:
      base_url: http://127.0.0.1:{port}
      path: /items/{{id}}
      method: POST
      static_params:
        tag: null
      body:
        id: "{{id}}"
        tag: "{{tag}}"
        k: v
"#
    );
    let (_, body) = call(&yaml, serde_json::json!({}), &seen).await;
    assert_eq!(body, serde_json::json!({ "k": "v" }));
}

/// Each admitted null fills only its own placeholder: a null the schema
/// does not admit stays out beside it, and a nullable property the caller
/// gave a value keeps that value.
#[tokio::test]
async fn an_admitted_null_fills_only_its_own_placeholder() {
    let (port, seen) = recording_server().await;
    let yaml = format!(
        r#"
name: null_body_probe
description: probe
schema:
  input:
    type: object
    properties:
      a:
        type: [string, "null"]
      b:
        type: string
      c:
        type: [string, "null"]
providers:
  primary:
    service: rest
    config:
      base_url: http://127.0.0.1:{port}
      path: /items
      method: POST
      body:
        a: "{{a}}"
        b: "{{b}}"
        c: "{{c}}"
"#
    );
    let (_, body) = call(
        &yaml,
        serde_json::json!({ "a": null, "b": null, "c": "x" }),
        &seen,
    )
    .await;
    assert_eq!(body, serde_json::json!({ "a": null, "c": "x" }));
}

/// A plain-text body cannot carry a JSON null: an admitted null there is
/// not given, and its field is left out of the text.
#[tokio::test]
async fn a_plain_text_body_leaves_an_admitted_null_out() {
    let (port, seen) = recording_server().await;
    let yaml = format!(
        r#"
name: null_body_probe
description: probe
schema:
  input:
    type: object
    properties:
      id:
        type: [string, "null"]
providers:
  primary:
    service: rest
    config:
      base_url: http://127.0.0.1:{port}
      path: /notes
      method: POST
      body_content_type: text/plain
      body:
        id: "{{id}}"
        k: v
"#
    );
    let (_, body) = call_raw(&yaml, serde_json::json!({ "id": null }), &seen).await;
    assert_eq!(body, r#"{"k":"v"}"#);
}
