// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Adding a URL server with headers, and the plain-http credential refusal
//! answered before anything is written. Uses the parent's panel fixture.

use serde_json::json;

use super::*;

/// The add's answer and the detail its admin action record would carry
/// (`AuditDetail` on the response; `None` when the handler attached none).
async fn add_with_detail(panel: &Panel, body: Value) -> (StatusCode, Value, Option<String>) {
    let req: AddBackendRequest = serde_json::from_value(body).expect("add body");
    let guard = Panel::guard(routes::UI_BACKENDS, &axum::http::Method::POST);
    let response = add_backend(State(Arc::clone(&panel.state)), None, guard, Json(req))
        .await
        .into_response();
    let detail = response
        .extensions()
        .get::<crate::gateway::ui::admin_audit::AuditDetail>()
        .map(|detail| Value::Object(detail.0.clone()).to_string());
    let (status, answer) = read(response).await;
    (status, answer, detail)
}

/// H1: a URL add with a key header: the secret header value goes to the
/// store and gateway.yaml holds its reference; a plain header is written as
/// typed; the literal is in no answer, file, log record or audit detail.
#[test]
fn h1_a_url_add_stores_a_secret_header_and_answers_its_reference() {
    let bearer = format!("Bearer {TOKEN}");
    let mut checked = false;
    let logs = crate::test_log_capture::records(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        runtime.block_on(async {
            let panel = Panel::new().await;
            let body = json!({
                "name": "h",
                "url": "https://host.example/mcp",
                "headers": {"Authorization": bearer, "X-Team": "ops"},
            });
            let (status, answer, detail) = add_with_detail(&panel, body).await;
            assert_eq!(status, StatusCode::CREATED, "{answer}");
            no_value(&answer, TOKEN);
            let stored = answer["secrets_stored"].as_array().expect("secrets_stored");
            assert_eq!(stored.len(), 1, "{answer}");
            assert_eq!(stored[0]["field"], "headers.Authorization", "{answer}");
            let reference = stored[0]["reference"].as_str().expect("a reference");
            let text = panel.text();
            assert!(
                !text.contains(TOKEN),
                "the literal reached gateway.yaml:\n{text}"
            );
            let written = panel.written("h");
            assert_eq!(
                written.headers.get("Authorization").map(String::as_str),
                Some(reference),
                "{text}"
            );
            assert_eq!(
                written.headers.get("X-Team").map(String::as_str),
                Some("ops"),
                "{text}"
            );
            assert!(
                !detail.as_deref().unwrap_or_default().contains(TOKEN),
                "the literal reached the audit detail: {detail:?}"
            );
            checked = true;
        });
    });
    assert!(checked, "the add's assertions did not run");
    let shown = logs
        .iter()
        .filter(|r| r.to_string().contains(TOKEN))
        .count();
    assert_eq!(shown, 0, "the literal reached the log: {logs:#?}");
}

/// C2: a plain-http URL with an ordinary query is credential-bearing by the
/// config's own rule; the add refuses it as the operator's mistake (422),
/// where it used to fail inside the writer with a 500.
#[tokio::test]
async fn c2_a_plain_http_url_with_a_plain_query_no_longer_answers_500() {
    let panel = Panel::new().await;
    let (status, answer) = panel
        .add(json!({"name": "q", "url": "http://host.example/mcp?x=1"}))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(answer["error"], "cleartext_credentials", "{answer}");
}
