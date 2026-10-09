// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7507: two description writes to one issue, in one process, through the
//! shipped `linear_update_issue` capability. A loopback GraphQL endpoint keeps
//! the stored description and answers only with the fields the mutation asks
//! for, as Linear does, so the caller sees what was stored only when the
//! capability asks for it.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{Json, Router, extract::State, routing::post};
use serde_json::{Value, json};

use crate::capability::executor::CapabilityExecutor;

type Stored = Arc<Mutex<String>>;

/// Store `input.description` and answer with the issue's selected fields.
async fn issue_update(State(stored): State<Stored>, Json(request): Json<Value>) -> Json<Value> {
    let query = request["query"].as_str().unwrap_or_default();
    let input = &request["variables"]["input"];
    let mut stored = stored.lock().unwrap();
    if let Some(description) = input["description"].as_str() {
        description.clone_into(&mut stored);
    }
    let mut issue = json!({ "id": "issue-1", "identifier": "MIK-1", "title": "t", "url": "u" });
    let selected = query
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|word| word == "description");
    if selected {
        issue["description"] = json!(stored.clone());
    }
    Json(json!({ "data": { "issueUpdate": { "success": true, "issue": issue } } }))
}

/// The shipped capability, pointed at a loopback endpoint, with its stored
/// description.
async fn update_issue() -> (
    CapabilityExecutor,
    crate::capability::CapabilityDefinition,
    Stored,
) {
    let stored = Stored::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new()
        .route("/graphql", post(issue_update))
        .with_state(Arc::clone(&stored));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut executor = CapabilityExecutor::new();
    executor.client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("capabilities/linear/linear_update_issue.yaml"),
    )
    .unwrap();
    let mut capability = crate::capability::parse_capability(&text).unwrap();
    capability.auth.required = false;
    capability.auth.auth_type.clear();
    capability.auth.key.clear();
    let primary = capability.providers.named.get_mut("primary").unwrap();
    primary.config.base_url = format!("http://localhost:{port}");
    (executor, capability, stored)
}

#[tokio::test]
async fn a_second_description_write_applies_and_is_echoed() {
    let (executor, capability, stored) = update_issue().await;
    for text in [
        "first description",
        "second, longer description with `code`",
    ] {
        let answer = executor
            .execute(
                &capability,
                json!({ "issueId": "issue-1", "description": text }),
            )
            .await
            .unwrap();
        assert_eq!(
            *stored.lock().unwrap(),
            text,
            "the write did not reach the store"
        );
        assert_eq!(
            answer["issue"]["description"], text,
            "the answer does not show what was stored: {answer}"
        );
    }
}
