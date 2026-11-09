// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8706: `linear_get_issue` looks an issue up by its key, never by the
//! first hit of a text search. A loopback GraphQL endpoint answers the way
//! Linear does: `issue(id:)` resolves a UUID or an identifier, an unknown key
//! is an error with `data: null`, and `searchIssues` ranks some other issue
//! first, as it did for an issue's UUID in production (MIK-8410's returned
//! MIK-5478).
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{Json, Router, extract::State, routing::post};
use serde_json::{Value, json};

use crate::capability::executor::CapabilityExecutor;

const WANTED_ID: &str = "9cf1e2a4-6b3d-4f8e-a1c7-2d5b8e0f3a61";
const WANTED_KEY: &str = "MIK-8410";

fn issue(id: &str, identifier: &str) -> Value {
    json!({
        "id": id,
        "identifier": identifier,
        "title": format!("issue {identifier}"),
        "comments": { "nodes": [] },
        "children": { "nodes": [] },
    })
}

/// Every query the capability sent, in order.
type Seen = Arc<Mutex<Vec<String>>>;

async fn linear(State(seen): State<Seen>, Json(request): Json<Value>) -> Json<Value> {
    let query = request["query"].as_str().unwrap_or_default().to_owned();
    seen.lock().unwrap().push(query.clone());
    if query.contains("searchIssues") {
        let other = issue("0b5a5bd5-0000-4000-8000-000000005478", "MIK-5478");
        return Json(json!({ "data": { "searchIssues": { "nodes": [other] } } }));
    }
    // Only a real key lookup is answered: anything else is refused as Linear
    // refuses a query it cannot run, so a changed query fails these tests.
    if !(query.contains("$id: String!") && query.contains("issue(id: $id)")) {
        return Json(json!({ "data": null, "errors": [{ "message": "unexpected query" }] }));
    }
    let key = request["variables"]["id"].as_str().unwrap_or_default();
    if key == WANTED_ID || key == WANTED_KEY {
        return Json(json!({ "data": { "issue": issue(WANTED_ID, WANTED_KEY) } }));
    }
    Json(json!({
        "data": null,
        "errors": [{
            "message": "Entity not found: Issue",
            "extensions": { "userPresentableMessage": "Could not find referenced Issue." }
        }]
    }))
}

/// The shipped capability, pointed at the loopback endpoint.
async fn get_issue() -> (
    CapabilityExecutor,
    crate::capability::CapabilityDefinition,
    Seen,
) {
    let seen = Seen::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new()
        .route("/graphql", post(linear))
        .with_state(Arc::clone(&seen));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut executor = CapabilityExecutor::new();
    executor.client = crate::test_fixture_host::fixture_client(Duration::from_secs(2)).into();
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("capabilities/linear/linear_get_issue.yaml"),
    )
    .unwrap();
    let mut capability = crate::capability::parse_capability(&text).unwrap();
    capability.auth.required = false;
    capability.auth.auth_type.clear();
    capability.auth.key.clear();
    let primary = capability.providers.named.get_mut("primary").unwrap();
    primary.config.base_url = crate::test_fixture_host::fixture_url(port);
    (executor, capability, seen)
}

fn no_search(seen: &Seen) {
    let seen = seen.lock().unwrap();
    assert!(
        seen.iter().all(|query| !query.contains("searchIssues")),
        "the lookup ran a text search: {seen:?}"
    );
}

/// MIK-8706.KEY.1: a UUID returns the issue it names.
#[tokio::test]
async fn a_uuid_returns_the_issue_it_names() {
    let (executor, capability, seen) = get_issue().await;
    let answer = executor
        .execute(&capability, json!({ "identifier": WANTED_ID }))
        .await
        .unwrap();
    assert_eq!(answer["issue"]["id"], WANTED_ID, "{answer}");
    assert_eq!(answer["issue"]["identifier"], WANTED_KEY, "{answer}");
    no_search(&seen);
}

/// MIK-8706.KEY.2: an identifier returns that issue even when a text search
/// would rank another one first.
#[tokio::test]
async fn an_identifier_returns_that_issue_when_search_ranks_another_first() {
    let (executor, capability, seen) = get_issue().await;
    let answer = executor
        .execute(&capability, json!({ "identifier": WANTED_KEY }))
        .await
        .unwrap();
    assert_eq!(answer["issue"]["identifier"], WANTED_KEY, "{answer}");
    no_search(&seen);
}

/// MIK-8706.KEY.1: a key no issue has is an error, not another issue.
#[tokio::test]
async fn an_unknown_key_is_an_error_not_another_issue() {
    let (executor, capability, _seen) = get_issue().await;
    let unknown = "00000000-0000-4000-8000-000000000000";
    let outcome = executor
        .execute(&capability, json!({ "identifier": unknown }))
        .await;
    let message = match outcome {
        Ok(answer) => panic!("an unknown key answered with an issue: {answer}"),
        Err(error) => error.to_string(),
    };
    assert!(message.contains("Entity not found"), "{message}");
}
