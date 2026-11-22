// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R12c: the CLI-key ban reads the auth table the request arrived with. A
//! reload that drops the CLI key while its request is in flight must not
//! let that request restore.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Extension, FromRequest as _, State};
use axum::http::{Method, Request, StatusCode};
use serde_json::{Value, json};

use super::super::guard::Guard;
use super::support_tests::{Audit, CLI, Rig, config_text, config_text_without_cli};
use super::{RestoreBody, restore};
use crate::gateway::routes;

#[tokio::test]
async fn r12c_a_cli_key_dropped_mid_request_is_still_refused() {
    let first = config_text("environment: \"a\"\n");
    let rig = Rig::start(&first, Audit::Logged).await;
    rig.reload_to(&config_text("environment: \"b\"\n")).await;
    let old = rig.version_of(first.as_bytes());
    // The table the CLI request was authenticated against.
    let arrival = rig.state.live_config.generation();
    let cli = arrival
        .auth()
        .validate_token(CLI)
        .expect("the CLI key validates on arrival");
    // The one change: a reload drops the CLI key before the handler runs.
    rig.reload_to(&config_text_without_cli("environment: \"b\"\n"))
        .await;
    assert!(
        rig.state
            .live_config
            .generation()
            .auth()
            .validate_token(CLI)
            .is_none(),
        "the premise: the live table no longer knows the CLI key"
    );
    let before = rig.bytes();
    rig.steps();
    let request = Request::builder()
        .method("POST")
        .uri(routes::UI_CONFIG_RESTORE)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({ "version": old }).to_string(),
        ))
        .expect("a request");
    let body = Json::<RestoreBody>::from_request(request, &()).await;
    let guard = Guard::for_route(routes::UI_CONFIG_RESTORE, &Method::POST, Some(cli));
    let answer = restore(
        State(Arc::clone(&rig.state)),
        guard,
        Extension(arrival),
        None,
        body,
    )
    .await;
    let status = answer.status();
    let bytes = axum::body::to_bytes(answer.into_body(), 1 << 16)
        .await
        .expect("the body reads");
    let got: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(
        (status, got),
        (
            StatusCode::FORBIDDEN,
            json!({ "error": "Authentication required" })
        )
    );
    assert_eq!(rig.bytes(), before);
    assert!(rig.rejected().is_empty());
    assert!(rig.steps().is_empty());
}
