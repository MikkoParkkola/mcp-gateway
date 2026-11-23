// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reproduction probe, never shipped: one changed capability whose file the
//! gateway can no longer read takes the decision list, the count and every
//! resolve down to "unavailable". It asserts today's behaviour on purpose.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{Method, StatusCode};
use axum::response::Response;
use serde_json::Value;

use super::*;
use crate::capability::hash::{compute_capability_hash, rewrite_with_pin};
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::config::AuthConfig;
use crate::gateway::auth::AuthenticatedClient;

const SPEC: &str = "name: probed\ndescription: As first loaded\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.com\n      path: /v1\n";

/// An admin bearer for the two read routes.
fn operator() -> AuthenticatedClient {
    AuthenticatedClient {
        admin: true,
        authenticated: true,
        name: "onefile-probe".to_owned(),
        principal: crate::gateway::auth::principal_of("onefile-probe-secret"),
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
        quota_principal: None,
        backends: vec!["*".to_owned()],
        denied_tools: None,
        allowed_tools: None,
        rate_limit: 0,
    }
}

/// A route's status and its JSON (null when it sent none).
async fn decoded(reply: Response) -> (StatusCode, Value) {
    let code = reply.status();
    let raw = axum::body::to_bytes(reply.into_body(), usize::MAX)
        .await
        .expect("the reply body reads");
    (code, serde_json::from_slice(&raw).unwrap_or_default())
}

async fn listed(state: &Arc<AppState>) -> (StatusCode, Value) {
    let guard = Guard::for_route(routes::UI_DECISIONS, &Method::GET, Some(operator()));
    decoded(list_decisions(State(Arc::clone(state)), guard).await).await
}

async fn counted(state: &Arc<AppState>) -> (StatusCode, Value) {
    let guard = Guard::for_route(routes::UI_DECISIONS_COUNT, &Method::GET, Some(operator()));
    decoded(count_decisions(State(Arc::clone(state)), guard).await).await
}

/// Poll the list until `want` holds; a generous bound, never the first try.
async fn until(state: &Arc<AppState>, want: impl Fn(StatusCode, &Value) -> bool) -> (StatusCode, Value) {
    let give_up = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let (code, body) = listed(state).await;
        if want(code, &body) {
            return (code, body);
        }
        assert!(tokio::time::Instant::now() < give_up, "never: {code} {body}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(unix)]
#[tokio::test]
async fn probe_one_unreadable_changed_file_takes_list_count_and_resolve_down() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = crate::test_dir_keep::kept_tempdir();
    let file = dir.path().join("probed.yaml");
    let pinned = rewrite_with_pin(SPEC, &compute_capability_hash(SPEC));
    std::fs::write(&file, &pinned).expect("the capability file");
    let backend = Arc::new(CapabilityBackend::new("probe", Arc::new(CapabilityExecutor::new())));
    backend
        .load_from_directory(dir.path().to_str().expect("a utf-8 dir"))
        .await
        .expect("it loads");
    // Its bytes change: one recorded pin mismatch.
    std::fs::write(&file, pinned.replace("As first loaded", "Changed since")).expect("changed");
    assert_eq!(backend.detect_rug_pulls().await.len(), 1);

    // An access log of its own, so the access source reports as it does live.
    let logged = crate::security::TransparencyLogConfig {
        path: dir.path().join("probe-access.jsonl").to_string_lossy().into_owned(),
        enabled: true,
        key_id: "onefile-probe".into(),
        ..crate::security::TransparencyLogConfig::default()
    };
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(logged)).expect("the probe's log"),
    );
    let held = Arc::clone(&backend);
    let (state, _fixture) = crate::gateway::router::tests::audience_state(
        &AuthConfig::default(),
        (None, None),
        move |mut meta| {
            *meta.capabilities.write() = Some(held);
            meta.transparency_logger = Some(log);
            meta
        },
    )
    .await;
    let (_stop, shutdown) = tokio::sync::broadcast::channel(1);
    let _tick = start(&state.meta_mcp, None, shutdown, state.control_plane_store.clone());

    // Control: readable, the change is listed and the list answers.
    let (_, body) = until(&state, |code, body| {
        code == StatusCode::OK
            && body["decisions"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item["kind"] == "capability_changed"))
    })
    .await;
    println!("PROBE readable: {body}");

    // The one change: the file can no longer be read.
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
    let (code, body) = until(&state, |code, _| code != StatusCode::OK).await;
    let (count_code, count_body) = counted(&state).await;
    let lookup = state
        .meta_mcp
        .decisions()
        .expect("the decision set")
        .request("any-open-id")
        .err();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("chmod back");
    println!("PROBE list: {code} {body}");
    println!("PROBE count: {count_code} {count_body}");
    println!("PROBE resolve lookup refused for: {lookup:?}");
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"], "decisions_unavailable", "{body}");
    assert_eq!(count_code, StatusCode::SERVICE_UNAVAILABLE, "{count_body}");
    assert!(
        lookup.is_some_and(|sources| sources.contains(&("capability_changes", "unreadable"))),
        "every resolve answers 503"
    );
}
