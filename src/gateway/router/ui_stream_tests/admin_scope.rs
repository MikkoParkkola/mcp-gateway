// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stream's admin parts are gateway-wide: an admin key scoped to some
//! backends is offered no `reload` kind and is sent the counts-only status
//! view, through the real stream; an admin key holding every backend gets both.

use super::*;

const ALL: &str = "u3-admin-every-backend";
const EMPTY: &str = "u3-admin-no-backends";
const SCOPED: &str = "u3-admin-docs-only";

fn admin_key(key: &str, backends: &[&str]) -> ApiKeyConfig {
    ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(key.as_bytes())),
        name: key.to_string(),
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        admin: true,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

/// The first `hello` and `status` frames `key` is sent: whether `reload` is
/// offered, and whether the status is the full view, a `servers` list naming
/// `docs`. Either view carries the counts.
async fn admin_parts(state: &Arc<AppState>, key: &str) -> (bool, bool) {
    let mut s = open(state, request(STREAM, Who::Bearer(key), None)).await;
    assert_eq!(s.status, StatusCode::OK, "{key} opens the stream");
    let hello = s.until("hello").await.json();
    let reload = hello["kinds"]
        .as_array()
        .expect("hello names its kinds")
        .iter()
        .any(|k| k == "reload");
    let status = s.until("status").await.json();
    assert!(
        status["server_count"].is_u64(),
        "{key}: the status carries its counts: {status}"
    );
    let full = match status.get("servers") {
        None => false,
        Some(servers) => {
            let names: Vec<&str> = servers
                .as_array()
                .expect("a servers list")
                .iter()
                .filter_map(|s| s["name"].as_str())
                .collect();
            assert!(
                names.contains(&"docs"),
                "{key}: the full view names docs: {status}"
            );
            true
        }
    };
    (reload, full)
}

#[tokio::test]
async fn the_stream_gives_a_backend_scoped_admin_no_admin_view() {
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![
            admin_key(ALL, &["*"]),
            admin_key(EMPTY, &[]),
            admin_key(SCOPED, &["docs"]),
            standard_key(),
        ],
        ..AuthConfig::default()
    };
    let (state, _dir) = test_router_app_state_with_auth_and_key_server(&auth, None).await;
    let _ = state
        .backends
        .register(http_backend_at("docs", "http://127.0.0.1:9/mcp"));
    tokio::time::pause();
    assert_eq!(
        admin_parts(&state, ALL).await,
        (true, true),
        "control: an admin key holding every backend gets reload and the full view"
    );
    assert_eq!(
        admin_parts(&state, EMPTY).await,
        (true, true),
        "an admin key with no backends is a gateway-wide admin"
    );
    assert_eq!(
        admin_parts(&state, SCOPED).await,
        (false, false),
        "an admin key scoped to docs gets neither reload nor the full view"
    );
    assert_eq!(
        admin_parts(&state, KEY).await,
        (false, false),
        "a standard key gets neither"
    );
}
