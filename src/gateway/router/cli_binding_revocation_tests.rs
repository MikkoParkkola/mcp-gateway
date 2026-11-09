// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R1: authoritative root removal with its CLI child still configured.
use super::live_keys_tests::{reload_text, status};
use crate::config::{ApiKeyBinding, ApiKeyConfig, AuthConfig, EventsConfig};
use crate::gateway::auth::{KeyBinding, live};
use axum::http::StatusCode;
use std::sync::Arc;

pub(super) const CHILD: &str = "r1-cli-child";
const ROOT: &str = "r1-root";
const OTHER: &str = "r1-root-b";
const OLD: &str = "r1-child-previous";

pub(super) async fn fixture() -> (
    Arc<super::AppState>,
    super::tests::FixtureDir,
    tempfile::TempDir,
    Vec<ApiKeyConfig>,
) {
    let key = |secret: &str| ApiKeyConfig {
        name: secret.into(),
        admin: true,
        backends: vec!["*".into()],
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        ..Default::default()
    };
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![key(ROOT), key(OTHER)],
        ..Default::default()
    };
    let (state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let root = state
        .live_config
        .generation()
        .auth()
        .validate_token(ROOT)
        .expect("root");
    let mut child = key(CHILD);
    child.approved_by = Some(ApiKeyBinding {
        quota_principal: root
            .quota_principal
            .expect("quota")
            .limit_store_key()
            .to_owned(),
        digest_tag: crate::gateway::auth::secret_tag(ROOT),
    });
    child.cli_host = Some("laptop".into());
    child.previous_key_sha256 = Some(crate::config::api_key_digest_spec(OLD.as_bytes()));
    child.previous_expires_at = Some("2999-01-01T00:00:00Z".parse().expect("time"));
    let keys = vec![auth.api_keys[0].clone(), auth.api_keys[1].clone(), child];
    let dir = tempfile::tempdir().expect("dir");
    reload(&state, dir.path(), &keys).await;
    (state, store, dir, keys)
}

async fn reload(state: &Arc<super::AppState>, dir: &std::path::Path, keys: &[ApiKeyConfig]) {
    let text = serde_json::json!({"auth": {"enabled": true, "api_keys": keys}}).to_string();
    reload_text(state, dir, text).await; // Reuses the K5 owner-only file/reload harness; JSON is YAML.
}

pub(super) async fn remove_root(
    state: &Arc<super::AppState>,
    dir: &std::path::Path,
    keys: &[ApiKeyConfig],
) {
    reload(state, dir, &keys[1..]).await;
}

#[tokio::test]
async fn child_previous_secret_is_refused_after_root_removal() {
    let (state, _store, dir, keys) = fixture().await;
    assert_eq!(status(&state, "/mcp", OLD).await, StatusCode::OK);
    remove_root(&state, dir.path(), &keys).await;
    assert_eq!(status(&state, "/mcp", OLD).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_held_watch_of_the_child_ends_at_its_next_poll() {
    let (state, _store, dir, keys) = fixture().await;
    let principal = crate::gateway::auth::principal_of(CHILD)
        .storage_form()
        .to_owned();
    let tag = crate::gateway::auth::secret_tag(CHILD);
    // Reuses auth_approval_binding_tests' watch binding harness at the real poll resolver.
    let poll = || {
        state.live_config.generation().auth().client_for_key(
            CHILD,
            &principal,
            KeyBinding::Secret(&tag),
        )
    };
    assert!(poll().is_some(), "watch opens while root is live");
    remove_root(&state, dir.path(), &keys).await;
    assert!(poll().is_none(), "next watch poll must refuse");
}

#[tokio::test]
async fn a_queued_task_of_the_child_does_not_run() {
    let (state, _store, dir, keys) = fixture().await;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Bearer {CHILD}").parse().expect("header"),
    );
    let held = live::held_credential(&headers);
    let auth = super::build_auth_state(&state);
    // Reuses the router audience_owner held-credential harness at the pre-work authorization seam.
    assert!(live::current_client(&auth, held.as_ref()).await.is_some());
    remove_root(&state, dir.path(), &keys).await;
    assert!(live::current_client(&auth, held.as_ref()).await.is_none());
}

#[tokio::test]
async fn event_admission_and_admin_standing_end_with_the_root() {
    use crate::events::{EventSource, EventsHub, LiveCredentials};
    let (state, _store, dir, keys) = fixture().await;
    let services = || {
        state
            .meta_mcp
            .events_services(Arc::clone(&state.live_config), LiveCredentials::default())
    };
    let hub_dir = Arc::new(tempfile::tempdir().expect("events dir"));
    let hub = EventsHub::open(&EventsConfig::default(), hub_dir.path()).expect("hub");
    hub.keep_test_dir(hub_dir);
    hub.start(services());
    let source = hub.install_operational_source(
        &crate::kill_switch::KillSwitch::new(),
        &state.backends,
        None,
    );
    let principal = crate::gateway::auth::principal_of(CHILD)
        .storage_form()
        .to_owned();
    let watch = crate::events::ApiKeyRef {
        name: CHILD.into(),
        principal: principal.clone(),
        digest_tag: Some(crate::gateway::auth::secret_tag(CHILD)),
    };
    let args = serde_json::json!({});
    // Reuses operational_source_tests' EventSource authorization and K5's event admission harness.
    assert!(services().admits(Some(&watch), "x"));
    assert!(
        source
            .authorize(&principal, "gateway.kill_switch.changed", &args)
            .await
            .is_ok()
    );
    remove_root(&state, dir.path(), &keys).await;
    let admitted = services().admits(Some(&watch), "x");
    let standing = source
        .authorize(&principal, "gateway.kill_switch.changed", &args)
        .await;
    assert!(
        !admitted && standing.is_err(),
        "event admission or admin standing survived"
    );
}

#[tokio::test]
async fn an_unrelated_root_stays_usable() {
    let (state, _store, dir, keys) = fixture().await;
    assert_eq!(status(&state, "/mcp", OTHER).await, StatusCode::OK);
    remove_root(&state, dir.path(), &keys).await;
    assert_eq!(
        status(&state, "/mcp", CHILD).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(status(&state, "/mcp", OTHER).await, StatusCode::OK);
}

#[tokio::test]
async fn removal_survives_a_clock_rolled_back() {
    let _clock = crate::clock::test_clock::at_secs(1_900_000_000);
    let (state, _store, dir, keys) = fixture().await;
    assert_eq!(status(&state, "/mcp", CHILD).await, StatusCode::OK);
    remove_root(&state, dir.path(), &keys).await;
    let _earlier = crate::clock::test_clock::at_secs(1_800_000_000);
    for secret in [CHILD, OLD] {
        assert_eq!(
            status(&state, "/mcp", secret).await,
            StatusCode::UNAUTHORIZED
        );
    }
}
