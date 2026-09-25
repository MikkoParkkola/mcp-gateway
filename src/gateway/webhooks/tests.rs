// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::sync::Arc;

use axum::body::to_bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde_json::{Value, json};

use super::*;
use crate::backend::BackendRegistry;
use crate::capability::{WebhookDefinition, WebhookTransform};
use crate::config::{StreamingConfig, WebhookConfig};
use crate::gateway::streaming::NotificationMultiplexer;

// ── helpers ───────────────────────────────────────────────────────────

fn make_multiplexer() -> Arc<NotificationMultiplexer> {
    Arc::new(NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        StreamingConfig::default(),
    ))
}

fn make_definition(notify: bool) -> WebhookDefinition {
    WebhookDefinition {
        path: "/test".to_string(),
        method: "POST".to_string(),
        secret: None,
        signature_header: None,
        notify,
        transform: WebhookTransform::default(),
    }
}

fn make_handler_state(
    multiplexer: Arc<NotificationMultiplexer>,
    definition: WebhookDefinition,
) -> WebhookHandlerState {
    WebhookHandlerState {
        multiplexer,
        capability_name: "test_cap".to_string(),
        webhook_name: "test_hook".to_string(),
        definition,
        config: WebhookConfig {
            require_signature: false,
            ..WebhookConfig::default()
        },
        stats: Arc::new(EndpointStats::default()),
        env: Arc::new(crate::config::LiveEnv::default()),
        backend: "capabilities".to_string(),
    }
}

// ── extract_json_path ─────────────────────────────────────────────────

#[test]
fn extract_json_path_nested_field_returns_value() {
    // GIVEN: nested JSON with path data.issue.id
    // WHEN: extracting that path
    // THEN: returns the correct leaf value
    let payload = json!({
        "data": { "issue": { "id": "123", "title": "Bug fix" } },
        "action": "update"
    });

    assert_eq!(
        extract_json_path("data.issue.id", &payload),
        Some(&json!("123"))
    );
    assert_eq!(
        extract_json_path("action", &payload),
        Some(&json!("update"))
    );
}

#[test]
fn extract_json_path_missing_field_returns_none() {
    // GIVEN: JSON without the requested field
    // WHEN: extracting a non-existent path
    // THEN: returns None
    let payload = json!({ "data": {} });
    assert_eq!(extract_json_path("nonexistent", &payload), None);
    assert_eq!(extract_json_path("data.missing.deep", &payload), None);
}

#[test]
fn extract_json_path_array_index_access() {
    // GIVEN: JSON with an array
    // WHEN: extracting by numeric index
    // THEN: returns the correct element
    let payload = json!({ "items": ["a", "b", "c"] });
    assert_eq!(extract_json_path("items.1", &payload), Some(&json!("b")));
}

// ── extract_template_value ────────────────────────────────────────────

#[test]
fn extract_template_value_single_placeholder_substituted() {
    // GIVEN: template with one placeholder
    // WHEN: the field exists in payload
    // THEN: placeholder is replaced with field value
    let payload = json!({ "data": { "id": "456" }, "action": "created" });
    let result = extract_template_value("linear.issue.{action}", &payload).unwrap();
    assert_eq!(result, "linear.issue.created");
}

#[test]
fn extract_template_value_nested_path_substituted() {
    // GIVEN: template referencing a nested field
    // WHEN: the nested field exists
    // THEN: substitution succeeds
    let payload = json!({ "data": { "id": "456" }, "action": "created" });
    let result = extract_template_value("ID: {data.id}", &payload).unwrap();
    assert_eq!(result, "ID: 456");
}

#[test]
fn extract_template_value_missing_path_returns_error() {
    // GIVEN: template referencing a missing field
    // WHEN: the field does not exist
    // THEN: returns Err
    let payload = json!({ "action": "created" });
    let result = extract_template_value("{missing.field}", &payload);
    assert!(result.is_err());
}

#[test]
fn extract_template_value_no_placeholders_returned_as_is() {
    // GIVEN: template with no placeholders
    // WHEN: extracting
    // THEN: returns the template string unchanged
    let payload = json!({});
    let result = extract_template_value("static.event.type", &payload).unwrap();
    assert_eq!(result, "static.event.type");
}

// ── constant_time_eq ──────────────────────────────────────────────────

#[test]
fn constant_time_eq_equal_slices_returns_true() {
    assert!(constant_time_eq(b"hello", b"hello"));
}

#[test]
fn constant_time_eq_different_content_returns_false() {
    assert!(!constant_time_eq(b"hello", b"world"));
}

#[test]
fn constant_time_eq_different_length_returns_false() {
    assert!(!constant_time_eq(b"hello", b"hell"));
}

// ── transform_payload ─────────────────────────────────────────────────

#[test]
fn transform_payload_no_transform_uses_full_payload() {
    // GIVEN: definition with no transform fields
    // WHEN: transforming a payload
    // THEN: data field is the entire payload
    let multiplexer = make_multiplexer();
    let def = make_definition(true);
    let state = make_handler_state(multiplexer, def);
    let payload = json!({ "action": "created", "data": { "id": "1" } });

    let notif = transform_payload(&payload, &state).unwrap();
    assert_eq!(notif.source, "test_cap");
    assert_eq!(notif.event_type, "webhook.test_cap.test_hook");
    assert_eq!(notif.data, payload);
}

#[test]
fn transform_payload_with_event_type_template() {
    // GIVEN: definition with event_type template referencing payload field
    // WHEN: transforming a payload that contains {action}
    // THEN: event_type is substituted correctly
    let multiplexer = make_multiplexer();
    let mut def = make_definition(true);
    def.transform.event_type = Some("linear.issue.{action}".to_string());
    let state = make_handler_state(multiplexer, def);
    let payload = json!({ "action": "update" });

    let notif = transform_payload(&payload, &state).unwrap();
    assert_eq!(notif.event_type, "linear.issue.update");
}

#[test]
fn transform_payload_with_data_mapping() {
    // GIVEN: definition with data field mappings
    // WHEN: payload contains the mapped fields
    // THEN: transformed data contains only the mapped keys
    let multiplexer = make_multiplexer();
    let mut def = make_definition(true);
    def.transform
        .data
        .insert("issue_id".to_string(), "{data.id}".to_string());
    def.transform
        .data
        .insert("action".to_string(), "{action}".to_string());
    let state = make_handler_state(multiplexer, def);
    let payload = json!({ "action": "created", "data": { "id": "ABC-123" } });

    let notif = transform_payload(&payload, &state).unwrap();
    assert_eq!(notif.data["issue_id"], "ABC-123");
    assert_eq!(notif.data["action"], "created");
}

// ── WebhookRegistry ───────────────────────────────────────────────────

fn make_capability_with_webhooks(
    name: &str,
    webhook_paths: &[(&str, &str, bool)],
) -> crate::capability::CapabilityDefinition {
    use crate::capability::{
        AuthConfig, CacheConfig, CapabilityDefinition, CapabilityMetadata, ProvidersConfig,
        SchemaDefinition, WebhookDefinition, WebhookTransform,
    };
    use crate::transform::TransformConfig;
    use std::collections::HashMap;

    let mut webhooks = HashMap::new();
    for (wname, wpath, notify) in webhook_paths {
        webhooks.insert(
            (*wname).to_string(),
            WebhookDefinition {
                path: (*wpath).to_string(),
                method: "POST".to_string(),
                secret: None,
                signature_header: None,
                notify: *notify,
                transform: WebhookTransform::default(),
            },
        );
    }

    CapabilityDefinition {
        fulcrum: "1.0".to_string(),
        name: name.to_string(),
        description: "Test capability".to_string(),
        schema: SchemaDefinition::default(),
        providers: ProvidersConfig::default(),
        auth: AuthConfig::default(),
        cache: CacheConfig::default(),
        metadata: CapabilityMetadata::default(),
        transform: TransformConfig::default(),
        response_transform: TransformConfig::default(),
        projection: None,
        visible_in_states: vec![],
        webhooks,
        sha256: None,
    }
}

#[test]
fn registry_endpoint_count_reflects_registered_capabilities() {
    // GIVEN: a fresh registry and a capability with two webhooks
    // WHEN: registering the capability
    // THEN: endpoint_count returns 2
    let mut registry = WebhookRegistry::new(WebhookConfig::default());
    let cap = make_capability_with_webhooks(
        "test_cap",
        &[("hook1", "/hook1", true), ("hook2", "/hook2", false)],
    );
    registry.register_capability(&cap);
    assert_eq!(registry.endpoint_count(), 2);
}

#[test]
fn registry_list_endpoints_sorted_by_path() {
    // GIVEN: registry with endpoints at /z/hook and /a/hook
    // WHEN: listing endpoints
    // THEN: returned in ascending path order
    let mut registry = WebhookRegistry::new(WebhookConfig::default());
    let cap = make_capability_with_webhooks(
        "cap",
        &[("z_hook", "/z/hook", true), ("a_hook", "/a/hook", true)],
    );
    registry.register_capability(&cap);

    let endpoints = registry.list_endpoints();
    assert_eq!(endpoints.len(), 2);
    // The base_path "/webhooks" is prepended; paths must be ascending.
    assert!(endpoints[0].path < endpoints[1].path);
}

// ── EndpointStats ─────────────────────────────────────────────────────

#[test]
fn endpoint_stats_initial_snapshot_all_zeros() {
    // GIVEN: a freshly created EndpointStats
    // WHEN: snapshotting immediately
    // THEN: all counters are zero and last_received_at is None
    let stats = EndpointStats::default();
    let snap = stats.snapshot();
    assert_eq!(snap.received, 0);
    assert_eq!(snap.delivered, 0);
    assert_eq!(snap.signature_failures, 0);
    assert_eq!(snap.transform_failures, 0);
    assert!(snap.last_received_at.is_none());
}

#[test]
fn endpoint_stats_record_received_increments_and_timestamps() {
    // GIVEN: fresh stats
    // WHEN: record_received is called
    // THEN: received == 1 and last_received_at is Some
    let stats = EndpointStats::default();
    stats.record_received();
    let snap = stats.snapshot();
    assert_eq!(snap.received, 1);
    assert!(snap.last_received_at.is_some());
}

#[test]
fn endpoint_stats_delivery_counter_independent_of_received() {
    // GIVEN: fresh stats
    // WHEN: received is called twice and delivered once
    // THEN: counts are tracked independently
    let stats = EndpointStats::default();
    stats.record_received();
    stats.record_received();
    stats.delivered.fetch_add(1, Ordering::Relaxed);
    let snap = stats.snapshot();
    assert_eq!(snap.received, 2);
    assert_eq!(snap.delivered, 1);
}

#[tokio::test]
async fn webhook_handler_invalid_json_returns_flat_bad_request_with_request_id() {
    let multiplexer = make_multiplexer();
    let state = make_handler_state(multiplexer, make_definition(true));

    let response = webhook_handler(
        State(state),
        HeaderMap::new(),
        axum::body::Bytes::from_static(br#"{"broken":"json""#),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|message| message.starts_with("Invalid JSON:"))
    );
    assert!(
        json["request_id"]
            .as_str()
            .is_some_and(|request_id| !request_id.is_empty())
    );
    assert!(json.get("jsonrpc").is_none());
}

#[tokio::test]
async fn webhook_handler_success_returns_received_status_with_request_id() {
    let multiplexer = make_multiplexer();
    let state = make_handler_state(multiplexer, make_definition(true));

    let response = webhook_handler(
        State(state),
        HeaderMap::new(),
        axum::body::Bytes::from_static(br#"{"event":"ok"}"#),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "received");
    assert_eq!(json["notified"], true);
    assert_eq!(json["sessions"], 0);
    assert!(
        json["request_id"]
            .as_str()
            .is_some_and(|request_id| !request_id.is_empty())
    );
    assert!(json.get("jsonrpc").is_none());
}

#[tokio::test]
async fn webhook_handler_invalid_signature_returns_request_scoped_error() {
    let multiplexer = make_multiplexer();
    let mut definition = make_definition(true);
    definition.secret = Some("super-secret".to_string());
    definition.signature_header = Some("X-Signature".to_string());
    let state = make_handler_state(multiplexer, definition);

    let response = webhook_handler(
        State(state),
        HeaderMap::new(),
        axum::body::Bytes::from_static(br#"{"event":"ok"}"#),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "Invalid signature");
    assert!(
        json["request_id"]
            .as_str()
            .is_some_and(|request_id| !request_id.is_empty())
    );
    assert!(json.get("jsonrpc").is_none());
}

#[tokio::test]
async fn webhook_handler_transformation_failure_returns_request_scoped_error() {
    let multiplexer = make_multiplexer();
    let mut definition = make_definition(true);
    definition.transform.event_type = Some("{missing.field}".to_string());
    let state = make_handler_state(multiplexer, definition);

    let response = webhook_handler(
        State(state),
        HeaderMap::new(),
        axum::body::Bytes::from_static(br#"{"event":"ok"}"#),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "Transformation failed");
    assert!(
        json["request_id"]
            .as_str()
            .is_some_and(|request_id| !request_id.is_empty())
    );
    assert!(json.get("jsonrpc").is_none());
}

// ── method_to_filter ──────────────────────────────────────────────────

#[test]
fn method_to_filter_known_methods_mapped_correctly() {
    // GIVEN: valid HTTP method strings
    // WHEN: mapping to MethodFilter
    // THEN: correct filter variants are returned (compile-time check via usage)
    let _ = method_to_filter("GET");
    let _ = method_to_filter("POST");
    let _ = method_to_filter("PUT");
    let _ = method_to_filter("PATCH");
    let _ = method_to_filter("DELETE");
    let _ = method_to_filter("UNKNOWN"); // defaults to POST
}

#[tokio::test]
async fn webhook_handler_rejects_a_secret_that_resolves_to_nothing() {
    // A `{env.VAR}` secret naming an unset variable expands to the empty
    // string. An empty HMAC key is computable by anyone, so a caller can forge
    // a signature the check would otherwise accept.
    let multiplexer = make_multiplexer();
    let mut definition = make_definition(true);
    definition.secret = Some("{env.MIK_7256_WEBHOOK_SECRET_THAT_IS_NEVER_SET}".to_string());
    definition.signature_header = Some("X-Signature".to_string());
    let state = make_handler_state(multiplexer, definition);

    let body = br#"{"event":"forged"}"#;
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(b"").unwrap();
    mac.update(body);
    let forged = hex::encode(mac.finalize().into_bytes());

    let mut headers = HeaderMap::new();
    headers.insert("X-Signature", forged.parse().unwrap());

    let response = webhook_handler(State(state), headers, axum::body::Bytes::from_static(body))
        .await
        .into_response();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_handler_accepts_a_secret_an_env_file_assigns() {
    // Env files load into an in-memory overlay rather than into the process
    // environment, so a `{env.VAR}` secret is only resolvable through that
    // overlay. Without it the secret expands to the empty string and every
    // legitimate signature is rejected.
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join(".env");
    crate::gateway::test_helpers::write_owner_only(
        &env_file,
        "MIK_7256_OVERLAY_SECRET=well-known-test-value\n",
    )
    .unwrap();
    let overlay = crate::config::EnvOverlay::from_paths(&[env_file]);
    let env = Arc::new(crate::config::LiveEnv::new(
        Arc::new(overlay),
        crate::config::ResolvedEnvFiles::default(),
    ));

    let multiplexer = make_multiplexer();
    let mut definition = make_definition(true);
    definition.secret = Some("{env.MIK_7256_OVERLAY_SECRET}".to_string());
    definition.signature_header = Some("X-Signature".to_string());
    let mut state = make_handler_state(multiplexer, definition);
    state.env = env;

    let body = br#"{"event":"legitimate"}"#;
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(b"well-known-test-value").unwrap();
    mac.update(body);
    let signature = hex::encode(mac.finalize().into_bytes());

    let mut headers = HeaderMap::new();
    headers.insert("X-Signature", signature.parse().unwrap());

    let response = webhook_handler(State(state), headers, axum::body::Bytes::from_static(body))
        .await
        .into_response();

    assert_eq!(response.status(), StatusCode::OK);
}

// ── Notification scope ────────────────────────────────────────────────

const AUTH_YAML: &str = "enabled: true
api_keys:
  - key: key-in-scope
    name: in
    backends: [capabilities]
  - key: key-out-of-scope
    name: out
    backends: [other]
";

/// The authorizer the router installs: static keys, plus a key server if given.
fn authorizer(
    key_server: Option<Arc<crate::key_server::KeyServer>>,
) -> crate::gateway::auth::AuthState {
    let config: crate::config::AuthConfig = serde_yaml::from_str(AUTH_YAML).unwrap();
    crate::gateway::auth::AuthState {
        auth_config: Arc::new(crate::gateway::auth::ResolvedAuthConfig::from_config(
            &config,
        )),
        key_server,
        dashboard_bootstrap: Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        tls_enabled: false,
    }
}

/// The credential a request presenting `bearer` leaves on its session.
fn held(bearer: &str) -> Option<crate::gateway::auth::live::HeldCredential> {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {bearer}").parse().unwrap(),
    );
    crate::gateway::auth::live::held_credential(&headers)
}

/// Open a session the way the MCP handler does for a caller presenting `bearer`.
fn open_session(
    multiplexer: &NotificationMultiplexer,
    id: &str,
    bearer: Option<&str>,
) -> tokio::sync::broadcast::Receiver<crate::gateway::streaming::TaggedNotification> {
    let owner = format!("credential:{id}");
    multiplexer
        .get_or_create_session_scoped(Some(id), &owner, bearer.and_then(held))
        .1
}

async fn post_webhook(state: WebhookHandlerState) -> Value {
    let response = webhook_handler(
        State(state),
        HeaderMap::new(),
        axum::body::Bytes::from_static(br#"{"event":"private"}"#),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[test]
fn a_webhook_that_does_not_ask_to_notify_does_not() {
    // Opting in is the only way a webhook payload reaches a session.
    let def: WebhookDefinition = serde_yaml::from_str("path: /linear/webhook").unwrap();
    assert!(!def.notify, "notify must default to false");
}

#[tokio::test]
async fn notify_reaches_only_sessions_whose_caller_may_access_the_backend() {
    let multiplexer = make_multiplexer();
    multiplexer.set_authorizer(authorizer(None));
    let mut rx_in = open_session(&multiplexer, "in", Some("key-in-scope"));
    let mut rx_out = open_session(&multiplexer, "out", Some("key-out-of-scope"));

    post_webhook(make_handler_state(
        Arc::clone(&multiplexer),
        make_definition(true),
    ))
    .await;

    let delivered = rx_in
        .try_recv()
        .expect("an in-scope session receives the event");
    assert_eq!(delivered.data["event"], "private");
    assert!(
        rx_out.try_recv().is_err(),
        "a caller without access to the backend must not receive another integration's payload"
    );
}

#[tokio::test]
async fn notify_skips_a_session_that_presented_no_credential() {
    // With authentication on, no credential means no identity: fail closed.
    let multiplexer = make_multiplexer();
    multiplexer.set_authorizer(authorizer(None));
    let mut rx = open_session(&multiplexer, "bare", None);

    post_webhook(make_handler_state(
        Arc::clone(&multiplexer),
        make_definition(true),
    ))
    .await;

    assert!(
        rx.try_recv().is_err(),
        "a credential-less session must not receive webhook data"
    );
}

#[tokio::test]
async fn notify_delivers_nothing_before_an_authorizer_is_installed() {
    let multiplexer = make_multiplexer();
    let mut rx = open_session(&multiplexer, "early", Some("key-in-scope"));

    post_webhook(make_handler_state(
        Arc::clone(&multiplexer),
        make_definition(true),
    ))
    .await;

    assert!(rx.try_recv().is_err(), "no authorizer means no delivery");
}

// ── Revocation ────────────────────────────────────────────────────────

fn temporary_token(backends: &[&str]) -> crate::key_server::TemporaryToken {
    use crate::key_server::InMemoryTokenStore;
    use crate::key_server::oidc::VerifiedIdentity;
    use crate::key_server::store::TokenScopes;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    crate::key_server::TemporaryToken {
        jti: InMemoryTokenStore::generate_jti(),
        token: InMemoryTokenStore::generate_bearer(),
        identity: VerifiedIdentity {
            subject: "sub".to_string(),
            email: "user@issuer.test".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://issuer.test".to_string(),
        },
        scopes: TokenScopes {
            backends: backends.iter().map(|b| (*b).to_string()).collect(),
            tools: vec![],
            rate_limit: 0,
        },
        iat: now,
        exp: now + 3600,
        client_ip: None,
    }
}

#[tokio::test]
async fn a_session_whose_token_was_revoked_receives_no_webhook_data() {
    let key_server = Arc::new(crate::key_server::KeyServer::new(
        crate::config::KeyServerConfig::default(),
    ));
    let kept = temporary_token(&["capabilities"]);
    let revoked = temporary_token(&["capabilities"]);
    let (kept_bearer, revoked_bearer) = (kept.token.clone(), revoked.token.clone());
    let revoked_jti = revoked.jti.clone();
    key_server.store.insert(kept).await;
    key_server.store.insert(revoked).await;
    let multiplexer = make_multiplexer();
    multiplexer.set_authorizer(authorizer(Some(Arc::clone(&key_server))));
    let mut rx_kept = open_session(&multiplexer, "kept", Some(&kept_bearer));
    let mut rx_revoked = open_session(&multiplexer, "revoked", Some(&revoked_bearer));

    assert!(key_server.store.revoke_by_jti(&revoked_jti).await);
    post_webhook(make_handler_state(
        Arc::clone(&multiplexer),
        make_definition(true),
    ))
    .await;

    assert!(rx_kept.try_recv().is_ok(), "a live token keeps receiving");
    assert!(
        rx_revoked.try_recv().is_err(),
        "a revoked token must not receive webhook data"
    );
}

// ── Dashboard session ─────────────────────────────────────────────────

fn with_session_cookie(handle: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        format!("{}={handle}", crate::gateway::auth::SESSION_COOKIE)
            .parse()
            .unwrap(),
    );
    headers
}

#[tokio::test]
async fn a_dashboard_session_receives_webhook_data_only_on_an_issued_handle() {
    // The middleware admits an issued session cookie on any path, /mcp
    // included, so a stream opened with one is a caller like any other.
    let auth = authorizer(None);
    let handle = auth.dashboard_bootstrap.issue_session();
    let multiplexer = make_multiplexer();
    multiplexer.set_authorizer(auth);
    let held = crate::gateway::auth::live::held_credential;
    let (_, mut rx_issued) = multiplexer.get_or_create_session_scoped(
        Some("dashboard"),
        "credential:dashboard-session",
        held(&with_session_cookie(&handle)),
    );
    let (_, mut rx_forged) = multiplexer.get_or_create_session_scoped(
        Some("forged"),
        "unauthenticated:public",
        held(&with_session_cookie("never-issued")),
    );

    post_webhook(make_handler_state(
        Arc::clone(&multiplexer),
        make_definition(true),
    ))
    .await;

    assert!(
        rx_issued.try_recv().is_ok(),
        "an issued dashboard session is an authenticated caller"
    );
    assert!(
        rx_forged.try_recv().is_err(),
        "a handle this process never issued authenticates nobody"
    );
}
