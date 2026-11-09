// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The API key table applies on reload (ADR-023, amended): a key added,
//! removed or expired by a reload is judged by the next request, on `/mcp`
//! and on `/mcp/{name}`.

use std::sync::Arc;

use axum::http::StatusCode;
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_auth;
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::config_reload::ReloadContext;

const KEPT: &str = "live-keys-kept-secret";
const ADDED: &str = "live-keys-added-secret";

fn key(secret: &str, expires_at: Option<&str>) -> ApiKeyConfig {
    ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        expires_at: expires_at.map(|at| at.parse().expect("an RFC 3339 instant")),
        name: secret.to_owned(),
        backends: vec!["*".to_owned()],
        ..Default::default()
    }
}

fn auth(keys: Vec<ApiKeyConfig>) -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: keys,
        ..AuthConfig::default()
    }
}

/// The YAML for `keys`, as an operator writes it.
fn file_text(keys: &[ApiKeyConfig]) -> String {
    use std::fmt::Write as _;
    let mut text = String::from("auth:\n  enabled: true\n  api_keys:\n");
    for k in keys {
        let digest = k.key_sha256.as_deref().expect("a digest");
        let _ = write!(
            text,
            "    - name: {}\n      key_sha256: \"{digest}\"\n      backends: [\"*\"]\n",
            k.name
        );
        if let Some(at) = k.expires_at {
            let _ = writeln!(text, "      expires_at: \"{}\"", at.to_rfc3339());
        }
        if let Some(principal) = &k.principal {
            let _ = writeln!(text, "      principal: \"{principal}\"");
        }
        if k.kind == crate::config::ApiKeyKind::Personal {
            let _ = writeln!(text, "      kind: personal");
        }
        if let Some(previous) = &k.previous_key_sha256 {
            let _ = writeln!(text, "      previous_key_sha256: \"{previous}\"");
        }
        if let Some(at) = k.previous_expires_at {
            let _ = writeln!(text, "      previous_expires_at: \"{}\"", at.to_rfc3339());
        }
    }
    text
}

/// A reload context over `state`'s live config, reading `path`.
fn reloader(state: &Arc<super::AppState>, path: &std::path::Path) -> ReloadContext {
    ReloadContext::new(
        path.to_path_buf(),
        Arc::clone(&state.live_config),
        Arc::clone(&state.backends),
        crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    )
    .expect("the registry pairs with the config")
}

/// Reload `keys` from a file into `state`.
async fn reload_keys(state: &Arc<super::AppState>, dir: &std::path::Path, keys: &[ApiKeyConfig]) {
    reload_text(state, dir, file_text(keys)).await;
}

/// Reload the config `text` into `state`.
async fn reload_text(state: &Arc<super::AppState>, dir: &std::path::Path, text: String) {
    let path = dir.join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, text).expect("write");
    reloader(state, &path)
        .reload_outcome()
        .await
        .expect("the key edit applies");
}

/// A `ping`: what the K rows send unless they need another method.
fn ping() -> serde_json::Value {
    serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})
}

/// `body` with `secret` on `path`, through `router`.
async fn send(
    router: &axum::Router,
    path: &str,
    secret: &str,
    body: &serde_json::Value,
) -> axum::http::Response<axum::body::Body> {
    let request = axum::http::Request::post(path)
        .header("authorization", format!("Bearer {secret}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    router.clone().oneshot(request).await.expect("a response")
}

/// The status `secret` gets on `path` (the body is left unread: an accepted
/// call may answer with a stream).
async fn status(state: &Arc<super::AppState>, path: &str, secret: &str) -> StatusCode {
    send(&create_router(Arc::clone(state)), path, secret, &ping())
        .await
        .status()
}

/// The status and body of a legacy `initialize` that declares elicitation,
/// with `secret`: under `security.posture: hardened` the identity check is then
/// the only one that can refuse it (an undeclared elicitation is refused too),
/// and a caller that passes it is served 200.
async fn hardened_initialize(state: &Arc<super::AppState>, secret: &str) -> (StatusCode, String) {
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {"elicitation": {}},
        "clientInfo": {"name": "live-keys-kind", "version": "1"}
    }});
    let response = send(&create_router(Arc::clone(state)), "/mcp", secret, &body).await;
    let status = response.status();
    // A served initialize may answer with a stream: read the body of a
    // refusal only.
    if status == StatusCode::OK {
        return (status, String::new());
    }
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// K1: a key added by reload is accepted on the next call, on `/mcp` and on
/// `/mcp/{name}`; the kept key still works (control).
#[tokio::test]
async fn k1_a_key_added_by_reload_is_accepted_on_the_next_call() {
    let (state, _store) = test_router_app_state_with_auth(&auth(vec![key(KEPT, None)])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    for path in ["/mcp", "/mcp/absent"] {
        assert_eq!(
            status(&state, path, ADDED).await,
            StatusCode::UNAUTHORIZED,
            "{path}: precondition, the new key is unknown before the reload"
        );
    }

    reload_keys(&state, dir.path(), &[key(KEPT, None), key(ADDED, None)]).await;

    for path in ["/mcp", "/mcp/absent"] {
        for (secret, what) in [(ADDED, "a key added by reload"), (KEPT, "the kept key")] {
            let got = status(&state, path, secret).await;
            // Accepted means past authentication: neither refused nor a
            // server error, which would also not be a 401.
            assert!(
                got != StatusCode::UNAUTHORIZED && !got.is_server_error(),
                "{path}: {what} was not accepted: {got}"
            );
        }
    }
}

/// K2: a key removed by reload is refused on the next call, and a key whose
/// `expires_at` moves into the past is refused as expired.
#[tokio::test]
async fn k2_a_key_removed_or_expired_by_reload_is_refused_on_the_next_call() {
    let (state, _store) =
        test_router_app_state_with_auth(&auth(vec![key(KEPT, None), key(ADDED, None)])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    for secret in [KEPT, ADDED] {
        let got = status(&state, "/mcp", secret).await;
        assert!(
            accepted(got),
            "precondition: {secret} works before the reload: {got}"
        );
    }

    // ADDED removed; KEPT now expired.
    reload_keys(
        &state,
        dir.path(),
        &[key(KEPT, Some("2001-01-01T00:00:00Z"))],
    )
    .await;

    for path in ["/mcp", "/mcp/absent"] {
        assert_eq!(
            status(&state, path, ADDED).await,
            StatusCode::UNAUTHORIZED,
            "{path}: a key removed by reload still works"
        );
        assert_eq!(
            status(&state, path, KEPT).await,
            StatusCode::UNAUTHORIZED,
            "{path}: a key expired by reload still works"
        );
    }
}

/// The no-pin refusal (`UNPINNED`, a 500) is unreachable from a request: the
/// router pins a generation on every route it owns and on its fallback before
/// anything reads keys. Every owned path, an unowned one, three methods,
/// with a key and without.
#[tokio::test]
async fn no_request_through_the_router_reaches_the_no_pin_refusal() {
    let (state, _store) = test_router_app_state_with_auth(&auth(vec![key(KEPT, None)])).await;
    let mut paths: Vec<String> = crate::gateway::routes::OWNED
        .iter()
        .map(|path| {
            path.split('/')
                .map(|segment| {
                    if segment.starts_with('{') {
                        "x"
                    } else {
                        segment
                    }
                })
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect();
    paths.push("/no-such-route".to_owned());
    for path in &paths {
        for method in ["GET", "POST", "DELETE"] {
            for secret in [Some(KEPT), None] {
                let mut request = axum::http::Request::builder()
                    .method(method)
                    .uri(path.as_str())
                    .header("content-type", "application/json");
                if let Some(secret) = secret {
                    request = request.header("authorization", format!("Bearer {secret}"));
                }
                let response = create_router(Arc::clone(&state))
                    .oneshot(
                        request
                            .body(axum::body::Body::from("{}"))
                            .expect("a request"),
                    )
                    .await
                    .expect("a response");
                // The refusal is a 500; anything else (a stream included,
                // whose body never ends) is not it.
                if response.status() != StatusCode::INTERNAL_SERVER_ERROR {
                    continue;
                }
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .expect("a body");
                assert!(
                    !String::from_utf8_lossy(&body).contains(super::UNPINNED),
                    "{method} {path} (key: {}) reached the no-pin refusal",
                    secret.is_some()
                );
            }
        }
    }
}

const ROTATED: &str = "live-keys-rotated-secret";

/// K5 `key_sha256` (MIK-9255.IDENT.1): a kept key whose digest a reload
/// changes accepts the new secret and refuses the old one on the next call.
#[tokio::test]
async fn k5_a_key_digest_changed_by_reload_applies_on_the_next_call() {
    let (state, _store) = test_router_app_state_with_auth(&auth(vec![key(KEPT, None)])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    assert_ne!(
        status(&state, "/mcp", KEPT).await,
        StatusCode::UNAUTHORIZED,
        "precondition: the key works before the reload"
    );

    let built_before = create_router(Arc::clone(&state));
    let rotated = ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(ROTATED.as_bytes())),
        ..key(KEPT, None)
    };
    reload_keys(&state, dir.path(), &[rotated]).await;

    // Through a router built before the reload, too: one that captured the
    // key table when it was built would still judge by the old one.
    for (router, which) in [
        (built_before, "the router built before the reload"),
        (create_router(Arc::clone(&state)), "a router built after it"),
    ] {
        let got = send(&router, "/mcp", ROTATED, &ping()).await.status();
        assert!(
            got != StatusCode::UNAUTHORIZED && !got.is_server_error(),
            "{which}: the new digest was not accepted: {got}"
        );
        assert_eq!(
            send(&router, "/mcp", KEPT, &ping()).await.status(),
            StatusCode::UNAUTHORIZED,
            "{which}: the old digest still works after the reload"
        );
    }
}

/// K5 `previous_key_sha256` with `previous_expires_at` (MIK-9255.IDENT.3): a
/// rotation written by reload accepts the previous secret while its grace
/// runs, and a second reload that ends the grace refuses it.
#[tokio::test]
async fn k5_a_rotation_written_by_reload_honours_its_grace() {
    let (state, _store) = test_router_app_state_with_auth(&auth(vec![key(KEPT, None)])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let rotation = |previous_expires_at: &str| ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(ROTATED.as_bytes())),
        previous_key_sha256: Some(crate::config::api_key_digest_spec(KEPT.as_bytes())),
        previous_expires_at: Some(previous_expires_at.parse().expect("an RFC 3339 instant")),
        ..key(KEPT, None)
    };

    reload_keys(&state, dir.path(), &[rotation("2999-01-01T00:00:00Z")]).await;
    for (secret, what) in [
        (ROTATED, "the new secret"),
        (KEPT, "the previous secret in its grace"),
    ] {
        let got = status(&state, "/mcp", secret).await;
        assert!(
            got != StatusCode::UNAUTHORIZED && !got.is_server_error(),
            "{what} was not accepted: {got}"
        );
    }

    reload_keys(&state, dir.path(), &[rotation("2000-01-01T00:00:00Z")]).await;
    assert_eq!(
        status(&state, "/mcp", KEPT).await,
        StatusCode::UNAUTHORIZED,
        "the previous secret still works after its grace ended"
    );
    let got = status(&state, "/mcp", ROTATED).await;
    assert!(
        got != StatusCode::UNAUTHORIZED && !got.is_server_error(),
        "the new secret stopped working: {got}"
    );
}

const OPS_PRINCIPAL: &str = "0a1b2c3d4e5f";
const OPS_WINDOW: u32 = 5;
/// When the rotated key's previous digest stops working, in seconds after
/// the epoch.
const GRACE_ENDS: u64 = 1_900_000_000;

/// The `ops` key holding `secret`, under an explicit principal and a window
/// of `OPS_WINDOW` calls a minute.
fn ops_key(secret: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        name: "ops".to_owned(),
        principal: Some(OPS_PRINCIPAL.to_owned()),
        rate_limit: OPS_WINDOW,
        ..key(secret, None)
    }
}

/// The file that rotates `ops` from `KEPT` to `ROTATED`, the old digest kept
/// until `GRACE_ENDS`, as an operator writes it.
fn ops_rotation_text() -> String {
    let ends = chrono::DateTime::from_timestamp(i64::try_from(GRACE_ENDS).expect("fits"), 0)
        .expect("an instant")
        .to_rfc3339();
    let digest = |secret: &str| crate::config::api_key_digest_spec(secret.as_bytes());
    format!(
        "auth:\n  enabled: true\n  api_keys:\n    - name: ops\n      key_sha256: \"{}\"\n      \
         previous_key_sha256: \"{}\"\n      previous_expires_at: \"{ends}\"\n      \
         principal: \"{OPS_PRINCIPAL}\"\n      rate_limit: {OPS_WINDOW}\n      backends: [\"*\"]\n",
        digest(ROTATED),
        digest(KEPT),
    )
}

/// What the live table makes of `secret`: the caller's principal, then its
/// quota principal's limit key and store key.
fn ops_identity(state: &Arc<super::AppState>, secret: &str) -> [String; 3] {
    let generation = state.live_config.generation();
    let client = generation
        .auth()
        .validate_token(secret)
        .expect("the secret authenticates");
    let quota = client.quota_principal.expect("an API key has a quota");
    [
        client.principal.storage_form().to_owned(),
        quota.limit_store_key().to_owned(),
        quota.as_store_key().to_owned(),
    ]
}

/// Spend one call of `secret`'s window on the live table; false when refused.
fn spend_one(state: &Arc<super::AppState>, secret: &str) -> bool {
    let generation = state.live_config.generation();
    let auth = generation.auth();
    let client = auth
        .validate_token(secret)
        .expect("the secret authenticates");
    auth.check_authenticated_client_rate_limit(&client)
}

/// Whether `got` is a call the key table let through and the window served:
/// only a 2xx. A 429 or any other refusal (400, 403, 404) is never an
/// admission, so a precondition cannot pass on the wrong refusal.
fn accepted(got: StatusCode) -> bool {
    got.is_success()
}

/// `accepted` admits only a served call. A ping is answered
/// `JsonRpcResponse::success` (handlers.rs, the `"ping"` arm), a 2xx, so a
/// 400, 403 or 404 is a refusal the "works" preconditions must not pass.
#[test]
fn accepted_admits_only_a_served_call() {
    assert!(accepted(StatusCode::OK));
    for refused in [
        StatusCode::BAD_REQUEST,
        StatusCode::UNAUTHORIZED,
        StatusCode::FORBIDDEN,
        StatusCode::NOT_FOUND,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::INTERNAL_SERVER_ERROR,
    ] {
        assert!(!accepted(refused), "{refused} was taken as served");
    }
}

/// K2: what K5 leaves unproven is the identity across a rotation. A key with
/// an explicit `principal` that a reload rotates (new digest, the old one kept
/// as `previous_key_sha256` with `previous_expires_at`) is accepted on both
/// digests while the injected clock reads before the previous expiry, with no
/// second reload, and on the new one only once it reads the expiry. The
/// principal, the quota's limit key and the spent part of the window carry
/// across; the digest-bound store key is the one thing that changes.
#[tokio::test]
async fn k2_an_explicit_principal_rotation_by_reload_keeps_identity_and_window() {
    let _clock = crate::clock::test_clock::at_secs(GRACE_ENDS - 1);
    let (state, _store) = test_router_app_state_with_auth(&auth(vec![ops_key(KEPT)])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let before = ops_identity(&state, KEPT);
    assert_eq!(before[0], OPS_PRINCIPAL, "premise: the explicit principal");
    assert!(
        spend_one(&state, KEPT) && spend_one(&state, KEPT),
        "premise"
    );

    reload_text(&state, dir.path(), ops_rotation_text()).await;

    for (secret, what) in [(ROTATED, "the new digest"), (KEPT, "the old digest")] {
        let got = status(&state, "/mcp", secret).await;
        assert!(accepted(got), "{what} before the grace ends: {got}");
    }
    let rotated = state
        .live_config
        .generation()
        .auth()
        .validate_token(ROTATED);
    assert_eq!(
        rotated.map(|client| client.rate_limit),
        Some(OPS_WINDOW),
        "the rotated client's rate limit"
    );
    let after = ops_identity(&state, ROTATED);
    assert_eq!(after[0], before[0], "the principal moved");
    assert_eq!(after[1], before[1], "the limit key moved");
    assert_ne!(after[2], before[2], "the store key follows the digest");

    let _ended = crate::clock::test_clock::at_secs(GRACE_ENDS);
    assert_eq!(status(&state, "/mcp", KEPT).await, StatusCode::UNAUTHORIZED);
    let got = status(&state, "/mcp", ROTATED).await;
    assert!(accepted(got), "the new digest after the grace ends: {got}");
    // Two spent before the reload, three calls since: the window is full only
    // if the reload kept the first two.
    assert!(
        !spend_one(&state, ROTATED),
        "the reload gave a fresh window"
    );
}

/// `keys` under `security.posture: hardened`, the posture the `kind` row's
/// gateway runs with (a reload that changed it would be refused), with the
/// signing secret hardened requires.
fn hardened(keys: &[ApiKeyConfig]) -> String {
    format!(
        "security:\n  posture: hardened\n  message_signing:\n    shared_secret: \"k5-hardened-signing-secret-0123456789\"\n{}",
        file_text(keys)
    )
}

/// K5 `kind` (MIK-9255.IDENT.6), observed through the one behaviour that
/// reads it: under `security.posture: hardened` a shared key is refused for
/// want of a per-caller identity and a personal one is not
/// (`hardened_identity.rs`). A reload that makes the key personal admits it
/// on the next call, and one that makes it shared again refuses it.
#[tokio::test]
async fn k5_a_key_kind_changed_by_reload_applies_on_the_next_call() {
    // Started from the same file text its reloads write, loaded as startup
    // loads it, so the reloads differ from it in the key alone.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, hardened(&[key(KEPT, None)]))
        .expect("write");
    let config = crate::config::Config::load(Some(&path)).expect("the hardened config loads");
    let auth = config.auth.clone();
    let (state, _store) =
        super::tests::test_router_app_state_with_auth_and_config(&auth, config).await;
    let refused = |(status, body): &(StatusCode, String)| {
        *status == StatusCode::FORBIDDEN && body.contains(super::hardened_identity::REFUSAL)
    };
    // Served: the hardened initialize answers 200, so authentication and the
    // identity check both passed.
    let admitted = |answer: &(StatusCode, String)| answer.0 == StatusCode::OK;
    // Control: a gateway started with the key already personal admits it,
    // so a refusal after the reload below is the reload's, not the fixture's.
    {
        let control_dir = tempfile::tempdir().expect("tempdir");
        let control_path = control_dir.path().join("gateway.yaml");
        let personal = ApiKeyConfig {
            kind: crate::config::ApiKeyKind::Personal,
            ..key(KEPT, None)
        };
        crate::gateway::test_helpers::write_owner_only(&control_path, hardened(&[personal]))
            .expect("write");
        let control =
            crate::config::Config::load(Some(&control_path)).expect("the hardened config loads");
        let control_auth = control.auth.clone();
        let (started_personal, _control_store) =
            super::tests::test_router_app_state_with_auth_and_config(&control_auth, control).await;
        let got = hardened_initialize(&started_personal, KEPT).await;
        assert!(
            admitted(&got),
            "control: a key started personal is not admitted: {got:?}"
        );
    }
    let before = hardened_initialize(&state, KEPT).await;
    assert!(
        refused(&before),
        "precondition: a shared key is refused for want of an identity: {before:?}"
    );

    let personal = ApiKeyConfig {
        kind: crate::config::ApiKeyKind::Personal,
        ..key(KEPT, None)
    };
    reload_text(&state, dir.path(), hardened(&[personal])).await;
    let made_personal = hardened_initialize(&state, KEPT).await;
    assert!(
        admitted(&made_personal),
        "the key made personal by reload is not admitted: {made_personal:?}"
    );

    reload_text(&state, dir.path(), hardened(&[key(KEPT, None)])).await;
    let made_shared = hardened_initialize(&state, KEPT).await;
    assert!(
        refused(&made_shared),
        "the key made shared again by reload is admitted: {made_shared:?}"
    );
}

/// A key rotated by hand in gateway.yaml because its secret leaked (a new
/// digest, the same explicit principal, no previous digest) and then reloaded
/// keeps its grants (ADR-022), but an event watch opened with the leaked
/// secret must stop being admitted: the reload path ends it, with no route
/// involved.
#[tokio::test]
async fn a_reload_rotating_a_leaked_key_ends_its_old_watch() {
    const PRINCIPAL: &str = "0a1b2c3d4e5f";
    const OLD: &str = "live-keys-leaked-old-secret";
    const NEW: &str = "live-keys-leaked-new-secret";
    let with = |secret: &str| {
        let mut k = key(secret, None);
        k.name = "ops".to_owned();
        k.principal = Some(PRINCIPAL.to_owned());
        k
    };
    let (state, _store) = test_router_app_state_with_auth(&auth(vec![with(OLD)])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let services = state.meta_mcp.events_services(
        Arc::clone(&state.live_config),
        crate::events::LiveCredentials::default(),
    );
    // The running config as loaded from the file, so the live table holds
    // the key before the rotation.
    reload_keys(&state, dir.path(), &[with(OLD)]).await;
    // The watch as the old secret's caller recorded it: the key's name and
    // its principal.
    let watch = crate::events::ApiKeyRef {
        name: "ops".to_owned(),
        principal: PRINCIPAL.to_owned(),
        // Opened with the old secret: bound to its digest.
        digest_tag: Some(crate::gateway::auth::secret_tag(OLD)),
    };
    assert!(
        services.admits(Some(&watch), "x"),
        "control: before the rotation the watch is admitted"
    );
    reload_keys(&state, dir.path(), &[with(NEW)]).await;
    assert!(
        !services.admits(Some(&watch), "x"),
        "a leaked rotation by reload left the old secret's watch admitted"
    );
}
