// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Anonymous and non-admin access, the dashboard link and the starter posture.

use super::*;

/// The auth-disabled anonymous identity must not reach the management API.
///
/// This is the integration-level guard for the CWE-346 fix: every test above
/// authenticates, so without this case the whole file would pass again if the
/// anonymous identity were handed admin a second time.
#[tokio::test]
async fn anonymous_is_refused_admin_endpoints() {
    let config = Config::default();
    assert!(
        !config.auth.enabled,
        "this case is about the shipped default"
    );

    let (state, _store) = make_app_state_with_auth_config(&config.auth).await;
    let router = create_router(state);

    for uri in ["/ui/api/config", "/ui/api/registry", "/ui/api/capabilities"] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{uri} must refuse an anonymous caller"
        );
    }
}

/// `/dashboard` renders backend names, tool names and call counts. It is an
/// operator view, so it follows the same rule as the rest of the management
/// surface: admin only.
#[tokio::test]
async fn anonymous_is_refused_the_dashboard() {
    let config = Config::default();
    let (state, _store) = make_app_state_with_auth_config(&config.auth).await;
    let router = create_router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/dashboard")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // HTML, not JSON: a browser cannot attach an Authorization header to a
    // navigation, so the refusal has to tell a human what to do next.
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("text/html"),
        "expected an HTML explanation, got {content_type}"
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes);
    assert!(body.contains("/ui"), "the page must point somewhere usable");
}

/// The documented split: `/dashboard` and the management endpoints refuse an
/// anonymous caller outright, while `/ui/api/status` still answers with counts
/// so health probes and status pages keep working without a credential.
#[tokio::test]
async fn anonymous_still_reads_redacted_status() {
    let config = Config::default();
    let (state, _store) = make_app_state_with_auth_config(&config.auth).await;
    let router = create_router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/ui/api/status")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    // `backends` is not a field either view sets — the inventory is `servers`,
    // and only the admin view has it. Asserting the absence of a name nothing
    // uses is an assertion that cannot fail.
    assert!(
        body.get("servers").is_none(),
        "an anonymous caller must not receive the server inventory: {body}"
    );
    assert!(
        body.get("server_count").is_some() && body.get("healthy_count").is_some(),
        "and must still get the redacted counts, or this proves only that the \
         endpoint returned something: {body}"
    );
}

/// Three surfaces gated by something other than `.admin`, all reachable by the
/// anonymous identity used when authentication is disabled.
#[tokio::test]
async fn anonymous_is_refused_every_inventory_surface() {
    let config = Config::default();
    let (state, _store) = make_app_state_with_auth_config(&config.auth).await;
    let router = create_router(state);

    // /api/costs has no projection model: spend per session and per API key is
    // admin data or nothing, so it refuses.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/costs")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "/api/costs exposes cross-tenant spend and must require admin"
    );

    // The control plane is a governance surface. Filtering the backend list was
    // not enough: the snapshot also carries policies and shadow-radar data, and
    // an assertion about one substring cannot see the rest. A caller that
    // presented no credential is refused outright.
    for uri in [
        "/ui/api/control-plane",
        "/ui/api/control-plane/grants",
        "/ui/api/control-plane/policies",
        "/ui/api/control-plane/decisions",
    ] {
        let method = if uri.ends_with("control-plane") {
            Method::GET
        } else {
            Method::POST
        };
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{uri} is a governance surface and must refuse an unauthenticated caller"
        );
    }
}

/// `/health` computed a variable named `is_admin` from a client-NAME test, so
/// any authenticated API key received full backend detail whether or not it
/// held admin.
#[tokio::test]
async fn a_non_admin_api_key_gets_the_redacted_health_view() {
    let auth = AuthConfig {
        enabled: true,
        // /health is a public path by default, so the middleware assigns the
        // "public" identity before validating any credential and the handler
        // never sees the key. Removing it is what puts the API key on this path
        // at all; without this the case passes without exercising anything.
        public_paths: vec![],
        api_keys: vec![
            serde_json::from_value(serde_json::json!({
                "key_sha256": mcp_gateway::config::api_key_digest_spec(b"scoped-key"),
                "name": "scoped", "backends": ["*"], "admin": false
            }))
            .expect("api key fixture"),
        ],
        ..AuthConfig::default()
    };
    let (state, _store) = make_app_state_with_auth_config(&auth).await;
    let router = create_router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .header("authorization", "Bearer scoped-key")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    // Asserted on the redacted SHAPE. A3 narrowed it from `{count,
    // all_healthy}` under `backends` to no `backends` at all: a backend count
    // is inventory, and a non-admin gets `status` and `version` only.
    let mut keys: Vec<&str> = body
        .as_object()
        .expect("a health object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["status", "version"],
        "a non-admin key gets health and version, no backend or capability detail: {body}"
    );
}

/// A browser navigating to the dashboard cannot attach an Authorization header,
/// so a token alone does not make the dashboard usable. The gateway prints a
/// one-time link; opening it exchanges the credential for a session cookie and
/// redirects, so the token never stays in the address bar or the history.
#[tokio::test]
async fn the_dashboard_bootstrap_link_opens_the_dashboard() {
    let auth = admin_auth_config();
    let (state, _store) = make_app_state_with_auth_config(&auth).await;
    // The link carries a single-use value, NOT the admin token: a query string
    // reaches this gateway's own request log, which outlives the browser tab.
    let bootstrap = state
        .dashboard_bootstrap
        .peek()
        .expect("a fresh gateway has an unused bootstrap value");
    let router = create_router(state);

    // Step 1: the printed link carries that value once.
    //
    // Driven with connect info, because that is how the gateway serves this
    // router: both branches of `Gateway::run` use
    // `into_make_service_with_connect_info`, and redemption now reads the peer
    // address rather than the `Host` header — a header the caller writes and a
    // proxy rewrites (MIK-7257). A `oneshot` with no peer is refused on
    // purpose, so a faithful case has to supply one.
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(format!("/dashboard?bootstrap={bootstrap}"))
        .header("host", "127.0.0.1:39400")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(axum::extract::ConnectInfo(
        "127.0.0.1:52344".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the link must redirect, so the credential leaves the address bar"
    );
    let cookie = response
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        cookie.contains("HttpOnly"),
        "not readable by script: {cookie}"
    );
    assert!(
        cookie.contains("SameSite=Strict"),
        "not sent cross-site: {cookie}"
    );

    // Step 2: the browser follows the redirect carrying that cookie.
    let session = cookie.split(';').next().unwrap_or_default().to_string();
    let req = Request::builder()
        .method(Method::GET)
        .uri("/dashboard")
        .header(axum::http::header::COOKIE, session)
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the dashboard must render"
    );

    // A wrong value opens nothing, and so does the right value a second time:
    // a link left in a shell history is spent.
    for value in ["not-the-value", bootstrap.as_str()] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/dashboard?bootstrap={value}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "bootstrap value {value} must not open the dashboard"
        );
    }
}

/// The shipped starter posture, end to end: tools open, admin closed.
///
/// A config test shows the file; this shows the behaviour. The regression it
/// guards against is enabling authentication and gating the MCP endpoint with
/// it, which breaks the client the operator already configured.
#[tokio::test]
async fn the_starter_posture_keeps_tools_open_and_admin_closed() {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(ADMIN_TOKEN.to_string()),
        public_paths: vec!["/health".to_string(), "/mcp".to_string()],
        ..AuthConfig::default()
    };
    let (state, _store) = make_app_state_with_auth_config(&auth).await;
    let router = create_router(state);

    // An MCP client with no credential still lists tools.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string(),
        ))
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes).to_string();
    // The property is that AUTH does not block this path. The fixture has
    // meta-MCP off, so the handler answers with its own error; what must not
    // appear is a credential refusal.
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "auth blocked /mcp: {body}"
    );
    assert!(
        !body.contains("Authorization"),
        "the configured client must keep working with no change: {body}"
    );

    // The same caller cannot manage the gateway.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/ui/api/config")
        .body(Body::empty())
        .unwrap();
    let status = router.clone().oneshot(req).await.unwrap().status();
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "management needs the credential, got {status}"
    );

    // The credential opens management.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/ui/api/config")
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(router.oneshot(req).await.unwrap().status(), StatusCode::OK);
}

/// A public path drops the credential REQUIREMENT, not the credential.
///
/// `/mcp` is public on the starter config so ordinary tools stay open. An
/// operator presenting their admin token there must still be admin, or the
/// management tools their token pays for are unreachable.
#[tokio::test]
async fn a_credential_presented_on_a_public_path_still_counts() {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(ADMIN_TOKEN.to_string()),
        public_paths: vec!["/health".to_string(), "/mcp".to_string()],
        ..AuthConfig::default()
    };
    let (state, _store) = make_app_state_with_auth_config(&auth).await;
    let router = create_router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    // The redacted view has no `backends` at all (A3). Its presence is the
    // admin view, which is what the credential must still buy.
    assert!(
        body["backends"].is_object(),
        "an admin credential must still grant the admin view, got the redacted one: {body}"
    );
}

/// The printed dashboard link works only from the machine running the gateway.
///
/// The value is printed to the operator's terminal on the assumption that
/// seeing it means being at the machine. Declaring a `public_url` breaks that:
/// the origin gate then admits the published hostname by design, so anyone who
/// obtains the printed value — shipped logs, shared scrollback, a screenshot —
/// could exchange it for an admin session from anywhere. Printing was already
/// gated on a loopback bind; redemption was not.
#[tokio::test]
async fn a_bootstrap_link_is_not_redeemable_through_a_published_host() {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some("admin-token".to_string()),
        ..AuthConfig::default()
    };
    let (state, _store) = make_app_state_with_auth_config(&auth).await;
    let bootstrap = state
        .dashboard_bootstrap
        .peek()
        .expect("a bootstrap value is issued at startup");
    let router = create_router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/dashboard?bootstrap={bootstrap}"))
        .header("host", "gw.example.com")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();

    // Refused, and which layer refuses depends on the configuration. With no
    // `public_url` declared, as here, the origin gate rejects the unknown Host
    // first and answers 403. With one declared the gate admits that hostname by
    // design, and the loopback restriction on redemption is what refuses,
    // answering 401. Asserting "refused" rather than one code keeps the case
    // honest about which control is doing the work.
    assert!(
        response.status() == StatusCode::UNAUTHORIZED || response.status() == StatusCode::FORBIDDEN,
        "a published Host must not mint an admin session from the printed \
         link, got {}",
        response.status()
    );
}

/// A reload does not change request-time authentication — the invariant the
/// reload posture refusal rests on.
///
/// `network_bind_refusal` is evaluated on a reload against the config that will
/// be IN FORCE: the running snapshot, with only live-applied fields overlaid
/// from the file. That is only safe while `auth` is NOT one of the live fields.
/// It is not, today — `AppState::auth_config` is built once and `config_reload`
/// never touches it — but nothing enforced it, and every unit case in that suite
/// reads `auth` from the running config and would keep agreeing with itself if
/// this changed. This is the test that fails on that day.
///
/// Wired the way production is, because a first draft was not and could not have
/// failed: it gave the router a hard-coded auth config and reloaded a DIFFERENT
/// `LiveConfig` from the one the router held, so no reload could have reached
/// the request path even if `auth` were live. Here one startup config builds the
/// router's authentication, and one `Arc<LiveConfig>` is shared by the router
/// and the reload — the arrangement `Gateway::run` builds.
///
/// See docs/design/unauthenticated-network-posture.md, Decision C.
#[tokio::test]
async fn a_reload_does_not_change_request_time_authentication() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");

    // GIVEN: one startup config, authentication ON, and it is what both the
    // router's auth state and the shared live snapshot are built from.
    let startup = Config {
        auth: admin_auth_config(),
        ..Config::default()
    };
    write_owner_only(
        &config_path,
        "security:\n  transparency_log:\n    enabled: true\nauth:\n  enabled: true\n  bearer_token: \"test-admin-token\"\n",
    )
    .unwrap();

    let live_config = Arc::new(LiveConfig::new(startup.clone()));
    let (mut state, _store) = make_app_state(None, Some(config_path.clone())).await;
    {
        let s = Arc::get_mut(&mut state).expect("test AppState should be uniquely owned");
        s.auth_config = Arc::new(ResolvedAuthConfig::from_config(&startup.auth));
        s.live_config = Arc::clone(&live_config);
    }
    let router = create_router(Arc::clone(&state));

    let unauthenticated = || {
        Request::builder()
            .method(Method::GET)
            .uri("/ui/api/config")
            .body(Body::empty())
            .unwrap()
    };

    // Positive control: without it, a router that never refuses anything would
    // pass the assertion below for the wrong reason.
    let before = router
        .clone()
        .oneshot(unauthenticated())
        .await
        .unwrap()
        .status();
    assert!(
        before == StatusCode::UNAUTHORIZED || before == StatusCode::FORBIDDEN,
        "the fixture does not require a credential, so this test proves nothing: {before}"
    );

    // WHEN: the file turns authentication OFF and is reloaded through the live
    // snapshot the router reads. Nothing here refuses — no public URL is
    // declared — so the reload applies and publishes.
    write_owner_only(&config_path, "auth:\n  enabled: false\n").unwrap();
    let ctx = ReloadContext::new(
        config_path,
        Arc::clone(&live_config),
        Arc::clone(&state.backends),
        startup.failsafe.clone(),
        startup.meta_mcp.cache_ttl,
    )
    .expect("the registry pairs with the config");
    ctx.reload_outcome().await.expect("the reload failed");
    assert!(
        !live_config.get().auth.enabled,
        "the reload did not publish, so this proves nothing about what a \
         published change reaches"
    );

    // THEN: the request path is unmoved. The published snapshot says auth is
    // off; what is in force is what the process started with.
    let after = router
        .clone()
        .oneshot(unauthenticated())
        .await
        .unwrap()
        .status();
    assert_eq!(
        after, before,
        "a reload changed request-time authentication — the reload posture \
         overlay reads `auth` from the running config and is now unsound"
    );
}

/// A leaked link cannot be redeemed through a proxy (MIK-7257).
///
/// The check used to read `Host`, which the caller writes and a reverse proxy
/// rewrites — nginx's default for a bare `proxy_pass` is the upstream address.
/// A request forwarded from anywhere therefore arrived carrying a loopback
/// `Host` and was granted an admin session. Both cases below present exactly
/// that: a perfect loopback `Host` and a valid, unspent bootstrap value.
#[tokio::test]
async fn a_forwarded_request_cannot_redeem_the_dashboard_link() {
    for (label, peer, forwarded) in [
        ("straight off the network", "203.0.113.9:41000", false),
        ("through a proxy on this machine", "127.0.0.1:52344", true),
    ] {
        let auth = admin_auth_config();
        let (state, _store) = make_app_state_with_auth_config(&auth).await;
        let bootstrap = state
            .dashboard_bootstrap
            .peek()
            .expect("a fresh gateway has an unused bootstrap value");
        let router = create_router(state);

        let mut builder = Request::builder()
            .method(Method::GET)
            .uri(format!("/dashboard?bootstrap={bootstrap}"))
            // The loopback Host the old check trusted.
            .header("host", "127.0.0.1:39400");
        if forwarded {
            builder = builder.header("x-forwarded-for", "203.0.113.9");
        }
        let mut req = builder.body(Body::empty()).unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            peer.parse::<std::net::SocketAddr>().unwrap(),
        ));

        let response = router.clone().oneshot(req).await.unwrap();
        assert_ne!(
            response.status(),
            StatusCode::SEE_OTHER,
            "a request {label} redeemed the link and was handed an admin session"
        );
    }
}
