// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6745 slice 6: the connect offer on a refused dispatch (design §9.1-§9.3;
//! §11.2 rows T-OFFER, T-OFFER2, T-BC1). Real router, auth, adapter, compiled
//! binding, installed vault strategy and custody; the offer and the refusal it
//! answers read ONE store. The store-level H1 half of T-OFFER3 is in
//! `personal_accounts/journey/tests_offer.rs`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::super::super::create_router_with_accounts;
use super::super::{ResolvedAuthConfig, StreamingConfig, test_router_app_state_with};
use crate::personal_accounts::revoke_fixture::{RevocationEndpoint, RevokeFixture};

const ACCOUNT: &str = "work";
const BACKEND: &str = "drive";
const RESOURCE: &str = "https://api.fixture.test/";
const HMAC: &str = "fixture-adapter-signing-secret-123456789";
const PLAIN_HMAC: &str = "fixture-plain-adapter-secret-9876543210";
const API_KEY: &str = "fixture-named-api-key";
const START_PREFIX: &str = "https://chat.fixture.test/accounts/v1/journeys/";
/// Today's refusal text for an absent account, pinned from source (vault.rs
/// `refusal`, `PropagationError` Display, the invoke.rs `refuse` closure and
/// `Error::Config`), so a missing predicate cannot change what callers read.
const ABSENT_TEXT: &str = "Configuration error: identity propagation required for backend \
    'drive' but credential minting failed: no connected account (fail-closed): account is not \
    connected — connect the account for this backend, then retry";

/// Whether `accounts.hosted` and the bridged adapter's `session` block exist.
#[derive(Clone, Copy)]
enum Shape {
    Bridged,
    NotHosted,
}

/// Which adapter asserts the caller: the bridge, or one with no `session`.
#[derive(Clone, Copy)]
enum Caller {
    Bridged,
    Plain,
}

fn config(env: &std::path::Path, shape: Shape) -> crate::config::Config {
    let (session, hosted) = match shape {
        Shape::Bridged => (
            "      session:\n        user_endpoint: http://127.0.0.1:9/api/v1/auths/\n",
            "  hosted:\n    public_origin: https://chat.fixture.test\n    return_paths: [/]\n",
        ),
        Shape::NotHosted => ("", ""),
    };
    serde_yaml::from_str(&format!(
        r#"
env_files: ["{env}"]
auth:
  enabled: true
  public_paths: []
  api_keys:
    - name: owui
      key: {API_KEY}
      backends: ["*"]
backends:
  {BACKEND}:
    http_url: https://drive.invalid/mcp
    account: {ACCOUNT}
accounts:
  schema_version: accounts.v1
  enabled: false
  deployment: single_process
  instance_id: router-fixture
  store_dir: /unused/router-fixture-store
  authority_dir: /unused/router-fixture-authority
  current_key_id: primary
  keys:
    primary: env:OWUI_ROUTE_STORE
  limits:
    journeys_created_per_minute: 1
  adapters:
    - kind: openwebui_signed_header
      installation_id: fixture-installation
      header: x-openwebui-assertion
      issuer: open-webui
      hmac_secret_ref: env:OWUI_ROUTE_HMAC
      allowed_api_key_names: [owui]
{session}    - kind: openwebui_signed_header
      installation_id: plain
      header: x-plain-assertion
      issuer: open-webui
      hmac_secret_ref: env:OWUI_PLAIN_HMAC
      allowed_api_key_names: [owui]
  descriptors:
    {ACCOUNT}:
      mode: personal_managed
      provider: fixture
      resource: {RESOURCE}
      issuer: https://issuer.fixture.test
      redirect_uri: https://chat.fixture.test/accounts/v1/callback
{hosted}"#,
        env = env.display()
    ))
    .unwrap()
}

struct Gateway {
    router: axum::Router,
    _fixture: RevokeFixture,
    _dir: tempfile::TempDir,
}

/// The production compile, backend construction and strategy install, with
/// the fixture's custody behind both the strategy and the journey handles.
async fn gateway(shape: Shape) -> Gateway {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join("adapter.env");
    std::fs::write(
        &env,
        format!("OWUI_ROUTE_HMAC={HMAC}\nOWUI_PLAIN_HMAC={PLAIN_HMAC}\nOWUI_ROUTE_STORE=UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=\n"),
    )
    .unwrap();
    let config = config(&env, shape);
    let auth = Arc::new(ResolvedAuthConfig::from_config(&config.auth));
    let (mut state, _store) =
        test_router_app_state_with(StreamingConfig::default(), config.clone()).await;
    Arc::get_mut(&mut state).unwrap().auth_config = auth;
    let fixture =
        RevokeFixture::start(ACCOUNT, RESOURCE, &[], RevocationEndpoint::Configured).await;
    let bound = crate::config::account_bindings::compile(&config).expect("binding compiles");
    let effective = bound[BACKEND].effective(&config.backends[BACKEND]);
    let backend = crate::backend::Backend::new(
        BACKEND,
        effective,
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    );
    // No network: a catalogue fetch that follows resolution reaches this stub.
    backend.set_transport_for_test(Arc::new(Silent));
    assert!(state.backends.register(Arc::new(backend)));
    crate::gateway::server::account_bindings::install_account_strategies(
        &config,
        Some(&fixture.custody()),
        &state.gateway_key_pair,
        &state.meta_mcp,
    )
    .expect("the production installer accepts the binding");
    let router = create_router_with_accounts(state, None, Some(fixture.handles()));
    Gateway {
        router,
        _fixture: fixture,
        _dir: dir,
    }
}

fn assertion(secret: &str, subject: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({"iss":"open-webui","sub":subject,"iat":now,"exp":now+120});
    let key = EncodingKey::from_secret(secret.as_bytes());
    encode(&Header::new(Algorithm::HS256), &claims, &key).unwrap()
}

/// One JSON-RPC request at `uri`, asserted by `caller` as `subject`.
async fn rpc(gw: &Gateway, uri: &str, caller: Caller, subject: &str, body: &Value) -> Value {
    let (header, secret) = match caller {
        Caller::Bridged => ("x-openwebui-assertion", HMAC),
        Caller::Plain => ("x-plain-assertion", PLAIN_HMAC),
    };
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {API_KEY}"))
        .header(header, assertion(secret, subject))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = gw.router.clone().oneshot(request).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    // A body that did not parse would contain no URL and pass vacuously.
    serde_json::from_slice(&bytes).expect("a JSON-RPC body")
}

/// A backend transport that answers every request with an empty result.
struct Silent;

#[async_trait::async_trait]
impl crate::transport::Transport for Silent {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let id = crate::protocol::RequestId::Number(1);
        Ok(crate::protocol::JsonRpcResponse::success(id, json!({})))
    }

    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.request(method, params).await
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

fn call(method: &str, params: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params})
}

/// `gateway_invoke` naming the bound backend: the meta dispatch site.
async fn invoke(gw: &Gateway, caller: Caller, subject: &str) -> Value {
    let args = json!({"server": BACKEND, "tool": "list_files", "arguments": {}});
    let params = json!({"name": "gateway_invoke", "arguments": args});
    rpc(gw, "/mcp", caller, subject, &call("tools/call", &params)).await
}

/// `tools/call` on `/mcp/{backend}`: the direct dispatch site.
async fn direct(gw: &Gateway, caller: Caller, subject: &str) -> Value {
    let params = json!({"name": "list_files", "arguments": {}});
    let uri = format!("/mcp/{BACKEND}");
    rpc(gw, &uri, caller, subject, &call("tools/call", &params)).await
}

/// The offered URL, after the §9.1 shape checks every dispatch site shares.
fn offered(response: &Value, code: &str) -> String {
    let error = &response["error"];
    let data = &error["data"];
    assert_eq!(data["schema_version"], "accounts.v1", "{response}");
    assert_eq!(data["error"]["code"], code, "{response}");
    assert_eq!(data["error"]["retryable"], false, "{response}");
    assert_eq!(data["account_id"], ACCOUNT, "{response}");
    let url = data["connect_url"]
        .as_str()
        .expect("connect_url")
        .to_owned();
    assert!(
        url.starts_with(START_PREFIX) && url.ends_with("/start"),
        "{url}"
    );
    let message = error["message"].as_str().expect("message");
    assert!(
        message.contains(&url),
        "Open WebUI may drop data: {message}"
    );
    url
}

#[tokio::test]
async fn t_offer_both_dispatch_sites_offer_one_journey_owned_by_the_caller() {
    // GIVEN: a bridged caller whose account was never connected
    let gw = gateway(Shape::Bridged).await;

    // WHEN: the meta route and the direct route each dispatch to the backend
    let meta = invoke(&gw, Caller::Bridged, "alice").await;
    let routed = direct(&gw, Caller::Bridged, "alice").await;

    // THEN: both carry the offer; the meta route answers -32001, the direct
    // route keeps its -32003, and the one creation per minute was spent once
    assert_eq!(meta["error"]["code"], -32001, "{meta}");
    assert_eq!(routed["error"]["code"], -32003, "{routed}");
    let url = offered(&meta, "account_not_connected");
    assert_eq!(offered(&routed, "account_not_connected"), url, "reused");
    let id = url
        .trim_start_matches(START_PREFIX)
        .trim_end_matches("/start");
    let owned = rpc_status(&gw, "alice", id).await;
    assert_eq!(owned["status"], "pending", "the caller owns it: {owned}");
    let foreign = rpc_status(&gw, "mallory", id).await;
    assert_eq!(foreign["error"]["code"], "not_found", "{foreign}");
}

#[tokio::test]
async fn t_offer2_an_unbridged_caller_or_an_unhosted_gateway_reads_todays_text() {
    for (shape, caller) in [
        (Shape::Bridged, Caller::Plain),
        (Shape::NotHosted, Caller::Bridged),
    ] {
        // GIVEN: predicate B fails, by caller or by configuration
        let gw = gateway(shape).await;

        // WHEN: both dispatch sites refuse the absent account
        let meta = invoke(&gw, caller, "bob").await;
        let routed = direct(&gw, caller, "bob").await;

        // THEN: no offer, and the message and code are exactly today's
        for (response, code) in [(&meta, -32603), (&routed, -32003)] {
            assert!(!response.to_string().contains("accounts/v1"), "{response}");
            assert_eq!(response["error"]["message"], ABSENT_TEXT, "{response}");
            assert_eq!(response["error"]["code"], code, "{response}");
        }
    }
}

/// `GET /accounts/v1/journeys/{id}` as `subject`, through the bridged adapter.
async fn rpc_status(gw: &Gateway, subject: &str, id: &str) -> Value {
    let request = Request::builder()
        .method("GET")
        .uri(format!("/accounts/v1/journeys/{id}"))
        .header("authorization", format!("Bearer {API_KEY}"))
        .header("x-openwebui-assertion", assertion(HMAC, subject))
        .body(Body::empty())
        .unwrap();
    let response = gw.router.clone().oneshot(request).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// Every catalogue and listing method a client can send at `/mcp` (§9.2).
fn catalogue_calls() -> Vec<Value> {
    let tool =
        |name: &str, args: Value| call("tools/call", &json!({"name": name, "arguments": args}));
    vec![
        call("tools/list", &json!({})),
        call("resources/list", &json!({})),
        call("resources/templates/list", &json!({})),
        call("prompts/list", &json!({})),
        call("resources/read", &json!({"uri": format!("{BACKEND}://x")})),
        call("prompts/get", &json!({"name": format!("{BACKEND}/p")})),
        call("logging/setLevel", &json!({"level": "info"})),
        tool("gateway_search_tools", json!({"query": "files"})),
        tool("gateway_list_tools", json!({})),
        tool("gateway_list_tools", json!({"server": BACKEND})),
        tool("gateway_list_servers", json!({})),
    ]
}

#[tokio::test]
async fn t_bc1_no_catalogue_method_mints_or_discloses_an_offer() {
    // GIVEN: one creation per minute, and an absent bridged caller
    let gw = gateway(Shape::Bridged).await;

    // WHEN: that caller runs every catalogue method
    for request in catalogue_calls() {
        let response = rpc(&gw, "/mcp", Caller::Bridged, "carol", &request).await;
        // THEN: nothing discloses a journey
        assert!(
            !response.to_string().contains("accounts/v1"),
            "{request}: {response}"
        );
    }

    // AND: the creation budget is unspent, so the catalogue minted nothing
    let meta = invoke(&gw, Caller::Bridged, "dave").await;
    offered(&meta, "account_not_connected");
}
