// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SUB4.READONLY.1 / SUB4.COMPAT.1 / SUB4.CARRIER.1 / R5, first admission leg.
//!
//! Every request reaches the shipped executable's production constructor. This
//! leg covers HTTP preflight and synchronous verified-owner replay; it does not
//! claim Task storage, orchestration, management, stdio or full lifecycle ACs.

#[path = "common/signing_gateway.rs"]
mod signing_gateway;

use reqwest::StatusCode;
use serde_json::{Value, json};
use signing_gateway::{BACKEND, BackendFixture, HttpGateway, TOOL, fixture_config};

const KEY: &str = "io.mcp-gateway/idempotency-key";
const VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const CAPS: &str = "io.modelcontextprotocol/clientCapabilities";
const RESULT_CANARY: &str = "sub4-actual-backend-result";

#[derive(Clone, Copy, Debug)]
enum Route {
    Meta,
    Direct,
}

impl Route {
    fn path(self, backend: &str) -> String {
        match self {
            Self::Meta => "/mcp".into(),
            Self::Direct => format!("/mcp/{backend}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Meta => "gateway_invoke",
            Self::Direct => TOOL,
        }
    }

    fn call(self, modern: bool, key: Option<Value>) -> Value {
        let arguments = json!({"fixture_value":"sub4-business-argument"});
        let arguments = match self {
            Self::Meta => json!({"server":BACKEND,"tool":TOOL,"arguments":arguments}),
            Self::Direct => arguments,
        };
        let mut request = json!({"jsonrpc":"2.0","id":"sub4-current-request","method":"tools/call",
            "params":{"name":self.name(),"arguments":arguments}});
        if modern {
            request["params"]["_meta"] = json!({(VERSION):"2026-07-28",(CAPS):{}});
        }
        if let Some(key) = key {
            request["params"]["_meta"][KEY] = key;
        }
        request
    }

    async fn send(self, gateway: &HttpGateway, request: &Value) -> (StatusCode, Value) {
        self.send_with_bearer(gateway, request, None).await
    }

    async fn send_with_bearer(
        self,
        gateway: &HttpGateway,
        request: &Value,
        bearer: Option<&str>,
    ) -> (StatusCode, Value) {
        self.send_with_key_header(gateway, request, bearer, None)
            .await
    }

    async fn send_with_key_header(
        self,
        gateway: &HttpGateway,
        request: &Value,
        bearer: Option<&str>,
        header_key: Option<&str>,
    ) -> (StatusCode, Value) {
        self.send_to_backend(gateway, request, bearer, header_key, BACKEND)
            .await
    }

    async fn send_to_backend(
        self,
        gateway: &HttpGateway,
        request: &Value,
        bearer: Option<&str>,
        header_key: Option<&str>,
        backend: &str,
    ) -> (StatusCode, Value) {
        // A retry has a fresh transport identity even when the operation key is
        // unchanged. Replaying the original JSON-RPC envelope must fail here.
        let mut request = request.clone();
        request["id"] = json!(uuid::Uuid::new_v4().to_string());
        if matches!(self, Self::Meta) {
            request["params"]["arguments"]["server"] = json!(backend);
        }
        let mut http = gateway
            .client
            .post(format!("{}{}", gateway.url, self.path(backend)))
            .json(&request);
        if let Some(bearer) = bearer {
            http = http.bearer_auth(bearer);
        }
        if let Some(key) = header_key {
            http = http.header("idempotency-key", key);
        }
        if request["params"]["_meta"][VERSION] == "2026-07-28" {
            http = http
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", self.name());
        } else {
            http = http.header("mcp-protocol-version", "2025-06-18");
        }
        let response = http.send().await.expect("actual gateway HTTP response");
        let status = response.status();
        let text = response.text().await.expect("complete gateway response");
        let body: Value = serde_json::from_str(&text).unwrap_or_else(|error| {
            panic!(
                "gateway returned non-JSON ({status}): {error}; {text}; {}",
                gateway.logs()
            )
        });
        // Authentication middleware refuses before JSON-RPC body parsing and
        // therefore cannot echo the request ID. All dispatched protocol replies can.
        assert_eq!(body["jsonrpc"], "2.0", "protocol envelope: {body}");
        if status == StatusCode::UNAUTHORIZED {
            assert_eq!(
                body.get("id"),
                Some(&Value::Null),
                "middleware refuses before body parsing"
            );
            assert!(body["error"].is_object(), "auth refusal envelope: {body}");
            assert!(
                body.get("result").is_none(),
                "auth refusal has no success: {body}"
            );
        } else {
            assert_eq!(
                body["id"], request["id"],
                "must echo this attempt's ID: {body}"
            );
        }
        (status, body)
    }
}

async fn fixture(read_only_targets: Vec<Value>) -> (BackendFixture, HttpGateway) {
    let backend =
        BackendFixture::start(json!({"content":[{"type":"text","text":RESULT_CANARY}]})).await;
    // The remote advertises readOnlyHint=true. Only gateway policy can trust it;
    // preserving this hint makes the missing-policy negative discriminating.
    let mut config = fixture_config(&backend.url);
    config["security"]["message_signing"] = json!({"enabled":false});
    config["auth"] = json!({"enabled":false});
    config["cache"] = json!({"enabled":false});
    config["idempotency"] = json!({"read_only_tools":read_only_targets});
    let gateway = HttpGateway::start(config).await;
    (backend, gateway)
}

fn assert_backend_result(status: StatusCode, body: &Value) {
    assert!(
        status.is_success(),
        "expected supported invocation: {status} {body}"
    );
    assert!(
        body.get("error").is_none(),
        "expected supported invocation: {body}"
    );
    assert_ne!(
        body["result"]["resultType"], "task",
        "keyless calls must remain synchronous"
    );
    assert!(
        body["result"].to_string().contains(RESULT_CANARY),
        "real backend result: {body}"
    );
}

fn assert_refusal(body: &Value) {
    assert!(
        body.get("error").is_some() || body["result"]["isError"] == true,
        "admission must explicitly refuse rather than return an empty success: {body}"
    );
    assert!(
        !body.to_string().contains(RESULT_CANARY),
        "refused work must not expose backend result: {body}"
    );
}

async fn legacy_positive_control(route: Route, backend: &BackendFixture, gateway: &HttpGateway) {
    let before = backend.calls().len();
    let (status, body) = route.send(gateway, &route.call(false, None)).await;
    assert_backend_result(status, &body);
    assert_eq!(
        backend.calls().len(),
        before + 1,
        "same-route legacy control must reach actual backend"
    );
}

async fn legacy_unkeyed_repeats(route: Route) {
    let (backend, gateway) = fixture(vec![]).await;
    legacy_positive_control(route, &backend, &gateway).await;
    legacy_positive_control(route, &backend, &gateway).await;
    assert_eq!(
        backend.calls().len(),
        2,
        "legacy intentional repeats remain two calls with unchanged identity requirements"
    );
}

async fn modern_missing_key(route: Route) {
    let (backend, gateway) = fixture(vec![]).await;
    legacy_positive_control(route, &backend, &gateway).await;
    let (_, body) = route.send(&gateway, &route.call(true, None)).await;
    assert_eq!(
        backend.calls().len(),
        1,
        "modern keyless unknown/mutating target must refuse before backend; {body}"
    );
    assert_refusal(&body);
}

async fn modern_unverified_key(route: Route) {
    let (backend, gateway) = fixture(vec![]).await;
    legacy_positive_control(route, &backend, &gateway).await;
    let mut request = route.call(true, Some(json!("sub4-explicit-key")));
    // Self-asserted client identity cannot manufacture a protected owner.
    request["params"]["_meta"]["io.modelcontextprotocol/clientInfo"] =
        json!({"name":"admin","version":"1"});
    let (_, body) = route.send(&gateway, &request).await;
    assert_eq!(
        backend.calls().len(),
        1,
        "an auth-disabled caller must not receive an anonymous shared reservation; {body}"
    );
    assert_refusal(&body);
}

async fn malformed_key(route: Route, value: Value) {
    // Use a policy-listed read-only target: malformed keys must not silently
    // become keyless. This isolates key validation from missing-owner refusal.
    let (backend, gateway) = fixture(vec![json!({"server":BACKEND,"tool":TOOL})]).await;
    let (status, body) = route.send(&gateway, &route.call(true, None)).await;
    assert_backend_result(status, &body);
    assert_eq!(backend.calls().len(), 1);
    let (status, body) = route
        .send(&gateway, &route.call(true, Some(value.clone())))
        .await;
    assert_eq!(
        backend.calls().len(),
        1,
        "malformed reserved key {value} must refuse before backend; {body}"
    );
    assert_eq!(
        body["error"]["code"], -32602,
        "malformed reserved key must be invalid-params: {body}"
    );
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "malformed modern metadata HTTP mapping"
    );
    assert_refusal(&body);
}

async fn explicit_read_only_policy(route: Route) {
    let (backend, gateway) = fixture(vec![json!({"server":BACKEND,"tool":TOOL})]).await;
    for expected in 1..=2 {
        let (status, body) = route.send(&gateway, &route.call(true, None)).await;
        assert_backend_result(status, &body);
        assert_eq!(
            backend.calls().len(),
            expected,
            "keyless read-only calls must not acquire a body-derived dedupe key"
        );
    }
}

async fn exact_policy_target(route: Route) {
    let (backend, gateway) =
        fixture(vec![json!({"server":BACKEND,"tool":"a_different_tool"})]).await;
    legacy_positive_control(route, &backend, &gateway).await;
    let (_, body) = route.send(&gateway, &route.call(true, None)).await;
    assert_eq!(
        backend.calls().len(),
        1,
        "remote hint and another policy target cannot exempt this target; {body}"
    );
    assert_refusal(&body);
}

async fn exact_policy_backend(route: Route) {
    const OTHER: &str = "sub4_other_backend";
    let result = json!({"content":[{"type":"text","text":RESULT_CANARY}]});
    let listed = BackendFixture::start(result.clone()).await;
    let unlisted = BackendFixture::start(result).await;
    let mut config = fixture_config(&listed.url);
    config["security"]["message_signing"] = json!({"enabled":false});
    config["auth"] = json!({"enabled":false});
    config["backends"][OTHER] = json!({"http_url":unlisted.url,"streamable_http":true});
    config["idempotency"] = json!({"read_only_tools":[{"server":BACKEND,"tool":TOOL}]});
    let gateway = HttpGateway::start(config).await;
    let (status, body) = route.send(&gateway, &route.call(true, None)).await;
    assert_backend_result(status, &body);
    assert_eq!((listed.calls().len(), unlisted.calls().len()), (1, 0));
    // Prove the unlisted backend/tool is otherwise reachable on this route.
    let (status, body) = route
        .send_to_backend(&gateway, &route.call(false, None), None, None, OTHER)
        .await;
    assert_backend_result(status, &body);
    assert_eq!((listed.calls().len(), unlisted.calls().len()), (1, 1));
    let (_, body) = route
        .send_to_backend(&gateway, &route.call(true, None), None, None, OTHER)
        .await;
    assert_eq!(
        (listed.calls().len(), unlisted.calls().len()),
        (1, 1),
        "same tool name at another backend must not inherit trusted exemption: {body}"
    );
    assert_refusal(&body);
}

/// SUB4.COMPAT.1 HTTP meta: no newly required key or principal for unchanged legacy calls.
#[tokio::test]
async fn sub4_compat_legacy_meta_intentional_repeats() {
    legacy_unkeyed_repeats(Route::Meta).await;
}
/// SUB4.COMPAT.1 HTTP direct, independent real route.
#[tokio::test]
async fn sub4_compat_legacy_direct_intentional_repeats() {
    legacy_unkeyed_repeats(Route::Direct).await;
}
/// SUB4.READONLY.1 / ELIGIBLE-01 modern unknown mutability is protected.
#[tokio::test]
async fn sub4_preflight_meta_missing_key_refuses() {
    modern_missing_key(Route::Meta).await;
}
/// SUB4.READONLY.1 / ELIGIBLE-01 direct path cannot bypass the requirement.
#[tokio::test]
async fn sub4_preflight_direct_missing_key_refuses() {
    modern_missing_key(Route::Direct).await;
}
/// SUB4 R5 missing verified owner is refused, even with an explicit key.
#[tokio::test]
async fn sub4_preflight_meta_unverified_owner_refuses() {
    modern_unverified_key(Route::Meta).await;
}
/// SUB4 R5 same owner requirement on direct path.
#[tokio::test]
async fn sub4_preflight_direct_unverified_owner_refuses() {
    modern_unverified_key(Route::Direct).await;
}
// SUB4.CARRIER.1: separate named tests ensure an early red cannot mask the
// remaining malformed carrier vectors on either real parser boundary.
macro_rules! malformed_cases {
    ($($name:ident: $route:expr, $value:expr;)*) => {$ (
        #[tokio::test]
        async fn $name() { malformed_key($route, $value).await; }
    )*};
}
malformed_cases! {
    sub4_carrier_meta_null: Route::Meta, Value::Null;
    sub4_carrier_meta_empty: Route::Meta, json!("");
    sub4_carrier_meta_number: Route::Meta, json!(17);
    sub4_carrier_meta_boolean: Route::Meta, json!(false);
    sub4_carrier_meta_array: Route::Meta, json!([]);
    sub4_carrier_meta_object: Route::Meta, json!({});
    sub4_carrier_direct_null: Route::Direct, Value::Null;
    sub4_carrier_direct_empty: Route::Direct, json!("");
    sub4_carrier_direct_number: Route::Direct, json!(17);
    sub4_carrier_direct_boolean: Route::Direct, json!(false);
    sub4_carrier_direct_array: Route::Direct, json!([]);
    sub4_carrier_direct_object: Route::Direct, json!({});
}
/// SUB4.READONLY.1 explicit trusted policy positive control, cache disabled.
#[tokio::test]
async fn sub4_readonly_meta_policy_executes_twice() {
    explicit_read_only_policy(Route::Meta).await;
}
/// SUB4.READONLY.1 same policy positive control on direct route.
#[tokio::test]
async fn sub4_readonly_direct_policy_executes_twice() {
    explicit_read_only_policy(Route::Direct).await;
}
/// SUB4.READONLY.1 the exact structured target, not remote hint, chooses exemption.
#[tokio::test]
async fn sub4_readonly_meta_other_target_refuses() {
    exact_policy_target(Route::Meta).await;
}
/// SUB4.READONLY.1 independent direct policy boundary.
#[tokio::test]
async fn sub4_readonly_direct_other_target_refuses() {
    exact_policy_target(Route::Direct).await;
}
/// SUB4.READONLY.1 matching tool names cannot erase the structured backend owner.
#[tokio::test]
async fn sub4_readonly_meta_other_backend_same_tool_refuses() {
    exact_policy_backend(Route::Meta).await;
}
#[tokio::test]
async fn sub4_readonly_direct_other_backend_same_tool_refuses() {
    exact_policy_backend(Route::Direct).await;
}

// Real HTTPS trust-store fixture on Linux. Other platforms still run the
// HTTP preflight cases above; no macOS OIDC trust-store acceptance is claimed.
#[cfg(target_os = "linux")]
#[path = "common/sub4_oidc.rs"]
mod sub4_oidc;
#[cfg(target_os = "linux")]
#[path = "common/sub4_verified_admission.rs"]
mod verified_admission;
