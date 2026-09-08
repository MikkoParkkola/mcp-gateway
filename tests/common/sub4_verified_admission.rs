// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Verified-owner cases remain a separate file to keep the preflight matrix readable.
use super::sub4_oidc::OidcFixture;
use super::*;

async fn authenticated_fixture() -> (BackendFixture, HttpGateway, OidcFixture) {
    authenticated_fixture_with_policy(false).await
}

async fn authenticated_fixture_with_policy(
    read_only: bool,
) -> (BackendFixture, HttpGateway, OidcFixture) {
    let backend =
        BackendFixture::start(json!({"content":[{"type":"text","text":RESULT_CANARY}]})).await;
    let oidc = OidcFixture::start().await;
    let mut config = fixture_config(&backend.url);
    config["security"]["message_signing"] = json!({"enabled":false});
    // Identity propagation OFF deliberately: verified admission ownership cannot
    // disappear merely because no backend credential is being minted.
    oidc.configure(&mut config);
    if read_only {
        config["idempotency"] = json!({"read_only_tools":[{"server":BACKEND,"tool":TOOL}]});
    }
    let gateway =
        HttpGateway::start_with_env(config, &[("SSL_CERT_FILE", oidc.ca_path.as_os_str())]).await;
    (backend, gateway, oidc)
}

async fn verified_control(route: Route) {
    let (backend, gateway, oidc) = authenticated_fixture().await;
    let request = route.call(true, Some(json!("sub4-verified-positive")));
    let (status, body) = route
        .send_with_bearer(&gateway, &request, Some(&oidc.token("alice", 1)))
        .await;
    assert_route_result(route, status, &body);
    assert_eq!(backend.calls().len(), 1);
    assert!(
        oidc.fetch_count() > 0,
        "production verifier must fetch the actual HTTPS JWKS"
    );
    let (status, body) = route
        .send_with_bearer(&gateway, &request, Some("unsigned-not-a-token"))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "invalid credential is not a public-route fallback"
    );
    assert_eq!(backend.calls().len(), 1);
    assert!(!body.to_string().contains(RESULT_CANARY));
}

async fn verified_missing_payload_key(route: Route, header_only: bool) {
    let (backend, gateway, oidc) = authenticated_fixture().await;
    let token = oidc.token("alice", 1);
    let keyed = route.call(true, Some(json!("sub4-keyed-positive-control")));
    let (status, body) = route.send_with_bearer(&gateway, &keyed, Some(&token)).await;
    assert_route_result(route, status, &body);
    assert_eq!(backend.calls().len(), 1);
    let (status, body) = route
        .send_with_key_header(
            &gateway,
            &route.call(true, None),
            Some(&token),
            header_only.then_some("sub4-header-is-not-a-payload-key"),
        )
        .await;
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "same verified principal must pass auth"
    );
    assert_eq!(
        backend.calls().len(),
        1,
        "verified keyless mutation must not dispatch: {body}"
    );
    assert_refusal(&body);
    assert_no_retry_headers(&backend);
}

fn assert_no_retry_headers(backend: &BackendFixture) {
    let headers = backend.call_headers();
    assert_eq!(
        headers.len(),
        backend.calls().len(),
        "headers and JSON record the same calls"
    );
    for headers in headers {
        assert_eq!(
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json"),
            "header recorder must observe the actual JSON transport header"
        );
        assert!(
            !headers.contains_key("idempotency-key"),
            "unsupported retry header reached actual backend"
        );
    }
}

async fn authenticated_read_only(route: Route) {
    let (backend, gateway, oidc) = authenticated_fixture_with_policy(true).await;
    let token = oidc.token("alice", 1);
    for count in 1..=2 {
        let (status, body) = route
            .send_with_bearer(&gateway, &route.call(true, None), Some(&token))
            .await;
        assert_route_result(route, status, &body);
        assert_eq!(
            backend.calls().len(),
            count,
            "trusted read-only policy remains effective with auth enabled"
        );
    }
}

async fn distinct_issuers(route: Route) {
    const OTHER_ISSUER: &str = "https://other-idp.example";
    let backend =
        BackendFixture::start(json!({"content":[{"type":"text","text":RESULT_CANARY}]})).await;
    let oidc = OidcFixture::start().await;
    let mut config = fixture_config(&backend.url);
    config["security"]["message_signing"] = json!({"enabled":false});
    oidc.configure(&mut config);
    let mut other_provider = config["key_server"]["oidc"][0].clone();
    other_provider["issuer"] = json!(OTHER_ISSUER);
    config["key_server"]["oidc"]
        .as_array_mut()
        .unwrap()
        .push(other_provider);
    let mut other_policy = config["key_server"]["policies"][0].clone();
    other_policy["match"]["issuer"] = json!(OTHER_ISSUER);
    config["key_server"]["policies"]
        .as_array_mut()
        .unwrap()
        .push(other_policy);
    let gateway =
        HttpGateway::start_with_env(config, &[("SSL_CERT_FILE", oidc.ca_path.as_os_str())]).await;
    let request = route.call(true, Some(json!("sub4-same-subject-different-issuer")));
    for (index, issuer) in [super::sub4_oidc::ISSUER, OTHER_ISSUER]
        .into_iter()
        .enumerate()
    {
        let expected = format!("{RESULT_CANARY}:issuer-{index}");
        backend.set_result(json!({"content":[{"type":"text","text":expected}]}));
        let token = oidc.token_for_issuer(issuer, "alice", 1);
        let (status, body) = route
            .send_with_bearer(&gateway, &request, Some(&token))
            .await;
        assert_named_route_result(route, status, &body, &expected);
        assert_eq!(
            backend.calls().len(),
            index + 1,
            "same subject under distinct verified issuers is a distinct owner"
        );
    }
    let (status, body) = route
        .send_with_bearer(&gateway, &request, Some(&oidc.token("alice", 2)))
        .await;
    assert_named_route_result(route, status, &body, &format!("{RESULT_CANARY}:issuer-0"));
    assert_eq!(
        backend.calls().len(),
        2,
        "first issuer retry returns its own retained result"
    );
}

async fn bad_signature(route: Route) {
    let (backend, gateway, oidc) = authenticated_fixture().await;
    let request = route.call(true, Some(json!("sub4-signature-positive-control")));
    let token = oidc.token("alice", 1);
    let (status, body) = route
        .send_with_bearer(&gateway, &request, Some(&token))
        .await;
    assert_route_result(route, status, &body);
    assert_eq!(backend.calls().len(), 1);
    let (status, body) = route
        .send_with_bearer(&gateway, &request, Some(&oidc.invalid_signature(&token)))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "valid JWT shape with invalid signature"
    );
    assert_eq!(backend.calls().len(), 1);
    assert!(!body.to_string().contains(RESULT_CANARY));
}

async fn missing_ca(route: Route) {
    let backend =
        BackendFixture::start(json!({"content":[{"type":"text","text":RESULT_CANARY}]})).await;
    let oidc = OidcFixture::start().await;
    let mut config = fixture_config(&backend.url);
    config["security"]["message_signing"] = json!({"enabled":false});
    oidc.configure(&mut config);
    let token = oidc.token("alice", 1);
    let request = route.call(true, Some(json!("sub4-trust-positive-control")));
    let untrusted = HttpGateway::start(config.clone()).await;
    let (status, body) = route
        .send_with_bearer(&untrusted, &request, Some(&token))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "ephemeral root is not machine-trusted"
    );
    assert_eq!(backend.calls().len(), 0);
    assert_eq!(
        oidc.fetch_count(),
        0,
        "TLS refusal happens before JWKS HTTP handler"
    );
    assert!(!body.to_string().contains(RESULT_CANARY));
    drop(untrusted);
    let trusted =
        HttpGateway::start_with_env(config, &[("SSL_CERT_FILE", oidc.ca_path.as_os_str())]).await;
    let (status, body) = route
        .send_with_bearer(&trusted, &request, Some(&token))
        .await;
    assert_route_result(route, status, &body);
    assert_eq!(backend.calls().len(), 1);
    assert!(
        oidc.fetch_count() > 0,
        "same issuer/token succeeds with child-local root"
    );
}

async fn verified_repeat(route: Route) {
    let (backend, gateway, oidc) = authenticated_fixture().await;
    let request = route.call(true, Some(json!("sub4-same-owner-key")));
    for generation in 1..=2 {
        let token = oidc.token("alice", generation);
        let (status, body) = route
            .send_with_bearer(&gateway, &request, Some(&token))
            .await;
        assert_route_result(route, status, &body);
        assert_eq!(
            backend.calls().len(),
            1,
            "same issuer/subject and explicit key must execute once across credential rotation; {body}"
        );
    }
    assert!(oidc.fetch_count() > 0);
    let fresh = route.call(true, Some(json!("sub4-intentional-new-key")));
    let (status, body) = route
        .send_with_bearer(&gateway, &fresh, Some(&oidc.token("alice", 3)))
        .await;
    assert_route_result(route, status, &body);
    assert_eq!(
        backend.calls().len(),
        2,
        "different-key positive control deliberately runs again"
    );
}

async fn verified_principals(route: Route) {
    let (backend, gateway, oidc) = authenticated_fixture().await;
    let request = route.call(true, Some(json!("sub4-same-key-distinct-owners")));
    for (index, subject) in ["alice", "bob"].into_iter().enumerate() {
        backend.set_result(
            json!({"content":[{"type":"text","text":format!("{RESULT_CANARY}:{subject}")}]}),
        );
        let (status, body) = route
            .send_with_bearer(&gateway, &request, Some(&oidc.token(subject, 1)))
            .await;
        assert_named_route_result(route, status, &body, &format!("{RESULT_CANARY}:{subject}"));
        assert!(
            body["result"]
                .to_string()
                .contains(&format!("{RESULT_CANARY}:{subject}")),
            "another owner's result must not be reused: {body}"
        );
        assert_eq!(
            backend.calls().len(),
            index + 1,
            "verified distinct subjects with identical display names own separate operations"
        );
    }
    let (status, body) = route
        .send_with_bearer(&gateway, &request, Some(&oidc.token("alice", 2)))
        .await;
    assert_named_route_result(route, status, &body, &format!("{RESULT_CANARY}:alice"));
    assert_eq!(
        backend.calls().len(),
        2,
        "returning original owner must replay only its own outcome"
    );
    assert!(
        body["result"]
            .to_string()
            .contains(&format!("{RESULT_CANARY}:alice")),
        "returning owner must receive Alice's retained payload: {body}"
    );
}

async fn cross_route_replay(first: Route, second: Route) {
    let (backend, gateway, oidc) = authenticated_fixture().await;
    let token = oidc.token("alice", 1);
    let first_request = first.call(true, Some(json!("sub4-one-cross-route-operation")));
    let (status, body) = first
        .send_with_bearer(&gateway, &first_request, Some(&token))
        .await;
    assert_route_result(first, status, &body);
    assert_eq!(backend.calls().len(), 1);
    let second_request = second.call(true, Some(json!("sub4-one-cross-route-operation")));
    let (status, body) = second
        .send_with_bearer(&gateway, &second_request, Some(&token))
        .await;
    assert_eq!(
        backend.calls().len(),
        1,
        "the other public route cannot create a second execution owner; {body}"
    );
    // The operation owner is invariant even if the final route representation
    // is intentionally incompatible. In that case the reviewed contract is409.
    if body.get("error").is_some() {
        assert_conflict(status, &body);
    } else {
        assert_route_result(second, status, &body);
    }
}

fn assert_conflict(status: StatusCode, body: &Value) {
    // The contract names JSON-RPC 409. Existing HTTP dispatch wraps protocol
    // errors in 200; a transport-level 409 is also a conflict, never a 5xx.
    assert!(
        matches!(status, StatusCode::OK | StatusCode::CONFLICT),
        "conflict transport: {status} {body}"
    );
    assert_eq!(
        body["error"]["code"], 409,
        "explicit representation/operation mismatch: {body}"
    );
    assert!(
        body.get("result").is_none(),
        "conflict must not carry stale success: {body}"
    );
    assert!(
        !body.to_string().contains(RESULT_CANARY),
        "conflict must not reveal retained payload: {body}"
    );
}

fn assert_route_result(route: Route, status: StatusCode, body: &Value) {
    assert_named_route_result(route, status, body, RESULT_CANARY);
}

fn assert_named_route_result(route: Route, status: StatusCode, body: &Value, expected_text: &str) {
    assert_backend_result(status, body);
    assert_ne!(
        body["result"]["isError"], true,
        "replay must be successful: {body}"
    );
    let expected = json!([{"type":"text","text":expected_text}]);
    match route {
        Route::Direct => assert_eq!(body["result"]["content"], expected),
        Route::Meta => {
            assert_eq!(body["result"]["resultType"], "complete");
            let content = body["result"]["content"]
                .as_array()
                .expect("meta content array");
            assert_eq!(content.len(), 1);
            assert_eq!(content[0]["type"], "text");
            let nested: Value =
                serde_json::from_str(content[0]["text"].as_str().expect("meta text"))
                    .expect("meta result JSON");
            assert_eq!(nested["content"], expected, "secured route representation");
        }
    }
}

#[tokio::test]
async fn sub4_oidc_meta_actual_verified_positive_and_invalid_token_control() {
    verified_control(Route::Meta).await;
}
#[tokio::test]
async fn sub4_oidc_direct_actual_verified_positive_and_invalid_token_control() {
    verified_control(Route::Direct).await;
}
#[tokio::test]
async fn sub4_preflight_meta_verified_missing_key_refuses() {
    verified_missing_payload_key(Route::Meta, false).await;
}
#[tokio::test]
async fn sub4_readonly_meta_authenticated_policy_executes_twice() {
    authenticated_read_only(Route::Meta).await;
}
#[tokio::test]
async fn sub4_readonly_direct_authenticated_policy_executes_twice() {
    authenticated_read_only(Route::Direct).await;
}
#[tokio::test]
async fn sub4_owner_meta_same_subject_distinct_verified_issuers() {
    distinct_issuers(Route::Meta).await;
}
#[tokio::test]
async fn sub4_owner_direct_same_subject_distinct_verified_issuers() {
    distinct_issuers(Route::Direct).await;
}
#[tokio::test]
async fn sub4_preflight_direct_verified_missing_key_refuses() {
    verified_missing_payload_key(Route::Direct, false).await;
}
#[tokio::test]
async fn sub4_carrier_meta_verified_header_only_refuses() {
    verified_missing_payload_key(Route::Meta, true).await;
}
#[tokio::test]
async fn sub4_carrier_direct_verified_header_only_refuses() {
    verified_missing_payload_key(Route::Direct, true).await;
}
#[tokio::test]
async fn sub4_oidc_meta_well_formed_bad_signature_refuses() {
    bad_signature(Route::Meta).await;
}
#[tokio::test]
async fn sub4_oidc_direct_well_formed_bad_signature_refuses() {
    bad_signature(Route::Direct).await;
}
#[tokio::test]
async fn sub4_oidc_meta_missing_ca_refuses_then_trusted_positive() {
    missing_ca(Route::Meta).await;
}
#[tokio::test]
async fn sub4_oidc_direct_missing_ca_refuses_then_trusted_positive() {
    missing_ca(Route::Direct).await;
}
#[tokio::test]
async fn sub4_owner_meta_rotated_token_replays_one_operation() {
    verified_repeat(Route::Meta).await;
}
#[tokio::test]
async fn sub4_owner_direct_rotated_token_replays_one_operation() {
    verified_repeat(Route::Direct).await;
}
#[tokio::test]
async fn sub4_owner_meta_same_display_distinct_verified_principals() {
    verified_principals(Route::Meta).await;
}
#[tokio::test]
async fn sub4_owner_direct_same_display_distinct_verified_principals() {
    verified_principals(Route::Direct).await;
}
#[tokio::test]
async fn sub4_shared_owner_meta_then_direct_never_redispatches() {
    cross_route_replay(Route::Meta, Route::Direct).await;
}
#[tokio::test]
async fn sub4_shared_owner_direct_then_meta_never_redispatches() {
    cross_route_replay(Route::Direct, Route::Meta).await;
}

fn business_args_mut(route: Route, request: &mut Value) -> &mut Value {
    match route {
        Route::Meta => &mut request["params"]["arguments"]["arguments"],
        Route::Direct => &mut request["params"]["arguments"],
    }
}

async fn bound_request_mismatch(route: Route, representation: bool) {
    let (backend, gateway, oidc) = authenticated_fixture().await;
    let token = oidc.token("alice", 1);
    let mut request = route.call(true, Some(json!("sub4-mismatch-operation")));
    let (status, body) = route
        .send_with_bearer(&gateway, &request, Some(&token))
        .await;
    assert_route_result(route, status, &body);
    assert_eq!(backend.calls().len(), 1);
    if representation {
        business_args_mut(route, &mut request)["_full"] = json!(true);
    } else {
        business_args_mut(route, &mut request)["fixture_value"] =
            json!("changed-business-operation");
    }
    let (status, body) = route
        .send_with_bearer(&gateway, &request, Some(&token))
        .await;
    assert_eq!(
        backend.calls().len(),
        1,
        "changed request/representation cannot create another owner: {body}"
    );
    assert_conflict(status, &body);
}

async fn full_is_not_forwarded(route: Route) {
    let (backend, gateway, oidc) = authenticated_fixture().await;
    let token = oidc.token("alice", 1);
    // Fresh distinct keys prove `_full` is a gateway presentation control even
    // without relying on the earlier mismatch case's operation fingerprint.
    for (key, full) in [("sub4-full-default", false), ("sub4-full-enabled", true)] {
        let mut request = route.call(true, Some(json!(key)));
        if full {
            business_args_mut(route, &mut request)["_full"] = json!(true);
        }
        let (status, body) = route
            .send_with_bearer(&gateway, &request, Some(&token))
            .await;
        assert_route_result(route, status, &body);
    }
    let calls = backend.calls();
    assert_eq!(calls.len(), 2, "new keys deliberately execute twice");
    for call in calls {
        assert_eq!(
            call["params"]["arguments"],
            json!({"fixture_value":"sub4-business-argument"}),
            "presentation control must be removed: {call}"
        );
    }
}

async fn payload_carrier(route: Route) {
    let (backend, gateway, oidc) = authenticated_fixture().await;
    let token = oidc.token("alice", 1);
    let request = route.call(true, Some(json!("sub4-authoritative-payload-key")));
    for header in ["sub4-conflicting-header-one", "sub4-conflicting-header-two"] {
        let (status, body) = route
            .send_with_key_header(&gateway, &request, Some(&token), Some(header))
            .await;
        assert_route_result(route, status, &body);
        assert_no_retry_headers(&backend);
        assert_eq!(
            backend.calls().len(),
            1,
            "changing HTTP key cannot partition payload-key ownership: {body}"
        );
    }
    let fresh = route.call(true, Some(json!("sub4-fresh-payload-key")));
    let (status, body) = route
        .send_with_key_header(
            &gateway,
            &fresh,
            Some(&token),
            Some("sub4-conflicting-header-two"),
        )
        .await;
    assert_route_result(route, status, &body);
    assert_no_retry_headers(&backend);
    let calls = backend.calls();
    assert_eq!(
        calls.len(),
        2,
        "same header plus different payload key is an intentional new operation"
    );
    for call in calls {
        assert!(
            call["params"]["_meta"].get(KEY).is_none(),
            "gateway retry key reached backend: {call}"
        );
        assert_eq!(
            call["params"]["arguments"],
            json!({"fixture_value":"sub4-business-argument"}),
            "business arguments survive control removal exactly"
        );
    }
}

async fn cross_era_keyed_replay(route: Route) {
    let (backend, gateway, oidc) = authenticated_fixture().await;
    let token = oidc.token("alice", 1);
    for modern in [true, false] {
        let request = route.call(modern, Some(json!("sub4-cross-era-key")));
        let (status, body) = route
            .send_with_bearer(&gateway, &request, Some(&token))
            .await;
        assert_backend_result(status, &body);
        assert_eq!(
            backend.calls().len(),
            1,
            "a legacy opt-in retry cannot escape a modern reservation: {body}"
        );
    }
}

/// SUB4 P5, same operation key must be bound to all forwarded arguments.
#[tokio::test]
async fn sub4_fingerprint_meta_changed_business_arguments_conflict() {
    bound_request_mismatch(Route::Meta, false).await;
}
#[tokio::test]
async fn sub4_fingerprint_direct_changed_business_arguments_conflict() {
    bound_request_mismatch(Route::Direct, false).await;
}
/// SUB4.REPR.1, presentation may not partition or bypass execution ownership.
#[tokio::test]
async fn sub4_representation_meta_full_change_conflicts() {
    bound_request_mismatch(Route::Meta, true).await;
}
#[tokio::test]
async fn sub4_representation_direct_full_change_conflicts() {
    bound_request_mismatch(Route::Direct, true).await;
}
#[tokio::test]
async fn sub4_representation_meta_full_is_removed_before_backend() {
    full_is_not_forwarded(Route::Meta).await;
}
#[tokio::test]
async fn sub4_representation_direct_full_is_removed_before_backend() {
    full_is_not_forwarded(Route::Direct).await;
}
/// SUB4.CARRIER.1, payload key is authoritative and never a backend argument.
#[tokio::test]
async fn sub4_carrier_meta_payload_wins_over_http_header() {
    payload_carrier(Route::Meta).await;
}
#[tokio::test]
async fn sub4_carrier_direct_payload_wins_over_http_header() {
    payload_carrier(Route::Direct).await;
}
/// SUB4.COMPAT.1 keyed legacy opt-in cannot bypass the same owner's modern key.
#[tokio::test]
async fn sub4_compat_meta_keyed_cross_era_retry() {
    cross_era_keyed_replay(Route::Meta).await;
}
#[tokio::test]
async fn sub4_compat_direct_keyed_cross_era_retry() {
    cross_era_keyed_replay(Route::Direct).await;
}
