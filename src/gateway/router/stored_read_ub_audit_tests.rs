// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 (lead Claude seat, second pass): the repeat arm shares the
//! stored-read pre-pass, whose account half can run the live refusal (and
//! its `idp_refuse` audit record) for an unbindable caller. A repeat judges
//! its accounts live, so the pre-pass must add no record of its own.

use super::*;

/// The `idp_refuse` records the log holds for [`BACKEND`].
fn refusals(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["action"] == "idp_refuse" && entry["backend"] == BACKEND)
        .count()
}

/// Ub-repeat: an unbindable caller's repeated keyed task call writes exactly
/// the refusal records its live call writes. Red with the account half of
/// the pre-pass run on the repeat arm: the repeat writes one more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ub_an_unbindable_callers_repeat_writes_the_live_calls_audit_records() {
    let auth = AuthConfig::default();
    let audit = tempfile::tempdir().expect("a log directory");
    let log_path = audit.path().join("audit.jsonl");
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: log_path.to_string_lossy().into_owned(),
                key_id: "8392".to_string(),
                ..crate::security::transparency_log::TransparencyLogConfig::default()
            },
        ))
        .expect("open log"),
    );
    let mut gateway = DirectAccountGateway::new(auth.clone(), &Binding::Connected);
    let (mut state, _store) = super::super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    let mut meta = gateway
        .take_meta()
        .with_surfaced_tools(vec![SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: TOOL.to_string(),
        }]);
    meta.enable_transparency_log(Arc::clone(&log));
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(log);
    let router = super::super::create_router(Arc::clone(&state));
    let nobody = |params: Value| {
        let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params});
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header("mcp-name", "gateway_invoke")
            .body(axum::body::Body::from(body.to_string()))
            .expect("a request");
        request
            .extensions_mut()
            .insert(crate::key_server::oidc::VerifiedIdentity {
                subject: String::new(),
                email: "nobody@example.invalid".to_string(),
                name: None,
                groups: vec![],
                issuer: "https://issuer.example.invalid".to_string(),
            });
        let router = router.clone();
        async move {
            let response = router.oneshot(request).await.expect("an answer");
            let bytes = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("a body");
            serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null)
        }
    };
    let call = json!({"name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
        "_meta": modern_meta()});
    let mut tasked = call.clone();
    tasked["task"] = json!({});
    tasked["_meta"][crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("s1-ub-repeat");
    let made = nobody(tasked.clone()).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while state
        .task_executor
        .service
        .store
        .status_for_test(&id)
        .is_some_and(|status| status == crate::protocol::tasks::TaskStatus::Working)
    {
        assert!(
            std::time::Instant::now() < bound,
            "premise: the task settles"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let before_live = refusals(&log_path);
    let live = nobody(call).await;
    assert!(
        live.get("error").is_some(),
        "premise: the live call is refused: {live}"
    );
    let live_records = refusals(&log_path) - before_live;
    assert!(
        live_records >= 1,
        "premise: the live refusal is recorded"
    );
    let before_repeat = refusals(&log_path);
    let _ = nobody(tasked).await;
    assert_eq!(
        refusals(&log_path) - before_repeat,
        live_records,
        "Ub-repeat: the repeat writes exactly the live call's refusal records"
    );
    assert_eq!(gateway.dispatched(), 0, "Ub-repeat: nothing dispatched");
}
