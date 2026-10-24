// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8697 credential canary, meta route (lead, 2026-10-24). The census
//! classifies lines that read a stored principal; this catches the rest of
//! that class: a value built from one (a cache or idempotency key) flowing
//! into a log line, an error or a record. An API-key caller drives a cache
//! miss, a hit, a refused-to-cache error, a missing tool, an idempotent
//! replay and a reused key with other arguments, with every log at TRACE
//! captured: its stored principal appears in none of them, in no answer and
//! in no audit record.

use super::*;

/// A backend that lists `read` and answers every call with `reply`: the
/// response cache stores only a listed, declared read (MIK-8393).
struct Listed(Value);

#[async_trait::async_trait]
impl Transport for Listed {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]})
        } else {
            self.0.clone()
        };
        Ok(crate::protocol::JsonRpcResponse::success(
            RequestId::Number(1),
            body,
        ))
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

fn cached_meta(dir: &tempfile::TempDir) -> MetaMcp {
    let registry = Arc::new(BackendRegistry::new());
    let refusal = json!({"content": [{"type": "text", "text": "no"}], "isError": true});
    for (name, reply) in [("alpha", ok_result()), ("beta", refusal)] {
        let backend = Arc::new(Backend::new(
            name,
            BackendConfig::r2_off(),
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        ));
        backend.set_transport_for_test(Arc::new(Listed(reply)));
        // Only a declared read is cached (MIK-8393): the hit path needs one.
        backend.set_read_only_declared_for_test(&["read"]);
        let _ = registry.register(backend);
    }
    let mut meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    let logger = crate::security::TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir
            .path()
            .join("audit.jsonl")
            .to_string_lossy()
            .into_owned(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    meta.enable_transparency_log(Arc::new(logger));
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    meta
}

fn keyed(idempotency_key: &str) -> crate::protocol::mrtr::RetryFields {
    crate::protocol::mrtr::RetryFields {
        input_responses: None,
        request_state: None,
        idempotency_key: Some(idempotency_key.to_owned()),
        malformed: Vec::new(),
        attestation: None,
    }
}

#[test]
fn canary_meta_paths_never_print_the_stored_principal() {
    let who = api_key_caller();
    let stored = who.principal.clone();
    let dir = tempfile::tempdir().expect("dir");
    let mut answers = Vec::new();
    let logs: String = crate::test_log_capture::records(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let meta = cached_meta(&dir);
            let plain = context(&AllowAll, &who);
            let beta = json!({"server": "beta", "tool": "read", "arguments": {}});
            let missing_tool = json!({"server": "alpha", "tool": "nope", "arguments": {}});
            for call in [args(), args(), beta, missing_tool] {
                let answer = meta.invoke_tool(&call, Some("s1"), &plain).await;
                answers.push(format!("{answer:?}"));
            }
            let retry = keyed("idem-canary");
            let mut idempotent = context(&AllowAll, &who);
            idempotent.retry = &retry;
            let other = json!({"server": "alpha", "tool": "read", "arguments": {"n": 2}});
            for call in [args(), args(), other] {
                let answer = meta.invoke_tool(&call, Some("s1"), &idempotent).await;
                answers.push(format!("{answer:?}"));
            }
        });
    })
    .iter()
    .map(Value::to_string)
    .collect();
    for line in [
        "Idempotency key registered as in-flight",
        "Idempotency cache hit",
        "Cached result",
        "Cache hit",
    ] {
        assert!(logs.contains(line), "premise, {line} was captured: {logs}");
    }
    assert!(
        answers.iter().any(|a| a.contains("409")),
        "premise, the reused key was refused: {answers:?}"
    );
    assert!(!logs.contains(&stored), "a log names the principal: {logs}");
    for answer in &answers {
        assert!(!answer.contains(&stored), "an answer names it: {answer}");
    }
    let audit = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap_or_default();
    assert!(!audit.is_empty(), "premise: records were written");
    assert!(!audit.contains(&stored), "a record names it: {audit}");
}
