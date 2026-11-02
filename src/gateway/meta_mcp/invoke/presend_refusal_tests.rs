// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A tools/call refused inside its backend's own send, before any byte
//! leaves (a secret rule that cannot be applied), is a call refused before
//! its backend: the invocation's pre-send flag reads refused, its delivery
//! record says so, and its idempotency key is released. A failure after the
//! send is not.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::gateway::meta_mcp::dispatch_log::PreSend;
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::protocol::mrtr::RetryFields;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget};
use crate::secrets::SecretResolver;

const SECRET: &str = "presend-secret-c41d";

/// What the backend's transport does with a `tools/call`.
#[derive(Clone, Copy)]
enum Answer {
    Served,
    /// Fails once its bytes left: may have run.
    LostAfterSend,
    /// Never connected: nothing was sent.
    NeverConnected,
}

/// A transport that lists one tool, counts every `tools/call` that reaches
/// it and answers as `answer` says.
struct Counted {
    calls: Arc<AtomicUsize>,
    answer: Answer,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Counted {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            let tool = json!({"name": "read", "inputSchema": {"type": "object"}});
            return Ok(JsonRpcResponse::success(id, json!({"tools": [tool]})));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.answer {
            Answer::Served => Ok(JsonRpcResponse::success(
                id,
                json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
            )),
            Answer::LostAfterSend => Err(crate::Error::Transport("connection reset".into())),
            Answer::NeverConnected => Err(crate::Error::TransportConnect("refused".into())),
        }
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    /// These rows judge what is refused before a send, not an answer's echo,
    /// so it stands in for a transport holding its set (DELTA-10 refuses an
    /// injected call on one that does not).
    fn redacts_injected_values(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

fn rule(inject_as: InjectTarget, key: &str, value: &str) -> CredentialRule {
    CredentialRule {
        name: "api".to_string(),
        credential_type: CredentialType::ApiKey,
        value: value.to_string(),
        inject_as,
        inject_key: key.to_string(),
        tools: vec!["*".to_string()],
    }
}

/// One case: the backend `svc` built from `transport` and `rules`, stamped
/// with a resolver when `resolved`, answering as `answer`, with idempotency on.
struct Case {
    meta: MetaMcp,
    backend: Arc<Backend>,
    calls: Arc<AtomicUsize>,
}

fn case(
    transport: TransportConfig,
    rules: Vec<CredentialRule>,
    resolved: bool,
    answer: Answer,
) -> Case {
    let backend = Arc::new(Backend::new(
        "svc",
        BackendConfig {
            transport,
            secrets: rules,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    if resolved {
        backend.stamp_secret_resolver(Arc::new(SecretResolver::new()));
    }
    let calls = Arc::new(AtomicUsize::new(0));
    backend.set_transport_for_test(Arc::new(Counted {
        calls: Arc::clone(&calls),
        answer,
    }));
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(Arc::clone(&backend)));
    let mut meta = MetaMcp::new(registry);
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    Case {
        meta,
        backend,
        calls,
    }
}

/// An argument rule with no resolver stamped: refused in `outbound`.
fn unresolved() -> Case {
    case(
        TransportConfig::default(),
        vec![rule(InjectTarget::Argument, "api_key", SECRET)],
        false,
        Answer::Served,
    )
}

/// What one call came to, read inside its own delivery cell.
struct Delivered {
    pre_send: PreSend,
    refused_effect: bool,
}

/// One `gateway_invoke` of `svc:read` under `key`, in a delivery of its own.
async fn invoke(meta: &MetaMcp, key: Option<&str>) -> Delivered {
    let fields = RetryFields {
        idempotency_key: key.map(str::to_owned),
        ..RetryFields::default()
    };
    let caller = MetaMcpCallerContext {
        retry: &fields,
        ..ctx(&AllowAll)
    };
    let call = json!({"server": "svc", "tool": "read", "arguments": {}});
    crate::gateway::delivery_facts::scope(async {
        let invoked =
            Box::pin(meta.invoke_tool_sourced(&call, None, &caller, "t".to_owned())).await;
        let refused_effect =
            crate::gateway::delivery_facts::snapshot().is_some_and(|facts| facts.refused());
        Delivered {
            pre_send: invoked.pre_send,
            refused_effect,
        }
    })
    .await
}

/// R1: an argument rule with no resolver refuses the call in `outbound`,
/// before its backend: the pre-send flag reads refused, nothing was sent.
#[tokio::test]
async fn a_secret_rule_with_no_resolver_is_refused_before_its_backend() {
    let case = unresolved();
    let delivered = invoke(&case.meta, None).await;
    assert_eq!(
        case.calls.load(Ordering::SeqCst),
        0,
        "premise: no tools/call was sent"
    );
    assert_eq!(
        delivered.pre_send,
        PreSend::Refused,
        "the refusal read as a dispatched call"
    );
}

/// R7: the delivery record of such a call says `refused`.
#[tokio::test]
async fn a_call_refused_in_its_send_is_recorded_as_refused() {
    let case = unresolved();
    let delivered = invoke(&case.meta, None).await;
    assert_eq!(
        case.calls.load(Ordering::SeqCst),
        0,
        "premise: no tools/call was sent"
    );
    assert!(
        delivered.refused_effect,
        "the delivery record did not say refused"
    );
}

/// R4: each class of secret refusal the meta route can reach reads refused
/// before its backend.
#[tokio::test]
async fn every_reachable_secret_refusal_class_is_refused_before_its_backend() {
    let stdio = TransportConfig::Stdio {
        command: "/bin/true".to_string(),
        cwd: None,
        protocol_version: None,
    };
    let classes = [
        (
            "no resolver",
            TransportConfig::default(),
            rule(InjectTarget::Argument, "api_key", SECRET),
            false,
        ),
        (
            "query rule",
            TransportConfig::default(),
            rule(InjectTarget::Query, "api_key", SECRET),
            true,
        ),
        (
            "header rule on stdio",
            stdio,
            rule(InjectTarget::Header, "X-Api-Key", SECRET),
            true,
        ),
        (
            "value that does not resolve",
            TransportConfig::default(),
            rule(
                InjectTarget::Argument,
                "api_key",
                "{env.PRESEND_REFUSAL_UNSET_9095}",
            ),
            true,
        ),
        (
            "invalid header value",
            TransportConfig::default(),
            rule(InjectTarget::Header, "X-Api-Key", "line\nbreak"),
            true,
        ),
    ];
    for (class, transport, rule, resolved) in classes {
        let case = case(transport, vec![rule], resolved, Answer::Served);
        let delivered = invoke(&case.meta, None).await;
        assert_eq!(
            case.calls.load(Ordering::SeqCst),
            0,
            "{class}: premise: nothing was sent"
        );
        assert_eq!(
            delivered.pre_send,
            PreSend::Refused,
            "{class}: read as a dispatched call"
        );
    }
}

/// R6 (OUT.3): an idempotent call refused in its send releases its key, so
/// the same-key retry after the rule is fixed runs.
#[tokio::test]
async fn a_call_refused_in_its_send_releases_its_key() {
    let case = unresolved();
    invoke(&case.meta, Some("k-9095")).await;
    assert_eq!(
        case.calls.load(Ordering::SeqCst),
        0,
        "premise: no tools/call was sent"
    );
    case.backend
        .stamp_secret_resolver(Arc::new(SecretResolver::new()));
    invoke(&case.meta, Some("k-9095")).await;
    assert_eq!(
        case.calls.load(Ordering::SeqCst),
        1,
        "the same-key retry was answered from the refusal instead of running"
    );
}

/// R5 (OUT.2), control: a call lost after its bytes left may have run: the
/// flag stays clear and the key is kept.
#[tokio::test]
async fn a_failure_after_the_send_is_not_marked_refused() {
    let case = case(
        TransportConfig::default(),
        Vec::new(),
        true,
        Answer::LostAfterSend,
    );
    let first = invoke(&case.meta, Some("k-sent")).await;
    let sent = case.calls.load(Ordering::SeqCst);
    assert!(sent >= 1, "premise: the call reached its transport");
    assert_eq!(
        first.pre_send,
        PreSend::Clear,
        "a sent call read as refused"
    );
    invoke(&case.meta, Some("k-sent")).await;
    assert_eq!(
        case.calls.load(Ordering::SeqCst),
        sent,
        "the key was released after a send"
    );
}

/// R17, control: a first attempt that never connected releases its key, as
/// before.
#[tokio::test]
async fn a_call_that_never_connected_still_releases_its_key() {
    let case = case(
        TransportConfig::default(),
        Vec::new(),
        true,
        Answer::NeverConnected,
    );
    let first = invoke(&case.meta, Some("k-connect")).await;
    let tried = case.calls.load(Ordering::SeqCst);
    assert!(tried >= 1, "premise: the call reached its transport");
    assert_eq!(
        first.pre_send,
        PreSend::Refused,
        "a never-sent call read as dispatched"
    );
    invoke(&case.meta, Some("k-connect")).await;
    assert!(
        case.calls.load(Ordering::SeqCst) > tried,
        "the key was kept for a call never sent"
    );
}
