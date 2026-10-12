// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8393 R7 through the invoke path: the cache asks the CALLER's slot.
//!
//! The unit row pins `is_read_only_for(binding)`. This one pins that the
//! invoke path hands the gate the caller's own dispatch binding: a gate fed
//! the shared slot (or any other caller's) would admit a call whose own
//! listing never declared the tool read-only.

use super::*;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;

const TOOL: &str = "lookup";

/// Mints `Bearer minted-for-<subject>`, bound to `<subject>@ledger`.
struct Mint;

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for Mint {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> std::result::Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        Ok(crate::identity_propagation::PropagatedCredential {
            headers: vec![(
                "Authorization".to_string(),
                format!("Bearer minted-for-{}", identity.subject),
            )],
            expires_at: i64::MAX,
            cache_binding: format!("{}@{}", identity.subject, backend.audience),
            subject_key: identity.subject.clone(),
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

/// Lists `TOOL` declared read-only and counts `tools/call`.
struct Wire(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl crate::transport::Transport for Wire {
    async fn request(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.request_with_headers(
            method,
            params,
            &[],
            None,
            crate::transport::ResendPermission::Permitted,
        )
        .await
    }

    async fn request_with_headers(
        &self,
        method: &str,
        _params: Option<serde_json::Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let body = match method {
            "tools/list" => json!({"tools": listing(TOOL, &ann(READ_ONLY))}),
            "tools/call" => {
                self.0.fetch_add(1, Ordering::SeqCst);
                json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
            }
            _ => json!({}),
        };
        Ok(crate::protocol::JsonRpcResponse::success(
            RequestId::Number(1),
            body,
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

fn person(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.to_string(),
        email: format!("{subject}@example.invalid"),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.example.invalid".to_string(),
    }
}

/// R7 (invoke level): the shared slot declares `TOOL` read-only; bob's own
/// slot has never been listed. Enforcement is off, so nothing lists bob's
/// slot ahead of the gate. Bob's repeat must reach the backend; once bob's
/// own fill declares the tool, his repeat is a hit (the control).
#[tokio::test]
async fn the_cache_asks_the_callers_own_slot() {
    use crate::backend::{Backend, BackendRegistry, PoolKey};
    use crate::config::{BackendConfig, FailsafeConfig, InputSchemaEnforcement};

    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        "ledger",
        BackendConfig {
            input_schema_enforcement: InputSchemaEnforcement::Off,
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "ledger".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let wire = || Arc::new(Wire(Arc::clone(&calls))) as Arc<dyn crate::transport::Transport>;
    backend.set_transport_for_test(wire());
    backend.set_pooled_transport_for_test(
        &PoolKey::PerUser {
            binding: "bob@ledger".to_string(),
        },
        wire(),
    );
    backend.set_read_only_declared_for_test(&[TOOL]);
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(Arc::clone(&backend)));
    let mut meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    meta.set_identity_propagation(Arc::new(Mint) as _);
    let audit = tempfile::NamedTempFile::new().expect("tempfile");
    let logger = crate::security::TransparencyLogger::open(Arc::new(
        crate::security::TransparencyLogConfig {
            enabled: true,
            path: audit.path().to_string_lossy().to_string(),
            key_id: "cache-slot".to_string(),
            ..crate::security::TransparencyLogConfig::default()
        },
    ))
    .expect("transparency logger opens");
    meta.enable_transparency_log(Arc::new(logger));
    meta.set_multi_user(true);

    let bob = person("bob");
    let call = async || {
        let answer = meta
            .invoke_tool(
                &json!({"server": "ledger", "tool": TOOL, "arguments": {}}),
                Some("session-bob"),
                &crate::gateway::meta_mcp::MetaMcpCallerContext {
                    verified_identity: Some(&bob),
                    ..allow_all_ctx_named(Some("bob"), None)
                },
            )
            .await
            .expect("bob's call is answered");
        assert_eq!(answer["isError"], json!(false), "{answer}");
    };

    call().await;
    call().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "bob's own slot declared nothing; another slot's declaration admitted his call"
    );

    backend
        .get_tools_for_binding(
            Some("bob@ledger"),
            &[(
                "Authorization".to_string(),
                "Bearer minted-for-bob".to_string(),
            )],
        )
        .await
        .expect("bob's own fill");
    call().await;
    call().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "after bob's own fill declared the tool, his repeat is a hit"
    );
}
