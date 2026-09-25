// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An identified caller on a multi-user gateway reads what it was listed.
//!
//! `resources/list` admits a `required` per-user backend for a caller whose
//! fetch carries its own identity. The read that follows must reach the same
//! backend on the same terms, under that identity, with the credential minted
//! once for the request. Own file because the parent test module would cross
//! the 800-line ceiling.

use super::super::MetaMcp;
use crate::backend::{Backend, BackendRegistry, PoolKey};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::gateway::router::CallerStanding;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::{JsonRpcResponse, RequestId};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const URI: &str = "mem://ledger/alpha-doc";

/// Mints `Bearer minted-for-<subject>` and counts every mint.
#[derive(Default)]
struct CountingMint {
    mints: AtomicUsize,
}

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for CountingMint {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        self.mints.fetch_add(1, Ordering::SeqCst);
        let subject_key = identity.subject.clone();
        Ok(crate::identity_propagation::PropagatedCredential {
            headers: vec![(
                "Authorization".to_string(),
                format!("Bearer minted-for-{subject_key}"),
            )],
            expires_at: i64::MAX,
            cache_binding: format!("{subject_key}@{}", backend.audience),
            subject_key,
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

/// Serves `URI` only to a request carrying alpha's minted credential, and
/// records the credential every request carried.
#[derive(Default)]
struct AlphaOnlyWire {
    seen: parking_lot::Mutex<Vec<(String, Option<String>)>>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for AlphaOnlyWire {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
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
        _params: Option<Value>,
        extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<JsonRpcResponse> {
        let bearer = extra_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.clone());
        let alpha = bearer.as_deref() == Some("Bearer minted-for-alpha");
        self.seen.lock().push((method.to_string(), bearer));
        let body = match method {
            "resources/list" if alpha => json!({ "resources": [{ "uri": URI, "name": "doc" }] }),
            "resources/list" => json!({ "resources": [] }),
            "resources/read" => json!({ "contents": [{ "uri": URI, "text": "alpha" }] }),
            _ => json!({}),
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), body))
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

fn alpha() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.example.invalid".to_string(),
    }
}

/// The durable audit record every mint requires; without one the resolver
/// refuses to mint at all. The file lives as long as the returned handle.
fn audit_log() -> (
    Arc<crate::security::TransparencyLogger>,
    tempfile::NamedTempFile,
) {
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let config = crate::security::TransparencyLogConfig {
        enabled: true,
        path: file.path().to_string_lossy().to_string(),
        key_id: "caller-forward".to_string(),
        ..crate::security::TransparencyLogConfig::default()
    };
    let logger = crate::security::TransparencyLogger::open(Arc::new(config))
        .expect("transparency logger opens");
    (Arc::new(logger), file)
}

/// A multi-user gateway with one `required`, per-user propagating backend.
fn gateway() -> (
    MetaMcp,
    Arc<AlphaOnlyWire>,
    Arc<CountingMint>,
    tempfile::NamedTempFile,
) {
    let config = BackendConfig {
        transport: TransportConfig::Http {
            http_url: "https://ledger.invalid/mcp".to_string(),
            streamable_http: true,
            protocol_version: None,
        },
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "ledger".to_string(),
            required: true,
            session_mode: SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..Default::default()
    };
    let backend = Arc::new(Backend::new(
        "ledger",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let wire = Arc::new(AlphaOnlyWire::default());
    let dynamic = || Arc::clone(&wire) as Arc<dyn crate::transport::Transport>;
    backend.set_transport_for_test(dynamic());
    backend.set_pooled_transport_for_test(
        &PoolKey::PerUser {
            binding: "alpha@ledger".to_string(),
        },
        dynamic(),
    );
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend), "fixture registration");
    let mint = Arc::new(CountingMint::default());
    let mut meta = MetaMcp::new(registry);
    meta.set_identity_propagation(Arc::clone(&mint) as _);
    let (logger, audit_file) = audit_log();
    meta.enable_transparency_log(logger);
    meta.set_multi_user(true);
    (meta, wire, mint, audit_file)
}

#[tokio::test]
async fn identified_caller_reads_the_resource_it_was_listed_under_its_own_identity() {
    let (meta, wire, mint, _audit_file) = gateway();
    let who = alpha();

    let listed = meta
        .handle_resources_list(RequestId::Number(1), None, None, Some(&who))
        .await;
    assert!(
        listed
            .result
            .as_ref()
            .is_some_and(|r| r.to_string().contains(URI)),
        "the identified caller is listed its own resource: {listed:?}"
    );

    let mints_before_read = mint.mints.load(Ordering::SeqCst);
    let params = json!({ "uri": URI });
    let read = meta
        .handle_resources_read(
            RequestId::Number(2),
            Some(&params),
            CallerStanding::Standard,
            None,
            Some(&who),
        )
        .await;
    assert!(
        read.error.is_none()
            && read
                .result
                .as_ref()
                .is_some_and(|r| r.to_string().contains("alpha")),
        "a resource listed to the caller must be readable by it, not answered as absent: {read:?}"
    );
    let reads: Vec<Option<String>> = wire
        .seen
        .lock()
        .iter()
        .filter(|(m, _)| m == "resources/read")
        .map(|(_, bearer)| bearer.clone())
        .collect();
    assert_eq!(
        reads,
        vec![Some("Bearer minted-for-alpha".to_string())],
        "the read must go upstream once, under the caller's own credential"
    );
    assert_eq!(
        mint.mints.load(Ordering::SeqCst) - mints_before_read,
        1,
        "one read resolves the caller's credential once, for the lookup and the forward"
    );
}
