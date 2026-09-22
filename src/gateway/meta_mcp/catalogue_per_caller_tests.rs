// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7334.CATALOGUE.1 — the per-caller catalogue itself.
//!
//! Its own file because `catalogue_isolation_tests.rs` is at the 800-line
//! ceiling and may not grow, and because these cases need a fixture the others
//! do not: an upstream that answers `tools/list` differently per credential.
//! Without that, "B did not see A's tools" could pass against an upstream with
//! one answer all along.

use super::MetaMcp;
use super::catalogue_isolation_tests::{
    GATEWAY_OAUTH_TOOL, PER_USER_BACKEND, SHARED_BACKEND, SHARED_TOOL, gateway_oauth_backend,
    named_tool, warm_backend,
};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::protocol::{JsonRpcResponse, RequestId, ToolsListResult};
use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// A propagation strategy that mints a distinct credential per identity.
///
/// Deliberately not `SignedAssertionStrategy`: the property under test is that
/// two identities get two catalogues, and a real JWT signer would add key
/// material to a test that is about routing, not about crypto. The minted
/// binding is derived from the subject, so it is the identity that varies.
struct PerIdentityMint;

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for PerIdentityMint {
    async fn propagate(
        &self,
        identity: &crate::key_server::oidc::VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
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

fn identity(subject: &str) -> crate::key_server::oidc::VerifiedIdentity {
    crate::key_server::oidc::VerifiedIdentity {
        subject: subject.to_string(),
        email: format!("{subject}@example.invalid"),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.example.invalid".to_string(),
    }
}

/// A transport that answers `tools/list` with a catalogue chosen by the
/// `Authorization` header it was handed.
///
/// This is the fixture's whole point: the upstream really does serve different
/// tools to different identities, so "B did not see A's tools" can only pass
/// because the fetch carried B's credential — never because the upstream had
/// one answer all along.
struct PerIdentityCatalogue {
    /// Tool name served when no credential arrives (the shared, static-credential view).
    shared: String,
    /// Tool name served to `Bearer minted-for-<subject>`, by subject.
    per_identity: HashMap<String, String>,
    seen: parking_lot::Mutex<Vec<Option<String>>>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for PerIdentityCatalogue {
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
        identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<JsonRpcResponse> {
        assert_eq!(method, "tools/list", "fixture serves only tools/list");
        self.seen.lock().push(identity_key.map(str::to_string));

        let subject = extra_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .and_then(|(_, v)| v.strip_prefix("Bearer minted-for-"))
            .map(str::to_string);
        let tool = subject
            .and_then(|s| self.per_identity.get(&s).cloned())
            .unwrap_or_else(|| self.shared.clone());

        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            ToolsListResult {
                tools: vec![named_tool(&tool)],
                next_cursor: None,
            },
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

/// Tool names the per-identity upstream serves.
const ALPHA_TOOL: &str = "alpha_private_ledger";
const BETA_TOOL: &str = "beta_private_ledger";
const STATIC_TOOL: &str = "gateway_static_ledger";

/// A multi-user gateway with a `required` per-user backend whose upstream
/// answers differently per identity, plus the two controls.
///
/// A transparency logger is attached because a `required` backend fails closed
/// without one — a mint must never reach a caller without a durable audit
/// record — so omitting it would make every case below pass for that reason
/// rather than for the one under test.
async fn per_identity_gateway() -> (MetaMcp, Arc<PerIdentityCatalogue>) {
    per_identity_gateway_logging_to(None).await
}

/// The same fixture, optionally writing its transparency log to a known path so
/// a case can count the records a request produced.
async fn per_identity_gateway_logging_to(
    log_path: Option<&str>,
) -> (MetaMcp, Arc<PerIdentityCatalogue>) {
    let registry = Arc::new(BackendRegistry::new());

    let wire = Arc::new(PerIdentityCatalogue {
        shared: STATIC_TOOL.to_string(),
        per_identity: HashMap::from([
            ("alpha".to_string(), ALPHA_TOOL.to_string()),
            ("beta".to_string(), BETA_TOOL.to_string()),
        ]),
        seen: parking_lot::Mutex::new(Vec::new()),
    });

    let per_user = Arc::new(Backend::new(
        PER_USER_BACKEND,
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "ledger".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..Default::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    per_user.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);
    // Each identity's slot needs a live transport: in production
    // `ensure_entry_started` opens one from config, and there is no real
    // upstream here. The SAME wire serves all three slots on purpose — it
    // discriminates on the credential it is handed, so a catalogue that came
    // back per-identity did so because the fetch carried that identity, not
    // because the fixture handed each slot a different answer.
    for binding in ["alpha@ledger", "beta@ledger"] {
        per_user.set_pooled_transport_for_test(
            &crate::backend::PoolKey::PerUser {
                binding: binding.to_string(),
            },
            Arc::clone(&wire) as Arc<dyn crate::transport::Transport>,
        );
    }
    assert!(registry.register(per_user), "fixture registration");
    assert!(
        registry
            .register(warm_backend(SHARED_BACKEND, SHARED_TOOL, BackendConfig::default()).await),
        "fixture registration"
    );
    assert!(
        registry.register(gateway_oauth_backend().await),
        "fixture registration"
    );

    let mut configs: HashMap<String, RoutingProfileConfig> = HashMap::new();
    configs.insert(
        "open".to_string(),
        RoutingProfileConfig {
            description: "denies nothing, so authorization cannot decide these cases".to_string(),
            ..Default::default()
        },
    );
    let mut meta = MetaMcp::new(registry)
        .with_profile_registry(ProfileRegistry::from_config(&configs, "open"));

    let path = log_path.map_or_else(
        || {
            let file = tempfile::NamedTempFile::new().expect("tempfile");
            let path = file.path().to_string_lossy().to_string();
            std::mem::forget(file);
            path
        },
        str::to_string,
    );
    meta.enable_transparency_log(Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::TransparencyLogConfig {
                enabled: true,
                path,
                key_id: "catalogue-isolation".to_string(),
                shared_secret: String::new(),
            },
        ))
        .expect("transparency logger opens"),
    ));
    meta.set_identity_propagation(Arc::new(PerIdentityMint));
    meta.set_multi_user(true);
    (meta, wire)
}

/// Tool names `gateway_list_tools` answers `caller` with.
pub(super) async fn listed_for(
    meta: &MetaMcp,
    caller: &super::MetaMcpCallerContext<'_>,
) -> Vec<String> {
    let response = meta
        .list_tools(&json!({}), None, caller)
        .await
        .expect("gateway_list_tools must answer");
    response["tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|t| t["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// GIVEN a multi-user gateway whose `required` per-user backend serves a
/// different catalogue to each identity
/// WHEN alpha, beta and an anonymous caller each list tools
/// THEN each identity sees its own catalogue and neither the other's; the
/// anonymous caller sees the backend omitted entirely; and nobody sees the
/// gateway-held-OAuth backend.
///
/// THE THREE ROWS ARE THE ORACLE, and all three are needed. Assert only that
/// beta cannot see alpha's tools and an empty gateway passes. Assert only that
/// alpha sees its own and a gateway that serves the per-user backend to
/// everyone passes — including to the anonymous caller, which is the fail-open
/// the design forbids at §4.6 row 2 and §7 Q1. The third row is what keeps the
/// fix for the first from becoming a blanket loosening of the isolation guard.
#[tokio::test]
async fn each_identity_sees_its_own_catalogue_and_no_one_elses() {
    let (meta, wire) = per_identity_gateway().await;
    let alpha_id = identity("alpha");
    let beta_id = identity("beta");

    let alpha = listed_for(&meta, &super::identified_caller(&alpha_id)).await;
    let beta = listed_for(&meta, &super::identified_caller(&beta_id)).await;
    let anonymous = listed_for(&meta, &super::anonymous_caller()).await;

    // ROW 1 — the mode being built: each identity is served its own catalogue.
    assert!(
        alpha.contains(&ALPHA_TOOL.to_string()),
        "alpha was not served its own catalogue: {alpha:?}"
    );
    assert!(
        beta.contains(&BETA_TOOL.to_string()),
        "beta was not served its own catalogue: {beta:?}"
    );

    // ROW 1, the other direction — isolation, which is only meaningful because
    // each caller demonstrably received something above.
    assert!(
        !alpha.contains(&BETA_TOOL.to_string()),
        "alpha was served beta's catalogue: {alpha:?}"
    );
    assert!(
        !beta.contains(&ALPHA_TOOL.to_string()),
        "beta was served alpha's catalogue: {beta:?}"
    );
    assert!(
        !alpha.contains(&STATIC_TOOL.to_string()) && !beta.contains(&STATIC_TOOL.to_string()),
        "an identified caller was served the gateway's static-credential \
         catalogue under its own identity: alpha={alpha:?} beta={beta:?}"
    );

    // ROW 2 — the caller who presents nothing gets nothing from an
    // identity-bound backend (§4.6 row 2, §7 Q1). Serving it here would be
    // PR #604's descope inverted: a per-user backend handed to an anonymous
    // caller.
    assert!(
        !anonymous.contains(&ALPHA_TOOL.to_string())
            && !anonymous.contains(&BETA_TOOL.to_string())
            && !anonymous.contains(&STATIC_TOOL.to_string()),
        "a `required` per-user backend was disclosed to a caller that presented \
         no identity at all: {anonymous:?}"
    );
    assert!(
        anonymous.contains(&SHARED_TOOL.to_string()),
        "the anonymous caller lost the genuinely shared backend too, so the \
         assertion above is measuring an empty answer rather than isolation: \
         {anonymous:?}"
    );

    // ROW 3 — one gateway-held OAuth login is never per-caller, whatever
    // identity the caller proves (ADR-008 INV-2). This is what fails if the
    // isolation guard is loosened for every authenticated caller rather than
    // only where the fetch runs on that caller's own slot.
    for (who, names) in [
        ("alpha", &alpha),
        ("beta", &beta),
        ("anonymous", &anonymous),
    ] {
        assert!(
            !names.contains(&GATEWAY_OAUTH_TOOL.to_string()),
            "{who} was served a backend behind ONE gateway-held OAuth login on a \
             multi-user gateway: {names:?}"
        );
    }

    // PROVENANCE, not just count: each fetch carried its own identity key, so
    // the two catalogues came from two slots rather than from one upstream that
    // happened to answer twice.
    let mut seen: Vec<String> = wire.seen.lock().iter().filter_map(Clone::clone).collect();
    seen.sort();
    seen.dedup();
    assert_eq!(
        seen,
        vec!["alpha@ledger".to_string(), "beta@ledger".to_string()],
        "the catalogue fetches did not carry one identity binding each"
    );
}

/// Records the transparency log holds after `list_tools`, by action.
fn audit_actions(path: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|entry| {
            entry
                .pointer("/fields/action")
                .or_else(|| entry.get("action"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

/// GIVEN a multi-user gateway with an identity-bound backend
/// WHEN a caller carrying no verified identity lists tools
/// THEN no credential is minted and no audit record is written; and WHEN an
/// identified caller does the same, one is.
///
/// THIS GUARDS A COST, NOT A CORRECTNESS PROPERTY, AND THAT IS WHY IT EXISTS.
/// `caller_credential_for` returns empty *without calling the resolver* when
/// the caller has no verified identity. Dropping that short-circuit would still
/// be correct — the resolver refuses and the guard omits the backend either way
/// — so nothing else in this suite would go red. What it would do is mint once
/// per identity-bound backend on every `tools/list` and write a durable
/// transparency-log record for each, on every deployment whose callers present
/// no identity. That is a silent, unbounded multiplication of an append-only
/// audit log, and a refactor that reintroduces it should fail a test rather
/// than be noticed in production disk usage.
///
/// Two-directional: the identified half must produce a record, or the
/// anonymous half's "zero" passes against a gateway whose audit logging is
/// simply broken.
#[tokio::test]
async fn an_unidentified_caller_mints_nothing_and_audits_nothing() {
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().to_string_lossy().to_string();
    std::mem::forget(file);

    let (meta, _wire) = per_identity_gateway_logging_to(Some(&path)).await;

    let anonymous = listed_for(&meta, &super::anonymous_caller()).await;
    let after_anonymous = audit_actions(&path);
    assert!(
        after_anonymous.is_empty(),
        "an unidentified caller's discovery reached the credential resolver: \
         {after_anonymous:?}. Every identity-bound backend would mint and audit \
         once per `tools/list`, on every deployment whose callers present none"
    );
    assert!(
        anonymous.contains(&SHARED_TOOL.to_string()),
        "the anonymous caller's discovery did not run at all, so the assertion \
         above holds for a request that never happened: {anonymous:?}"
    );

    let alpha_id = identity("alpha");
    let alpha = listed_for(&meta, &super::identified_caller(&alpha_id)).await;
    let after_alpha = audit_actions(&path);
    assert!(
        alpha.contains(&ALPHA_TOOL.to_string()),
        "the identified caller was not served its own catalogue: {alpha:?}"
    );
    assert!(
        after_alpha.iter().any(|action| action == "idp_mint"),
        "an identified caller's catalogue fetch minted a credential without a \
         durable audit record: {after_alpha:?}. A mint must never reach a caller \
         unaudited, and without this the zero above proves only that nothing is \
         ever logged"
    );
}
