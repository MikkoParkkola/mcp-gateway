// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7334.CATALOGUE.1 — the resend verdict is per-slot, like its source.
//!
//! The set of tools permitted to be resent is derived from a `tools/list` on
//! every fill (`metadata.rs`, inside `get_tools_for_binding`) and read on the
//! dispatch path to decide whether a failed `tools/call` may be re-issued
//! (`ops.rs`, `resend_decision`). Membership is the ONLY thing that grants that
//! permission (ADR-012 amendment A1), and absent means deny.
//!
//! WHY THIS NEEDS ITS OWN CASE. The catalogue cases prove the tool LISTS
//! separate per caller. They say nothing about this set, which is a second
//! consumer of the same fill and was left on `Backend` in the first draft of
//! the design. One identity's fill would then have decided another identity's
//! retry of a NON-IDEMPOTENT call — a duplicate side effect authorised by
//! somebody else's catalogue. No grep found it: the field is not named like a
//! cache and was not among those being deleted. The compiler found it, once the
//! fields were gone.
//!
//! Both directions, in one fixture: each identity's slot must permit its own
//! resend-safe tool AND must not permit the other's. With a backend-wide set
//! the second fill overwrites the first, so the earlier identity's slot answers
//! with the later identity's permissions and the "must not" half fails.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;

use super::Backend;
use super::pool::PoolKey;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::protocol::{JsonRpcResponse, RequestId, Tool, ToolAnnotations, ToolsListResult};
use crate::transport::{ResendPermission, Transport};
use crate::{Error, Result};

/// Alpha's upstream declares this one resend-safe; beta's does not declare it.
const ALPHA_SAFE: &str = "alpha_retry_safe";
/// Beta's upstream declares this one resend-safe; alpha's does not declare it.
const BETA_SAFE: &str = "beta_retry_safe";

fn tool(name: &str, resend_safe: bool) -> Tool {
    Tool {
        name: name.to_string(),
        title: None,
        description: Some(format!("{name} resend fixture")),
        input_schema: serde_json::json!({ "type": "object" }),
        output_schema: None,
        // Only an EXPLICIT `true` grants permission; absent and false both
        // deny (`annotations::prepare_tool_metadata`). `None` here is therefore
        // a real denial, not a gap in the fixture.
        annotations: resend_safe.then_some(ToolAnnotations {
            title: None,
            read_only_hint: None,
            destructive_hint: None,
            idempotent_hint: Some(true),
            open_world_hint: None,
        }),
        role: None,
        projection: None,
    }
}

/// An upstream that declares a different resend-safe tool per identity.
///
/// Both tools appear in BOTH catalogues; only the annotation differs. So a slot
/// answering with the wrong permissions cannot be explained by it having seen a
/// different tool list — it saw the same names, with the other caller's hints.
struct PerIdentityAnnotations;

#[async_trait]
impl Transport for PerIdentityAnnotations {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        Err(Error::BackendUnavailable(
            "a per-identity fill must not reach the identity-less path".to_string(),
        ))
    }

    async fn request_with_headers(
        &self,
        method: &str,
        _params: Option<Value>,
        _extra_headers: &[(String, String)],
        identity_key: Option<&str>,
        _resend: ResendPermission,
    ) -> Result<JsonRpcResponse> {
        assert_eq!(method, "tools/list", "fixture serves only tools/list");
        let alpha = identity_key == Some("alpha");
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            ToolsListResult {
                tools: vec![tool(ALPHA_SAFE, alpha), tool(BETA_SAFE, !alpha)],
                next_cursor: None,
            },
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

fn per_user_backend() -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        "resend_hub",
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
    for binding in ["alpha", "beta"] {
        backend.set_pooled_transport_for_test(
            &PoolKey::PerUser {
                binding: binding.to_string(),
            },
            Arc::new(PerIdentityAnnotations) as Arc<dyn Transport>,
        );
    }
    backend
}

fn permitted(backend: &Backend, binding: &str) -> std::collections::HashSet<String> {
    backend
        .pooled_entry(&PoolKey::PerUser {
            binding: binding.to_string(),
        })
        .resend_permitted
        .read()
        .clone()
}

/// GIVEN one `per_user` backend whose upstream annotates the same two tools
/// differently for two identities
/// WHEN each identity fills its own catalogue, alpha first
/// THEN each slot permits resending only the tool ITS upstream declared safe.
///
/// The ordering is deliberate: alpha fills first, so a backend-wide set would
/// carry beta's later answer by the time alpha is read. That is the exact
/// failure — alpha's retry verdict decided by beta's catalogue.
#[tokio::test]
async fn one_identity_fill_does_not_decide_another_identity_resend_verdict() {
    let backend = per_user_backend();

    backend
        .get_tools_for_binding(Some("alpha"), &[])
        .await
        .expect("alpha catalogue fill");
    backend
        .get_tools_for_binding(Some("beta"), &[])
        .await
        .expect("beta catalogue fill");

    let alpha = permitted(&backend, "alpha");
    let beta = permitted(&backend, "beta");

    assert!(
        alpha.contains(ALPHA_SAFE),
        "alpha's slot lost the permission its own upstream granted: {alpha:?} — \
         without this the assertions below would hold for a gateway that permits \
         nothing at all, which denies every retry rather than isolating them"
    );
    assert!(
        beta.contains(BETA_SAFE),
        "beta's slot lost the permission its own upstream granted: {beta:?}"
    );

    assert!(
        !alpha.contains(BETA_SAFE),
        "alpha may resend a call only BETA's upstream declared retry-safe: \
         {alpha:?}. A non-idempotent tool would be re-issued on the strength of \
         another caller's catalogue, duplicating its side effect (ADR-012 A1)"
    );
    assert!(
        !beta.contains(ALPHA_SAFE),
        "beta may resend a call only ALPHA's upstream declared retry-safe: {beta:?}"
    );
}

/// GIVEN the same backend
/// WHEN nothing has filled the shared slot
/// THEN it permits nothing, and a per-identity fill does not populate it.
///
/// Absent means deny, so a shared slot that inherited either identity's
/// permissions would grant retries to every caller that resolves no binding —
/// the leak in its widest form.
#[tokio::test]
async fn a_per_identity_fill_never_reaches_the_shared_resend_set() {
    let backend = per_user_backend();

    backend
        .get_tools_for_binding(Some("alpha"), &[])
        .await
        .expect("alpha catalogue fill");

    let shared = backend
        .pooled_entry(&PoolKey::Shared)
        .resend_permitted
        .read()
        .clone();
    assert!(
        shared.is_empty(),
        "a per-identity fill populated the shared resend set, so a caller with \
         no binding inherited one identity's retry permissions: {shared:?}"
    );
    assert!(
        permitted(&backend, "alpha").contains(ALPHA_SAFE),
        "alpha's own fill did not land either, so the assertion above passes \
         because nothing was fetched rather than because it stayed on its slot"
    );
}
