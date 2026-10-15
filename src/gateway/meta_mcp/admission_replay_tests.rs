// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.2 site 1: a deferral that cannot be recorded fails closed.

use std::sync::Arc;

use serde_json::json;

use super::super::ReplayTarget;
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::protocol::{JsonRpcResponse, RequestId};

/// A per-caller backend: identity propagation, so a replay to it defers.
fn per_caller_meta() -> MetaMcp {
    use crate::config::{BackendConfig, FailsafeConfig};
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };
    let backend = Arc::new(crate::backend::Backend::new(
        "idp",
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "idp".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..Default::default()
        },
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    assert!(registry.register(backend), "the backend registers");
    MetaMcp::new(registry)
}

/// R-closed (product seat finding 3; mutant M-closed): outside a request
/// memo the deferral cannot be recorded, so site 1 answers an error instead
/// of `None` (deferred), which would let the caller re-run a completed call
/// unprotected with no lift to serve it. Answering `None` regardless of the
/// record (M-closed) fails this row.
#[test]
fn an_unrecorded_deferral_fails_closed() {
    let meta = per_caller_meta();
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("closed".to_string()),
        ..Default::default()
    };
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        ..ctx(&AllowAll)
    };
    assert!(
        meta.stored_replay_defers("idp", "read"),
        "premise: the target defers"
    );
    let stored = JsonRpcResponse::success(RequestId::Number(4), json!({"content": []}));
    let answer = meta.defer_or_serve_replay(
        "gateway_invoke",
        &json!({"server": "idp", "tool": "read"}),
        &caller,
        Some(ReplayTarget {
            server: "idp".to_string(),
            tool: "read".to_string(),
        }),
        stored,
        None,
    );
    let (response, audit) = answer.expect("R-closed: an unrecorded deferral answered None");
    assert!(
        audit.is_none(),
        "R-closed: no stored facts travel with the refusal"
    );
    let error = response.error.expect("R-closed: the answer is an error");
    assert_eq!(error.code, -32603, "R-closed: {error:?}");
    assert_eq!(
        response.id,
        Some(RequestId::Number(4)),
        "R-closed: the request's id"
    );
}
