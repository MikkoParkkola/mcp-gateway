// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 review F4 (stdio): the route stage's refusal code is the one the
//! withheld call's record names, as on `/mcp`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::{
    AllowAll, AuthorizationError, CallTarget, Decision, ToolAuthorizer, ToolTarget, Transport,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::visible::{denial_code, with_visibility_memo};
use crate::protocol::RequestId;

/// A code no other refusal uses, so the record can only have it from here.
const CODE: i32 = -32042;

/// Refuses a call that carries arguments and allows one that carries none:
/// the gate re-asks with `{}`, so only the route stage sees this refusal.
struct RefusesArguments;

impl ToolAuthorizer for RefusesArguments {
    fn quota_principal(&self) -> Option<&crate::gateway::auth::QuotaPrincipal> {
        None
    }
    fn decide<'a>(&'a self, target: ToolTarget<'a>) -> Decision<'a> {
        if target.arguments.as_object().is_some_and(|a| !a.is_empty()) {
            return Decision::of(Err(AuthorizationError::forbidden(
                CODE,
                "refused for its arguments".to_owned(),
            )));
        }
        AllowAll.decide(target)
    }
    fn admits_backend(&self, _server: &str) -> bool {
        true
    }
    fn transport(&self) -> Transport {
        AllowAll.transport()
    }
    fn caller_name(&self) -> Option<&str> {
        None
    }
}

/// A target the route refuses for its arguments passes as withheld, and its
/// code is noted for the call's one record. Without the note, the gate's own
/// check (which allows `{}`) leaves the record no code and it is not
/// classed `denied`.
#[tokio::test]
async fn a_withheld_targets_route_code_is_noted_for_its_record() {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ))));
    let meta = MetaMcp::new(registry);
    let scope = crate::gateway::meta_mcp::InvokeScope {
        authorizer: &RefusesArguments,
        is_admin: false,
        api_key_name: None,
        agent_id: None,
        grant_subject: None,
        caller: crate::identity_propagation::CallerProof::Anonymous,
    };
    let target = CallTarget {
        server: "alpha".to_owned(),
        tool: "read".to_owned(),
        arguments: std::borrow::Cow::Owned(json!({"q": "x"})),
    };
    let (answer, noted) = with_visibility_memo(async {
        let answer = super::authorize_targets(
            &meta,
            scope,
            (std::slice::from_ref(&target), 1),
            &RequestId::Number(1),
        );
        (answer, denial_code("alpha", "read"))
    })
    .await;
    assert!(
        answer.is_none(),
        "premise: a withheld target passes: {answer:?}"
    );
    assert_eq!(noted, Some(CODE), "the route's refusal code was not noted");
}
