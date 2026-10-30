// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A playbook step refused by the caller's policy at dispatch, where the gate
//! (which judges the name with `{}` arguments) let it through: the playbook
//! ends on the gateway's refusal and records refused.

use std::sync::atomic::Ordering;

use serde_json::json;

use crate::gateway::authz::{
    AllowAll, AuthorizationError, BackendGrant, Decision, ToolAuthorizer, ToolTarget, Transport,
};
use crate::gateway::delivery_facts;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx};
use crate::protocol::RequestId;

/// Refuses a call that carries arguments and allows one that carries none,
/// so the name stays visible and only the dispatch-time check refuses it.
struct RefusesArguments;

impl ToolAuthorizer for RefusesArguments {
    fn quota_principal(&self) -> Option<&crate::gateway::auth::QuotaPrincipal> {
        None
    }
    fn backend_grant(&self) -> BackendGrant<'_> {
        BackendGrant::Unscoped
    }
    fn decide<'a>(&'a self, target: ToolTarget<'a>) -> Decision<'a> {
        if target.arguments.as_object().is_some_and(|a| !a.is_empty()) {
            return Decision::of(Err(AuthorizationError::forbidden(
                -32003,
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

const ONE_STEP: &str = r"
name: argued
description: one step whose arguments the policy refuses
on_error: abort
steps:
  - name: read
    server: alpha
    tool: read
    arguments: {q: 1}
";

/// The same step under `continue`: the playbook carries on and delivers.
const ONWARD: &str = r"
name: onward
description: carries on past the refused step
on_error: continue
steps:
  - name: read
    server: alpha
    tool: read
    arguments: {q: 1}
";

/// `name` from `yaml`, run by a caller judged by [`RefusesArguments`]: the
/// answer, the delivery record's fields, and how many calls were sent.
async fn run(
    yaml: &str,
    name: &str,
) -> (
    serde_json::Value,
    serde_json::Map<String, serde_json::Value>,
    usize,
) {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(crate::yaml::from_str(yaml).expect("the playbook parses"));
    meta.set_playbook_engine(engine);
    let mut fields = serde_json::Map::new();
    let answer = delivery_facts::scope(async {
        let response = Box::pin(meta.handle_tools_call(
            RequestId::Number(1),
            "gateway_run_playbook",
            json!({ "name": name }),
            None,
            ctx(&RefusesArguments),
        ))
        .await;
        delivery_facts::record_fields(delivery_facts::snapshot().as_ref(), false, &mut fields);
        serde_json::to_value(&response).expect("response is JSON")
    })
    .await;
    (answer, fields, calls.load(Ordering::SeqCst))
}

/// Control: a playbook carrying on past the same refusal still delivers its
/// report, so the step's refusal never marks it.
#[tokio::test]
async fn a_playbook_past_a_step_refused_at_dispatch_records_no_refused() {
    let (answer, fields, sent) = run(ONWARD, "onward").await;
    assert!(
        answer.to_string().contains("steps_failed"),
        "premise: the report was delivered: {answer}"
    );
    assert_eq!(sent, 0, "premise: never sent");
    assert_eq!(fields.get("response_effect"), None, "{fields:?}");
}

#[tokio::test]
async fn a_playbook_step_the_policy_refuses_at_dispatch_records_refused() {
    let (answer, fields, sent) = run(ONE_STEP, "argued").await;
    // A step's refusal is answered neutrally (A3), whatever the policy said.
    assert_eq!(
        answer["error"]["message"],
        crate::gateway::meta_mcp::STEP_NOT_PERMITTED,
        "premise: the dispatch-time refusal ended it: {answer}"
    );
    assert_eq!(sent, 0, "premise: never sent");
    assert_eq!(
        fields.get("response_effect"),
        Some(&json!("refused")),
        "{fields:?}"
    );
}
