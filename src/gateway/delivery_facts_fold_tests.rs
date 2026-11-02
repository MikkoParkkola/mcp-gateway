// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whose failure a composite's delivered answer counts as: a step's fold
//! survives the step's own cell when the step's error wraps it, and a typed
//! error that replaces a step's folded answer is counted as itself.

use super::*;
use crate::protocol::{JsonRpcResponse, RequestId};

const BACKEND: RpcError = RpcError {
    code: crate::error::rpc_codes::INTERNAL_ERROR,
    origin: Origin::Backend,
};

/// The answer `deliver` finalises in a fresh delivery after `run`.
async fn stamped<F: std::future::Future<Output = ()>>(
    run: F,
    mut deliver: JsonRpcResponse,
) -> JsonRpcResponse {
    scope(async move {
        run.await;
        stamp_folded(&mut deliver);
        deliver
    })
    .await
}

/// A single-tool execute delivering its step's error as its own: the step's
/// error is the bridge's -32003 wrapping a backend failure folded in the
/// step, so the delivered error counts as that backend failure.
#[tokio::test]
async fn a_wrap_inside_a_step_counts_with_the_steps_fold() {
    let frame = stamped(
        async {
            step(async {
                folded(BACKEND);
                wrapped_step(-32003);
            })
            .await;
            step_carried(None);
        },
        JsonRpcResponse::error(Some(RequestId::Number(1)), -32003, "bridged"),
    )
    .await;
    assert_eq!(
        frame.wire_meta.origin,
        Origin::Backend,
        "the wrap noted inside the step must reach the delivery"
    );
}

/// A step's answer was folded as a backend failure, then the gateway
/// replaced it with a typed refusal of its own: the composite reporting
/// that step carries the refusal, the gateway's, not the replaced fold.
#[tokio::test]
async fn a_typed_error_replacing_a_steps_fold_counts_as_itself() {
    let frame = stamped(
        async {
            step(async { folded(BACKEND) }).await;
            step_carried(Some(&crate::Error::ResponseFirewallRefused));
            step_absorbed();
        },
        JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({})),
    )
    .await;
    assert_eq!(
        frame.wire_meta.folded.map(|f| f.origin),
        Some(Origin::Gateway),
        "the replacing refusal is the gateway's"
    );
}

/// Control: a tool's own failure that the composite wraps (a playbook's
/// `tool_error`) and then carries past is still the step's backend failure.
#[tokio::test]
async fn a_wrapped_tool_failure_carried_past_keeps_the_steps_fold() {
    let frame = stamped(
        async {
            step(async { folded(BACKEND) }).await;
            step_tool_failed();
            step_carried(Some(&crate::Error::json_rpc(
                crate::error::rpc_codes::INTERNAL_ERROR,
                "step 's' failed: the tool reported an error",
            )));
            step_absorbed();
        },
        JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({})),
    )
    .await;
    assert_eq!(
        frame.wire_meta.folded.map(|f| f.origin),
        Some(Origin::Backend),
        "a wrapped tool failure stays the backend's"
    );
}

/// N5, a control: an attempt folds a backend failure, then the retried
/// attempt (its own step cell) is served, and the composite delivers that
/// latest step's answer as its own: it carries nothing, so it counts
/// nothing. Mutant m5 (`step()` keeps the previous fold when the latest
/// attempt has none) turns it red.
#[tokio::test]
async fn a_served_retry_after_a_failed_attempt_carries_nothing() {
    let frame = stamped(
        async {
            step(async { folded(BACKEND) }).await;
            step(async {}).await;
            step_carried(None);
        },
        JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({})),
    )
    .await;
    assert_eq!(
        frame.wire_meta.folded, None,
        "a served retry carries no fold"
    );
}

/// N12: a plan carries on past a backend step's failure (its tool error,
/// wrapped by the plan) and then past a typed refusal of the gateway's: the
/// answer reports both and counts once, as the gateway's, which outweighs
/// the backend's. At unit level: through the router a step the caller may
/// not run refuses the whole plan before any step runs
/// (`authorize_execution_plan`), so a refusal is never reported beside a
/// backend failure there. Mutant m12 (the backend outweighs the gateway in
/// `weight`) turns it red.
#[tokio::test]
async fn a_reported_backend_failure_and_a_reported_refusal_count_the_gateways() {
    let refusal = crate::Error::Forbidden {
        code: -32003,
        status: 403,
        message: "step not permitted for this caller".into(),
    };
    let frame = stamped(
        async {
            step(async { folded(BACKEND) }).await;
            step_tool_failed();
            step_carried(Some(&crate::Error::json_rpc(
                crate::error::rpc_codes::INTERNAL_ERROR,
                "step 's0' failed: the tool reported an error",
            )));
            step_absorbed();
            step(async {}).await;
            step_carried(Some(&refusal));
            step_absorbed();
        },
        JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({})),
    )
    .await;
    assert_eq!(
        frame.wire_meta.folded.map(|f| f.origin),
        Some(Origin::Gateway),
        "the gateway's refusal outweighs the backend's failure"
    );
}

/// A bridged backend failure the gateway wraps in its -32003, then replaces
/// with an audit outage (-32005, the write failed closed): the delivered
/// error is the gateway's own, not the wrapper, so it counts as the
/// gateway's. Mutant m21 (the stamp relabels any error after a wrap, the
/// code unchecked) turns it red.
#[tokio::test]
async fn an_audit_outage_replacing_a_wrapper_counts_as_the_gateways() {
    let frame = stamped(
        async {
            step(async {
                folded(BACKEND);
                wrapped_step(-32003);
            })
            .await;
            step_carried(None);
        },
        JsonRpcResponse::error(
            Some(RequestId::Number(1)),
            crate::Error::AuditUnavailable.to_rpc_code(),
            "audit unavailable",
        ),
    )
    .await;
    assert_eq!(
        frame.wire_meta.origin,
        Origin::Gateway,
        "the replacing audit outage is the gateway's"
    );
}
