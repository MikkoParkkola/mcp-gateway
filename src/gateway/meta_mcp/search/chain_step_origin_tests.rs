// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! N13 at the typed seam: a chain step whose invocation fails with the
//! backend's own `INVALID_PARAMS` reaches `step_failure`'s refusal arm, and
//! the chain's error delivered for it counts as the backend's. (Through the
//! router a backend's dispatch error is folded into an `isError` result
//! before the chain sees it, `post_dispatch`'s `dispatch_error_result`; that
//! path is the router row of the same name.)

use crate::error::rpc_codes::INVALID_PARAMS;
use crate::gateway::delivery_facts;
use crate::gateway::health_metrics::RpcError;
use crate::protocol::{JsonRpcResponse, Origin, RequestId};

#[tokio::test]
async fn a_chain_ending_on_a_typed_backend_refusal_counts_as_the_backends() {
    let (error, marker) = delivery_facts::scope(async {
        let step: crate::Result<()> = delivery_facts::step(async {
            Err(crate::Error::backend_json_rpc(
                crate::protocol::JsonRpcError {
                    code: INVALID_PARAMS,
                    message: "backend says no".to_owned(),
                    data: None,
                },
            ))
        })
        .await;
        let error =
            super::step_failure(0, "alpha:read", step.expect_err("premise: the step failed"));
        let mut frame = JsonRpcResponse::of_error(Some(RequestId::Number(1)), &error);
        delivery_facts::stamp_folded(&mut frame);
        (error, RpcError::of_frame(&frame))
    })
    .await;
    assert!(
        error
            .to_string()
            .contains("Chain step 0 (alpha:read) refused: backend says no"),
        "premise: the refusal arm's wording: {error}"
    );
    assert_eq!(
        marker,
        Some(RpcError {
            code: INVALID_PARAMS,
            origin: Origin::Backend
        }),
        "{error:?}"
    );
}
