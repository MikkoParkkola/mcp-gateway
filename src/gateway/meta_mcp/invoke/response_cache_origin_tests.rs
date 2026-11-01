// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! N18, a control: an answer served from the response cache is a served
//! answer: a single-tool execute delivering it as its own answer carries no
//! fold, so it counts nothing new. Mutant m18 (the cache-hit path notes a
//! backend fold) turns it red.

use super::*;
use crate::gateway::delivery_facts;
use crate::protocol::JsonRpcResponse;

/// The fold the delivery of `invoke` carries, read from the stamped frame.
async fn carried(
    meta: &MetaMcp,
    caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
) -> Option<crate::gateway::health_metrics::RpcError> {
    delivery_facts::scope(async {
        let answer = meta
            .invoke_tool(&call(18), None, caller)
            .await
            .expect("premise: served");
        // Delivered as the execute's own answer (`code_mode_execute`).
        delivery_facts::step_carried(None);
        let mut frame = JsonRpcResponse::success(RequestId::Number(1), answer);
        delivery_facts::stamp_folded(&mut frame);
        frame.wire_meta.folded
    })
    .await
}

#[tokio::test]
async fn a_cache_served_answer_counts_nothing_new() {
    let (meta, calls) = cached_meta(&FailsafeConfig::default(), vec![ok_body()]);
    let caller = ctx(&AllowAll);
    assert_eq!(
        carried(&meta, &caller).await,
        None,
        "the first, served answer"
    );
    assert_eq!(
        carried(&meta, &caller).await,
        None,
        "the cache-served answer"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "premise: the second answer came from the cache"
    );
}
