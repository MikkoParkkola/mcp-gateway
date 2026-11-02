// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's own error frame on a list page is the backend's error: the
//! catalogue fill fails with it (`page_error`), and the frame built from
//! that error (`of_error`) counts as the backend's. A direct `tools/list`
//! that forwards the page frame itself is another path, not pinned here.

use super::*;
use crate::gateway::health_metrics::RpcError;
use crate::protocol::Origin;

/// N2: page 3 answers with an error frame mid-drain.
#[tokio::test]
async fn a_list_pages_own_error_counts_as_the_backends() {
    let pager = Pager::tools(three_pages());
    let backend = backend_with(Arc::clone(&pager), Duration::ZERO);
    backend.get_tools_shared().await.expect("first fill");
    pager.script.lock().error_from = Some(pager.request_count() + 2);

    let error = backend
        .get_tools_shared()
        .await
        .expect_err("premise: page 3 answers with an error frame");
    assert!(
        error.to_string().contains("upstream failed"),
        "premise: the page's own error: {error}"
    );
    let frame = JsonRpcResponse::of_error(Some(RequestId::Number(1)), &error);
    assert_eq!(
        RpcError::of_frame(&frame).map(|m| m.origin),
        Some(Origin::Backend),
        "the page's error is the backend's: {error:?}"
    );
}
