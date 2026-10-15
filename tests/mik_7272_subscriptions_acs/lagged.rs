// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A listen stream that fell behind: the transport closes it.

use axum::http::StatusCode;
use serde_json::json;

use super::http::{next_data, open_listen, state};

/// MIK-7766: a listener that fell behind lost updates, so its stream closes
/// without the success response that would call the subscription complete.
#[tokio::test]
async fn ac_sub_1_a_lagged_listener_is_closed_without_a_graceful_end() {
    let (state, _store_dir) = state(true).await;
    let (status, _, mut stream) = open_listen(
        &state,
        json!({ "notifications": { "toolsListChanged": true } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    next_data(&mut stream)
        .await
        .expect("the ack opens the stream");
    // More than the registry's channel holds, published while unread.
    for _ in 0..300 {
        state.announce_tools_changed("any").await;
    }
    // The constant attach hint (MIK-8350 B10) may precede the close, byte for
    // byte as the registry sends it; nothing else is delivered, and never a
    // response.
    let attach_hint = json!({
        "jsonrpc": "2.0",
        "method": "notifications/tools/list_changed",
        "params": { "_meta": { "io.modelcontextprotocol/subscriptionId": 1 } }
    });
    let mut frames = Vec::new();
    while let Some(frame) = next_data(&mut stream).await {
        frames.push(frame);
    }
    assert!(
        frames.is_empty() || frames == [attach_hint],
        "a lagged stream closes with no response: {frames:?}"
    );
    assert!(
        matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                futures::StreamExt::next(&mut stream)
            )
            .await,
            Ok(None)
        ),
        "the body ended, not merely went quiet"
    );
}
