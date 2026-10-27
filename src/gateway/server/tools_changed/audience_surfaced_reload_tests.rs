// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! L3b (N2): a reload that changes only `surfaced_tools` reaches a
//! listener on each HTTP channel that carries `tools/list_changed`, the GET
//! stream and `subscriptions/listen`, exactly once. An identical reload
//! reaches neither.

use super::audience_fixture::{World, tool};
use crate::config::SurfacedToolConfig;

fn surfaced(pairs: &[(&str, &str)]) -> Vec<SurfacedToolConfig> {
    pairs
        .iter()
        .map(|(server, tool)| SurfacedToolConfig {
            server: (*server).to_string(),
            tool: (*tool).to_string(),
        })
        .collect()
}

#[tokio::test]
async fn l3b_a_surfaced_reload_tells_each_http_channel_once() {
    let w = World::start().await;
    w.store_shared("alpha", vec![tool("read", "r"), tool("write", "w")]);
    w.settle().await;
    let (mut get, mut listen) = (w.sse("k-std").await, w.listen("k-std").await);
    let meta = std::sync::Arc::clone(&w.state.meta_mcp);

    // `write` is withdrawn: k-std's served list changes.
    assert!(meta.reload_surfaced_for_test(surfaced(&[("alpha", "read"), ("caps", "hidden_cap")])));
    assert_eq!(
        get.told(&w).await,
        1,
        "L3b: the GET stream was not told once"
    );
    assert_eq!(
        listen.told(&w).await,
        1,
        "L3b: subscriptions/listen was not told once"
    );

    // The same list again changes nothing and tells nobody.
    assert!(!meta.reload_surfaced_for_test(surfaced(&[("alpha", "read"), ("caps", "hidden_cap")])));
    assert_eq!(
        get.told(&w).await,
        0,
        "L3b: an identical reload told the GET stream"
    );
    assert_eq!(
        listen.told(&w).await,
        0,
        "L3b: an identical reload told subscriptions/listen"
    );
}
