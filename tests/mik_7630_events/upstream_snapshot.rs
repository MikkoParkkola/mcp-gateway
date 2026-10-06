// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7950: while a URI is watched, the upstream session re-reads the
//! backend catalogue every configured `meta_mcp.cache_ttl`, not a fixed 300 s.

use super::*;

/// FIX.2: with a 2 s cache TTL, a watched URI's catalogue is re-read at
/// that interval.
#[tokio::test]
async fn the_catalogue_is_re_read_at_the_configured_cache_ttl() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = HttpPeer::start(Era::Modern).await;
    let mut cfg = upstream_config(dir.path(), http_backend(&peer), &[]);
    cfg["meta_mcp"]["cache_ttl"] = json!("2s");
    let gw = start_listed(dir.path(), &receiver, cfg).await;
    let updated = event("resource_updated");
    let _alice = sub(&gw, ALICE, &updated, &receiver, json!({"uri": URI_A})).await;
    eventually("one open listen", || peer.open_listens().len() == 1).await;

    let before = peer.frames("resources/list").len();
    // Two re-reads are due by 4 s; 8 s leaves room for a slow runner.
    let reread = wait_until(Duration::from_secs(8), || {
        peer.frames("resources/list").len() >= before + 2
    })
    .await;
    assert!(
        reread,
        "re-read {} times in 8 s with a 2 s cache TTL",
        peer.frames("resources/list").len() - before
    );
}
