// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T31: an applied reload marks the charts; a refused one does not.

use super::*;

#[tokio::test]
async fn t31_an_applied_reload_marks_the_charts_and_a_refused_one_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "backends:\n  svc:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
    )
    .unwrap();
    let store = Arc::new(crate::counters::CounterStore::new(0));
    let ctx = test_reload_context(&path).with_markers(Some(Arc::clone(&store)));
    ctx.reload_outcome().await.expect("the reload applies");
    write_owner_only(&path, "backends: [not: valid").unwrap();
    assert!(ctx.reload_outcome().await.is_err(), "the reload is refused");
    let kinds: Vec<_> = store.markers(0).into_iter().map(|m| m.kind).collect();
    assert_eq!(kinds, vec![crate::counters::MarkerKind::ConfigReload]);
}
