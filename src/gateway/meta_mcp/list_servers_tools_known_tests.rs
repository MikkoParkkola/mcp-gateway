// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `gateway_list_servers` `tools_count/tools_known` cases, split out of
//! `tests.rs` to keep that file under the line-count ceiling.
use super::*;

// ── gateway_list_servers: tools_count is a cache reading, not a tool count ──

#[tokio::test]
async fn list_servers_marks_a_backend_whose_tools_were_never_enumerated() {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};

    let registry = Arc::new(BackendRegistry::new());
    assert!(
        registry.register(Arc::new(Backend::new(
            "cold",
            BackendConfig::default(),
            &FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        ))),
        "the backend must register for this test to mean anything"
    );
    let meta = MetaMcp::new(registry);

    let result = meta
        .list_servers(&super::anonymous_caller(), None)
        .await
        .expect("list_servers succeeds");
    let servers = result["servers"].as_array().expect("servers is an array");
    let row = servers
        .iter()
        .find(|s| s["name"] == "cold")
        .expect("the registered backend is listed");

    assert_eq!(
        row.get("tools_count"),
        Some(&serde_json::Value::Null),
        "an unenumerated backend has no count to report, not a count of 0: {row}"
    );
    assert_eq!(
        row["tools_known"], false,
        "an unenumerated backend must not read as an empty one"
    );
}

// ── the capability backend during the startup scan ──
//
// HTTP startup binds the listener first and scans the capability directories in the background; until the scan
// completes the catalogue may be partial, so its count is not known. The fixture loads its one capability BEFORE the
// scan state is set, so in these rows the scan state decides the answer, not an empty catalogue.

/// A capability backend named `caps` holding one loaded capability; the directory lives as long as the guard.
async fn caps_with_one_capability() -> (tempfile::TempDir, Arc<crate::capability::CapabilityBackend>)
{
    let dir = tempfile::TempDir::new().expect("a temp dir");
    crate::gateway::test_helpers::write_owner_only(
        dir.path().join("warmup_probe.yaml"),
        "name: warmup_probe\n\
         description: the one capability of the startup-scan rows\n\
         providers:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.invalid\n      path: /probe\n",
    )
    .expect("the capability file is written");
    let caps = Arc::new(crate::capability::CapabilityBackend::new(
        "caps",
        Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    caps.load_from_directory(dir.path().to_str().expect("a UTF-8 temp path"))
        .await
        .expect("the capability loads");
    assert_eq!(
        caps.get_tools().len(),
        1,
        "premise: one capability is loaded"
    );
    (dir, caps)
}

/// The `caps` row of a `gateway_list_servers` answer.
async fn caps_row(meta: &MetaMcp) -> serde_json::Value {
    let result = meta
        .list_servers(&super::anonymous_caller(), None)
        .await
        .expect("list_servers succeeds");
    result["servers"]
        .as_array()
        .expect("servers is an array")
        .iter()
        .find(|s| s["name"] == "caps")
        .cloned()
        .unwrap_or_else(|| panic!("the capability backend is listed: {result}"))
}

#[tokio::test]
async fn list_servers_reports_the_capability_count_unknown_while_the_startup_scan_runs() {
    let (_dir, caps) = caps_with_one_capability().await;
    caps.begin_initial_scan();
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_capabilities(Arc::clone(&caps));

    let during = caps_row(&meta).await;
    assert_eq!(
        during.get("tools_count"),
        Some(&serde_json::Value::Null),
        "mid-scan the count is not known: null, never a number (upgrading.d/8721.md): {during}"
    );
    assert_eq!(
        during["tools_known"], false,
        "mid-scan the tools are not known: {during}"
    );

    caps.mark_initial_scan_complete();
    let after = caps_row(&meta).await;
    assert_eq!(
        after["tools_count"], 1,
        "after the scan the loaded capability is counted: {after}"
    );
    assert_eq!(
        after["tools_known"], true,
        "after the scan the count is known: {after}"
    );
}

#[tokio::test]
async fn get_stats_flags_the_capability_count_while_the_startup_scan_runs() {
    let (_dir, caps) = caps_with_one_capability().await;
    caps.begin_initial_scan();
    let meta = MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        Some(Arc::new(crate::stats::UsageStats::new())),
        None,
        Duration::from_secs(60),
    );
    meta.set_capabilities(Arc::clone(&caps));

    let during = meta
        .get_stats(&json!({}), true)
        .await
        .expect("stats answer");
    assert_eq!(
        during["tools_known"], false,
        "mid-scan the total is not final: {during}"
    );
    assert_eq!(
        during["tools_available"], 1,
        "mid-scan the total stays a floor of what is loaded, as for a backend not yet enumerated: {during}"
    );

    caps.mark_initial_scan_complete();
    let after = meta
        .get_stats(&json!({}), true)
        .await
        .expect("stats answer");
    assert_eq!(
        after["tools_known"], true,
        "after the scan the total is final: {after}"
    );
    assert_eq!(
        after["tools_available"], 1,
        "after the scan the same capability is counted: {after}"
    );
}

#[tokio::test]
async fn a_capability_backend_born_complete_lists_its_count_as_known_at_once() {
    // No begin_initial_scan: stdio startup and embedders load before serving, and their backend is born complete.
    let (_dir, caps) = caps_with_one_capability().await;
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_capabilities(caps);

    let row = caps_row(&meta).await;
    assert_eq!(
        row["tools_count"], 1,
        "a complete catalogue is counted: {row}"
    );
    assert_eq!(
        row["tools_known"], true,
        "a complete catalogue is known from the first call: {row}"
    );
}
