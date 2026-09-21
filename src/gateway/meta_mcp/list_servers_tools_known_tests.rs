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

    let result = meta.list_servers().await.expect("list_servers succeeds");
    let servers = result["servers"].as_array().expect("servers is an array");
    let row = servers
        .iter()
        .find(|s| s["name"] == "cold")
        .expect("the registered backend is listed");

    assert_eq!(row["tools_count"], 0, "nothing is cached yet");
    assert_eq!(
        row["tools_known"], false,
        "an unenumerated backend must not read as an empty one"
    );
}
