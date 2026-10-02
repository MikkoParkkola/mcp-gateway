// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7787 D4: a capability whose required login is missing is left out of
//! search, the initialize counts and the routing guide, as it is out of
//! `tools/list`. Calls are not this module's concern.
//!
//! The missing key is a variable no environment sets, so a developer's own
//! keys cannot change a verdict.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tempfile::TempDir;

use super::{InvokeScope, MetaMcp};
use crate::backend::BackendRegistry;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::gateway::meta_mcp_tool_total::ToolTotal;
use crate::gateway::router::CallerStanding;
use crate::ranking::SearchRanker;

const QUERY: &str = "zebracorn";
const MISSING_KEY: &str = "MIK7787_NO_SUCH_KEY_ANYWHERE";

fn yaml(name: &str, auth: &str) -> String {
    format!(
        "name: {name}\ndescription: zebracorn {name}\nproviders:\n  primary:\n    service: rest\n    \
         config:\n      base_url: https://example.invalid\n      path: /{name}\n{auth}"
    )
}

async fn meta(code_mode: bool) -> (MetaMcp, TempDir) {
    let dir = TempDir::new().unwrap();
    let keyed = format!("auth:\n  required: true\n  type: bearer\n  key: \"env:{MISSING_KEY}\"\n");
    std::fs::write(dir.path().join("keyed.yaml"), yaml("keyed", &keyed)).unwrap();
    std::fs::write(dir.path().join("open.yaml"), yaml("open", "")).unwrap();
    let backend = Arc::new(CapabilityBackend::new(
        "caps",
        Arc::new(CapabilityExecutor::new()),
    ));
    let loaded = backend
        .load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(loaded, 2, "both fixtures must load");
    let meta = MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_code_mode(code_mode);
    meta.set_capabilities(backend);
    (meta, dir)
}

fn names(response: &serde_json::Value) -> Vec<String> {
    let mut names: Vec<String> = response["matches"]
        .as_array()
        .expect("matches")
        .iter()
        .map(|m| m["tool"].as_str().expect("tool").to_string())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn classic_search_leaves_out_a_capability_whose_key_is_missing() {
    let (meta, _dir) = meta(false).await;
    let response = meta
        .search_tools_anon(&json!({ "query": QUERY }), None)
        .await
        .unwrap();
    assert_eq!(names(&response), ["open"]);
}

#[tokio::test]
async fn code_mode_search_leaves_out_a_capability_whose_key_is_missing() {
    let (meta, _dir) = meta(true).await;
    let response = meta
        .code_mode_search_anon(&json!({ "query": QUERY }), None)
        .await
        .unwrap();
    assert_eq!(names(&response), ["open"]);
}

#[tokio::test]
async fn the_initialize_count_does_not_include_a_capability_whose_key_is_missing() {
    let (meta, _dir) = meta(false).await;
    let (total, _servers) =
        meta.admitted_counts(InvokeScope::allow_all(CallerStanding::Admin), None);
    assert_eq!(total, ToolTotal::Exact(1));
}
