// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The search `limit` bound: both search tools advertise 1 to 25, and both
//! routes hold any requested value to that range.
//!
//! The gateway does not check meta-tool arguments against the advertised
//! schema, so the handler clamp is what a caller actually gets. The schema
//! cells pin that the advertised bound and the clamp agree.
use super::*;
use crate::gateway::meta_mcp_helpers::extract_search_limit;
use crate::gateway::meta_mcp_tool_defs::{
    ToolTotal, build_base_tools, build_code_mode_search_tool,
};

/// More matching capabilities than the cap, so a missing clamp shows.
const MATCHING: usize = 30;

fn limit_schema(tool: &crate::protocol::Tool) -> Value {
    tool.input_schema["properties"]["limit"].clone()
}

#[test]
fn both_search_tools_advertise_the_bound_the_handler_clamps_to() {
    let tools = build_base_tools(ToolTotal::Exact(1), 1);
    let search_tools = tools
        .iter()
        .find(|t| t.name == "gateway_search_tools")
        .expect("gateway_search_tools is a base tool");
    let clamp_max = extract_search_limit(&json!({ "limit": u64::MAX }));
    for (name, schema) in [
        ("gateway_search_tools", limit_schema(search_tools)),
        (
            "gateway_search",
            limit_schema(&build_code_mode_search_tool()),
        ),
    ] {
        assert_eq!(schema["minimum"], json!(1), "{name}: {schema}");
        assert_eq!(schema["maximum"], json!(clamp_max), "{name}: {schema}");
    }
}

#[test]
fn a_limit_below_one_is_raised_to_one() {
    for limit in [json!(0), json!(-5), json!(i64::MIN)] {
        assert_eq!(
            extract_search_limit(&json!({ "limit": limit })),
            1,
            "limit {limit}"
        );
    }
}

#[test]
fn a_limit_above_the_cap_is_lowered_to_it() {
    for limit in [json!(26), json!(1000), json!(u64::MAX)] {
        assert_eq!(
            extract_search_limit(&json!({ "limit": limit })),
            25,
            "limit {limit}"
        );
    }
}

#[test]
fn a_missing_or_non_integer_limit_keeps_the_default() {
    for args in [
        json!({}),
        json!({ "limit": "9" }),
        json!({ "limit": 2.5 }),
        json!({ "limit": null }),
    ] {
        assert_eq!(extract_search_limit(&args), 10, "args {args}");
    }
}

async fn meta_with_many_matches(code_mode: bool) -> (MetaMcp, Vec<TempDir>) {
    let names: Vec<String> = (0..MATCHING).map(|i| format!("{QUERY}_{i:02}")).collect();
    let caps: Vec<(&str, &str)> = names
        .iter()
        .map(|n| (n.as_str(), "a zebracorn fixture"))
        .collect();
    let (cap_backend, dirs) = capability_backend(&caps).await;
    let meta = MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_code_mode(code_mode)
    .with_profile_registry(registry_with_default("open", poisoned_profile(false)));
    meta.set_capabilities(cap_backend);
    (meta, dirs)
}

/// Requested limit, then the match count both routes must return.
const ROUTE_CASES: &[(i64, usize)] = &[(1000, 25), (0, 1)];

#[tokio::test]
async fn the_classic_route_holds_the_limit_to_the_bound() {
    let (meta, _dirs) = meta_with_many_matches(false).await;
    for &(limit, expected) in ROUTE_CASES {
        let response = meta
            .search_tools_anon(&json!({ "query": QUERY, "limit": limit }), None)
            .await
            .unwrap();
        assert_eq!(
            tool_names(&response).len(),
            expected,
            "limit {limit}: {response}"
        );
        assert_eq!(
            response["total_available"],
            json!(MATCHING),
            "limit {limit}: {response}"
        );
    }
}

#[tokio::test]
async fn the_code_mode_route_holds_the_limit_to_the_bound() {
    let (meta, _dirs) = meta_with_many_matches(true).await;
    for &(limit, expected) in ROUTE_CASES {
        let response = meta
            .code_mode_search_anon(&json!({ "query": QUERY, "limit": limit }), None)
            .await
            .unwrap();
        assert_eq!(
            tool_names(&response).len(),
            expected,
            "limit {limit}: {response}"
        );
    }
}
