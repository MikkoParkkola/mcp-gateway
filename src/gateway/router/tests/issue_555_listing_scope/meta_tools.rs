// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A3 cells for the discovery meta-tools: `gateway_list_tools`,
//! `gateway_search_tools`, `gateway_list_servers` and the refusals that must
//! not tell a withheld item from an absent one.

use serde_json::{Value, json};

use super::{Auth, CATALOGUE, call_tool, fixture, fixture_with, refused};

/// The `result` of a meta-tool call, parsed out of its text content when the
/// gateway wraps it, so a cell can read fields rather than grep prose.
pub(super) fn payload(body: &Value) -> Value {
    let result = &body["result"];
    if let Some(text) = result["content"][0]["text"].as_str()
        && let Ok(parsed) = serde_json::from_str::<Value>(text)
    {
        return parsed;
    }
    if !result["structuredContent"].is_null() {
        return result["structuredContent"].clone();
    }
    result.clone()
}

/// `(server, tool)` pairs a `gateway_list_tools` answer names.
fn listed_pairs(body: &Value) -> Vec<(String, String)> {
    payload(body)["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("gateway_list_tools must return tools: {body}"))
        .iter()
        .map(|t| {
            (
                t["server"].as_str().unwrap_or_default().to_string(),
                t["name"]
                    .as_str()
                    .or(t["tool"].as_str())
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect()
}

/// T6 (property): `gateway_list_tools` names a `(server, tool)` iff
/// `gateway_invoke` of it is not refused, over every configured pair.
#[tokio::test]
async fn list_equals_invoke_gateway_list_tools() {
    for key in ["alpha-only", "u1", "u2"] {
        let f = fixture(Auth::Keys).await;
        let listing = call_tool(&f.router, Some(key), "gateway_list_tools", json!({})).await;
        let pairs = listed_pairs(&listing);
        for (server, tool) in CATALOGUE {
            let answer = call_tool(
                &f.router,
                Some(key),
                "gateway_invoke",
                json!({ "server": server, "tool": tool, "arguments": { "q": "x" } }),
            )
            .await;
            let is_listed = pairs.iter().any(|(s, t)| s == server && t == tool);
            assert_eq!(
                is_listed,
                !refused(&answer),
                "{key}: {server}:{tool} listed={is_listed}, invoke answered {answer}"
            );
        }
        assert_eq!(
            payload(&listing)["total"].as_u64(),
            Some(pairs.len() as u64),
            "{key}: total must count admitted entries only"
        );
    }
}

/// T7: a search names nothing the caller could not invoke — no hit, no
/// suggestion tag. Covers `gateway_search_tools` and the code-mode search.
#[tokio::test]
async fn search_tools_omits_out_of_scope_matches_and_suggestions() {
    let f = fixture(Auth::Keys).await;
    for query in ["beta", "beta_tool", "zzzz-no-hit"] {
        let body = call_tool(
            &f.router,
            Some("alpha-only"),
            "gateway_search_tools",
            json!({ "query": query }),
        )
        .await;
        let text = payload(&body).to_string();
        assert!(
            !text.contains("beta"),
            "search for {query:?} disclosed beta: {text}"
        );
        assert!(
            !text.contains("cap_"),
            "search for {query:?} disclosed a capability: {text}"
        );
    }
    // Positive control: the same search as a caller scoped to beta finds it.
    let body = call_tool(
        &f.router,
        Some("both-key"),
        "gateway_search_tools",
        json!({ "query": "beta" }),
    )
    .await;
    assert!(
        payload(&body).to_string().contains("beta_tool"),
        "control: {body}"
    );

    let code = fixture_with(Auth::Keys, |meta| meta.with_code_mode(true)).await;
    let body = call_tool(
        &code.router,
        Some("alpha-only"),
        "gateway_search",
        json!({ "query": "tool" }),
    )
    .await;
    let text = payload(&body).to_string();
    assert!(text.contains("alpha_read"), "code-mode control: {body}");
    assert!(
        !text.contains("beta_tool"),
        "code-mode search disclosed beta: {text}"
    );
    assert!(
        !text.contains("cap_open"),
        "code-mode search disclosed a capability: {text}"
    );
}

/// T8: `gateway_list_servers` names only backends the caller may reach, the
/// capability backend included, and counts only admitted tools.
#[tokio::test]
async fn list_servers_omits_out_of_scope_backend() {
    let f = fixture(Auth::Keys).await;
    let servers = |body: &Value| -> Vec<(String, u64)> {
        payload(body)["servers"]
            .as_array()
            .unwrap_or_else(|| panic!("servers array: {body}"))
            .iter()
            .map(|s| {
                (
                    s["name"].as_str().unwrap_or_default().to_string(),
                    s["tools_count"].as_u64().unwrap_or(0),
                )
            })
            .collect()
    };
    let with_caps = servers(
        &call_tool(
            &f.router,
            Some("alpha-key"),
            "gateway_list_servers",
            json!({}),
        )
        .await,
    );
    assert!(
        !with_caps.iter().any(|(n, _)| n == "beta"),
        "beta disclosed: {with_caps:?}"
    );
    // alpha_write is denied by the global policy, so one of alpha's two is admitted.
    assert!(
        with_caps.contains(&("alpha".to_string(), 1)),
        "admitted count: {with_caps:?}"
    );

    let alpha_only = servers(
        &call_tool(
            &f.router,
            Some("alpha-only"),
            "gateway_list_servers",
            json!({}),
        )
        .await,
    );
    assert!(
        !alpha_only.iter().any(|(n, _)| n == "caps"),
        "capability backend disclosed: {alpha_only:?}"
    );
}

/// T10: a withheld backend or tool gets the answer an absent one gets.
#[tokio::test]
async fn withheld_is_indistinguishable_from_absent() {
    let f = fixture(Auth::Keys).await;
    let key = Some("alpha-only");
    let normalise = |body: Value, from: &str, to: &str| body.to_string().replace(from, to);

    let withheld = call_tool(
        &f.router,
        key,
        "gateway_list_tools",
        json!({ "server": "beta" }),
    )
    .await;
    let absent = call_tool(
        &f.router,
        key,
        "gateway_list_tools",
        json!({ "server": "nope" }),
    )
    .await;
    assert_eq!(
        normalise(withheld, "beta", "X"),
        normalise(absent, "nope", "X"),
        "list_tools(server=)"
    );

    let withheld = call_tool(&f.router, key, "beta_tool", json!({ "q": "x" })).await;
    let absent = call_tool(&f.router, key, "nope_tool", json!({ "q": "x" })).await;
    assert_eq!(
        withheld["error"]["code"],
        json!(-32601),
        "withheld call: {withheld}"
    );
    assert_eq!(
        normalise(withheld, "beta_tool", "X"),
        normalise(absent, "nope_tool", "X"),
        "direct-name call"
    );
}

/// T14: an invocation miss suggests no name the caller could not invoke.
#[tokio::test]
async fn invocation_miss_suggestions_are_scoped() {
    let f = fixture(Auth::Keys).await;
    let key = Some("nowrite-key");
    let miss = |tool: &str| json!({ "server": "alpha", "tool": tool, "arguments": {} });
    let body = call_tool(&f.router, key, "gateway_invoke", miss("alpha_writ")).await;
    assert!(
        !body.to_string().contains("alpha_write"),
        "suggested a denied tool: {body}"
    );
    // Control: a miss is answered with a suggestion at all.
    let body = call_tool(&f.router, key, "gateway_invoke", miss("alpha_rea")).await;
    assert!(
        body.to_string().contains("alpha_read"),
        "control suggestion: {body}"
    );
}

/// T25: the upstream-miss suggestion pool honours the global policy too.
#[tokio::test]
async fn upstream_miss_suggestion_is_scoped() {
    let f = fixture(Auth::Off).await;
    let args = json!({ "server": "alpha", "tool": "alpha_writ", "arguments": {} });
    let body = call_tool(&f.router, None, "gateway_invoke", args).await;
    assert!(
        !body.to_string().contains("alpha_write"),
        "suggested a policy denial: {body}"
    );
}

/// The description of meta-tool `name` in this caller's `tools/list`.
async fn description(router: &axum::Router, key: &str, name: &str) -> String {
    let body = super::rpc(router, Some(key), "tools/list", json!({})).await;
    body["result"]["tools"]
        .as_array()
        .and_then(|tools| tools.iter().find(|t| t["name"] == name))
        .and_then(|t| t["description"].as_str())
        .unwrap_or_else(|| panic!("{name} must be listed: {body}"))
        .to_string()
}

/// T16: meta-tool descriptions state the admitted counts, not the global ones.
#[tokio::test]
async fn meta_tool_descriptions_carry_admitted_counts() {
    let f = fixture(Auth::Keys).await;
    let servers = description(&f.router, "alpha-only", "gateway_list_servers").await;
    assert!(servers.contains("List all 1 connected"), "{servers}");
    let tools = description(&f.router, "alpha-only", "gateway_list_tools").await;
    assert!(tools.contains("all 1 tools across 1 backends"), "{tools}");
}

fn collect_servers(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(s)) = map.get("server") {
                out.push(s.clone());
            }
            map.values().for_each(|v| collect_servers(v, out));
        }
        Value::Array(items) => items.iter().for_each(|v| collect_servers(v, out)),
        _ => {}
    }
}

/// T18 (property): every server a discovery answer names is one
/// `gateway_list_servers` names, and one the caller may reach.
#[tokio::test]
async fn servers_named_anywhere_appear_in_list_servers() {
    for (auth, key) in [(Auth::Keys, Some("alpha-only")), (Auth::Off, None)] {
        let f = fixture(auth).await;
        let servers = call_tool(&f.router, key, "gateway_list_servers", json!({})).await;
        let known: Vec<String> = payload(&servers)["servers"]
            .as_array()
            .expect("servers")
            .iter()
            .filter_map(|s| s["name"].as_str().map(str::to_string))
            .collect();
        let mut named = Vec::new();
        for (tool, args) in [
            ("gateway_list_tools", json!({})),
            ("gateway_search_tools", json!({ "query": "tool" })),
        ] {
            collect_servers(
                &payload(&call_tool(&f.router, key, tool, args).await),
                &mut named,
            );
        }
        let listing = super::rpc(&f.router, key, "tools/list", json!({})).await;
        for t in listing["result"]["tools"].as_array().expect("tools") {
            let id = t["trustCard"]["serverId"].as_str().unwrap_or_default();
            if let Some(server) = id.strip_prefix("backend:") {
                named.push(server.to_string());
            }
        }
        for server in named {
            assert!(
                known.contains(&server),
                "{key:?}: '{server}' not in {known:?}"
            );
            if key.is_some() {
                assert_eq!(
                    server, "alpha",
                    "alpha-only was shown a server outside its scope"
                );
            }
        }
    }
}

/// T19: a chain target the caller may not invoke is named nowhere: (a) search
/// hits, (b) the initialize guide, (c) `tools/list`, (d) `gateway_list_tools`.
/// (c) and (d) pass today and guard against a future cross-reference field.
#[tokio::test]
async fn chains_with_targets_are_scoped() {
    let f = fixture(Auth::Keys).await;
    let key = Some("nohidden-key");
    let search = json!({ "query": "cap_open" });
    let bodies = [
        (
            "search",
            call_tool(&f.router, key, "gateway_search_tools", search.clone()).await,
        ),
        (
            "initialize",
            super::rpc(&f.router, key, "initialize", super::guide::init()).await,
        ),
        (
            "tools/list",
            super::rpc(&f.router, key, "tools/list", json!({})).await,
        ),
        (
            "list_tools",
            call_tool(&f.router, key, "gateway_list_tools", json!({})).await,
        ),
        (
            "list_tools(server)",
            call_tool(
                &f.router,
                key,
                "gateway_list_tools",
                json!({ "server": "caps" }),
            )
            .await,
        ),
    ];
    for (surface, body) in &bodies {
        assert!(
            !body.to_string().contains("cap_hidden"),
            "{surface} named cap_hidden: {body}"
        );
    }
    // Control: the chain's source is still found, so the search ran.
    assert!(
        bodies[0].1.to_string().contains("cap_open"),
        "control: {}",
        bodies[0].1
    );
}

/// T28: the unknown-meta-tool hint names no admin tool to a Standard caller.
#[tokio::test]
async fn unknown_meta_tool_hint_respects_standing() {
    let f = fixture(Auth::Keys).await;
    let standard = call_tool(&f.router, Some("open-key"), "gateway_kill_servr", json!({})).await;
    assert!(
        !standard.to_string().contains("gateway_kill_server"),
        "{standard}"
    );
    let admin = call_tool(
        &f.router,
        Some("admin-key"),
        "gateway_kill_servr",
        json!({}),
    )
    .await;
    assert!(
        admin.to_string().contains("gateway_kill_server"),
        "admin control: {admin}"
    );
}
