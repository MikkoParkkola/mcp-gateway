// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! tools/list normalisation: direct-backend proxy annotations and violators beside malformed siblings.

use super::*;

#[test]
fn normalize_tools_list_response_fills_direct_backend_proxy_annotations() {
    let mut response = JsonRpcResponse::success(
        RequestId::Number(1),
        json!({
            "tools": [
                {
                    "name": "search",
                    "description": "Search things",
                    "inputSchema": {"type": "object"},
                    "annotations": {"readOnlyHint": true}
                },
                {
                    "name": "archive_chat",
                    "description": "Archive a chat",
                    "inputSchema": {"type": "object"},
                    "annotations": {}
                }
            ],
            "nextCursor": "abc",
            "extra": "preserved"
        }),
    );

    normalize_tools_list_response(&beeper(), &mut response);

    let result = response.result.expect("success result");
    // Flipped by A3: the result is rebuilt as `{tools}` alone. An upstream
    // cursor or sibling key could name a tool the caller may not invoke.
    assert!(result.get("nextCursor").is_none(), "{result}");
    assert!(result.get("extra").is_none(), "{result}");

    let search = &result["tools"][0]["annotations"];
    assert_eq!(search["readOnlyHint"], true);
    assert_eq!(search["destructiveHint"], false);
    assert_eq!(search["idempotentHint"], true);
    assert_eq!(search["openWorldHint"], true);
    assert_eq!(
        result["tools"][0]["trustCard"]["schemaVersion"],
        "trust_card.v1"
    );
    assert_eq!(
        result["tools"][0]["trustCard"]["serverId"],
        "backend:beeper"
    );
    assert_eq!(result["tools"][0]["trustCard"]["toolName"], "search");
    assert_eq!(
        result["tools"][0]["trustCard"]["trustCardDigestSha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );

    let archive = &result["tools"][1]["annotations"];
    assert_eq!(archive["readOnlyHint"], false);
    assert_eq!(archive["destructiveHint"], true);
    assert_eq!(archive["idempotentHint"], false);
    assert_eq!(archive["openWorldHint"], true);
}

#[test]
fn normalize_tools_list_response_excludes_a_violator_beside_a_malformed_sibling() {
    // GIVEN a descriptor the `Tool` shape cannot accept (no `name`) sitting
    // next to a tool whose `x-mcp-header` breaches the token constraint
    let mut response = JsonRpcResponse::success(
        RequestId::Number(1),
        json!({
            "tools": [
                {"description": "no name field", "inputSchema": {"type": "object"}},
                {
                    "name": "bad",
                    "inputSchema": {"type": "object", "properties": {
                        "tenant": {"type": "string", "x-mcp-header": "Tenant Id"}
                    }}
                },
                {"name": "search", "inputSchema": {"type": "object"}}
            ]
        }),
    );

    // WHEN the direct passthrough response is normalized
    normalize_tools_list_response(&beeper(), &mut response);

    // THEN the malformed sibling no longer shields the violator: `bad` is
    // gone, `search` survives, and (A3) the unreadable entry is dropped too,
    // since the call predicate cannot judge it
    let tools = response.result.expect("success result")["tools"]
        .as_array()
        .expect("tools array")
        .clone();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert_eq!(names, vec!["search"]);
    assert_eq!(tools.len(), 1);
}

/// A backend named `beeper` with the default configuration, for the
/// normaliser cells.
fn beeper() -> crate::backend::Backend {
    crate::backend::Backend::new(
        "beeper",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    )
}
