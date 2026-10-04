// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7915 (HEADER.4a): a non-ASCII tool name reaches a modern peer as the
//! sentinel-wrapped `Mcp-Name` the specification gives, on both paths.

use super::*;

/// The other wire rows send ASCII names only, which pass through the encoder
/// untouched; this one needs the Base64 wrapper to survive the header. Its
/// only unsafe character is non-ASCII (no space, no sentinel), so the wrapper
/// can come from the non-ASCII rule alone.
#[tokio::test]
async fn a_non_ascii_tool_name_reaches_the_wire_sentinel_encoded() {
    let name = "café";
    for (path, label) in BOTH_PATHS {
        let params = Some(json!({ "name": name }));
        let run = Run::of(Peer::Modern, *path, "tools/call", params, &[], &[]).await;
        let sent = header(run.under_test("tools/call"), "Mcp-Name");
        assert_eq!(
            sent, "=?base64?Y2Fmw6k=?=",
            "on the {label} path the name must leave as the specification's encoding"
        );
        assert_eq!(
            mcp_gateway::protocol::headers::decode_header_value(&sent).as_deref(),
            Some(name),
            "and decode back to the body's name"
        );
    }
}
