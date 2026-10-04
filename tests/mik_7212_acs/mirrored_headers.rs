// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use mcp_gateway::protocol::headers::{HeaderCheck, mcp_name_body_field, mcp_name_required};

#[test]
fn resources_read_mirrors_its_uri_and_never_a_decoy_name() {
    // `resources/read` executes on `uri`. Reading `name` with a fallback to
    // `uri` lets a caller attach a permitted-looking `name`, satisfy the
    // header check against it, and have the gateway read the `uri` beside
    // it — a decoy that authorises one resource and fetches another.
    assert_eq!(mcp_name_body_field("resources/read"), Some("uri"));
    assert_eq!(mcp_name_body_field("tools/call"), Some("name"));
    assert_eq!(mcp_name_body_field("prompts/get"), Some("name"));
    assert_eq!(
        mcp_name_body_field("tools/list"),
        None,
        "a method with nothing to name must not demand a mirrored name"
    );
}

#[test]
fn the_required_set_and_the_mirrored_field_cannot_disagree() {
    // Two lists of the same three methods drift apart, and the drift is a
    // bypass: a method required to carry the header with no field to
    // compare it against would pass every check.
    for method in [
        "tools/call",
        "resources/read",
        "prompts/get",
        "tools/list",
        "initialize",
        "ping",
    ] {
        assert_eq!(
            mcp_name_required(method),
            mcp_name_body_field(method).is_some(),
            "{method}: the header requirement and the mirrored field must agree"
        );
    }
}

#[test]
fn a_name_that_disagrees_with_the_body_is_still_refused() {
    // The check itself, unchanged — guarding against a fix to the field
    // selection that quietly stops comparing anything.
    let check = HeaderCheck {
        header_protocol_version: Some("2026-07-28"),
        body_protocol_version: Some("2026-07-28"),
        header_method: Some("resources/read"),
        body_method: "resources/read",
        header_name: Some("file:///allowed"),
        body_name: Some("file:///etc/shadow"),
    };
    assert!(
        check.validate().is_err(),
        "a mirrored name that disagrees with the body must be refused"
    );
}
