// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The MIK-8707 latent gap, pinned at source (lead ruling, 2026-10-23). The
//! receipt's facts are fixed when it is stamped. On `/mcp` and stdio the stamp
//! is minted at dispatch, before the route's egress scan; on `/mcp/{name}` the
//! scan runs first. No delivered fact differs today ([`super::Latent`]), so the
//! order is read off the source: fixing MIK-8707 flips the first test, and a
//! second extractor arm fails the second, which names the ticket.

/// One source file of this crate.
fn source(path: &str) -> String {
    let full = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("{}: {e}", full.display()))
}

/// The byte offset of the single occurrence of `needle` in `text`.
fn only(text: &str, needle: &str, file: &str) -> usize {
    let found: Vec<usize> = text.match_indices(needle).map(|(at, _)| at).collect();
    assert_eq!(
        found.len(),
        1,
        "{file}: `{needle}` occurs {} times; re-read the order",
        found.len()
    );
    found[0]
}

/// The stamp and the egress scan, route by route, in the order the code runs
/// them: `/mcp` and stdio mint the receipt at dispatch
/// (`invoke/post_dispatch.rs`, which never scans) and scan afterwards in
/// `finalize_routed` / `finalize_content`; `/mcp/{name}` scans, then stamps.
#[test]
fn stamp_and_egress_scan_order_is_pinned_at_source() {
    const STAMP: &str = "maybe_stamp_provenance(";
    let dispatch = "src/gateway/meta_mcp/invoke/post_dispatch.rs";
    let post = source(dispatch);
    only(&post, STAMP, dispatch);
    assert!(
        !post.contains("scan_egress(") && !post.contains("finalize_routed("),
        "{dispatch}: the dispatch-time stamp now sits beside an egress scan: MIK-8707 moved?"
    );
    for (file, call, finalize) in [
        (
            "src/gateway/router/handlers.rs",
            "\"tools/call\" =>",
            "finalize_routed(",
        ),
        (
            "src/gateway/server/stdio_dispatch.rs",
            "let (mut response, execution) = if method == \"tools/call\" {",
            "finalize_content(",
        ),
    ] {
        let text = source(file);
        assert!(
            !text.contains(STAMP),
            "{file}: the route stamps itself now: MIK-8707 fixed? flip the cell"
        );
        let (dispatched, scanned) = (only(&text, call, file), only(&text, finalize, file));
        assert!(
            dispatched < scanned,
            "{file}: the stamping dispatch runs before the egress scan (MIK-8707)"
        );
    }
    let direct = "src/gateway/router/backend_handlers/direct_dispatch.rs";
    let text = source(direct);
    let scan = only(&text, "scan_direct_egress(", direct);
    let stamp = only(&text, "stamp_direct_provenance(", direct);
    assert!(
        scan < stamp,
        "{direct}: the direct route scans before it stamps (the pinned order)"
    );
}

/// The only receipt fact a payload can move is `row_count`, and its one
/// extractor arm reads a server-reported total that redaction cannot change.
/// A new arm may count something redaction removes, which makes MIK-8707 live:
/// re-check the latent reason before listing it here.
#[test]
fn a_new_extractor_arm_reopens_mik_8707() {
    let file = "src/trust/result_extractor.rs";
    let text = source(file);
    let arms: Vec<&str> = text
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with('"') && line.contains("\" => "))
        .collect();
    assert_eq!(
        arms,
        ["\"github_search_repos\" => github_search_row_count(&payload),"],
        "{file}: the extractor arms changed; MIK-8707 may now be live (a redacted answer \
         could change row_count): re-check Latent::NoExtractedFactRedactionChanges"
    );
}
