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

/// Stdio's finalize step is `/mcp`'s with no router firewall: `finalize_content`
/// only calls `finalize_routed(.., None)` (`response_security.rs:224-230`), so
/// stdio's seal-then-sign and sign-then-record order is the one R-SIGN and
/// R-RECSIGN drive on `/mcp`. A stdio tail that stops delegating fails here.
#[test]
fn stdio_finalizes_through_finalize_routed() {
    let file = "src/gateway/meta_mcp/response_security.rs";
    let text = source(file);
    let start = only(&text, "pub(crate) fn finalize_content(", file);
    let body_end = start
        + text[start..]
            .find("\n    }\n")
            .unwrap_or_else(|| panic!("{file}: finalize_content's body ends"));
    let body = &text[start..body_end];
    assert_eq!(
        body.matches("self.finalize_routed(response, context, None)")
            .count(),
        1,
        "{file}: finalize_content delegates to finalize_routed(.., None): {body}"
    );
    let stdio = "src/gateway/server/stdio_dispatch.rs";
    only(&source(stdio), "meta_mcp.finalize_content(", stdio);
}

/// The identifiers in the text from `needle` to the first `{`.
fn signature_words(text: &str, needle: &str, file: &str) -> Vec<String> {
    let start = only(text, needle, file);
    let end = start + text[start..].find('{').expect("a body follows");
    text[start..end]
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

/// An era twin's pin: the response tail cannot branch on the era or the
/// case, because nothing it runs receives either. `finalize_routed`, the
/// delivery context, `/mcp`'s record step, stdio's judge-record-commit and
/// the direct route's judged call take no era, case, replay or cache input.
#[test]
fn the_tail_takes_no_case_or_era() {
    const BANNED: [&str; 7] = [
        "era",
        "Era",
        "case",
        "replay",
        "cached",
        "cache_hit",
        "CacheOutcome",
    ];
    for (file, needle) in [
        (
            "src/gateway/meta_mcp/response_security.rs",
            "pub(crate) fn finalize_routed(",
        ),
        (
            "src/gateway/meta_mcp/response_security.rs",
            "pub(crate) struct ResponseDeliveryContext<'a>",
        ),
        (
            "src/gateway/router/judged_answer.rs",
            "pub(in crate::gateway) async fn record_delivery(",
        ),
        (
            "src/gateway/server/stdio_delivery.rs",
            "pub(super) async fn judge_and_commit(",
        ),
        (
            "src/gateway/router/backend_handlers/direct_audit.rs",
            "async fn audited_call_judged(",
        ),
    ] {
        let text = source(file);
        let words = if needle.contains("struct") {
            let start = only(&text, needle, file);
            let end = start + text[start..].find("\n}\n").expect("the struct closes");
            text[start..end]
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|word| !word.is_empty())
                .map(str::to_owned)
                .collect()
        } else {
            signature_words(&text, needle, file)
        };
        let hits: Vec<&String> = words
            .iter()
            .filter(|w| BANNED.contains(&w.as_str()))
            .collect();
        assert!(
            hits.is_empty(),
            "{file}: `{needle}` now takes {hits:?}: an era or case twin may no longer share its row"
        );
    }
}

/// A replay or cache-hit twin's pin: each route hands a replayed answer back
/// into its own response tail, and a cache hit is re-stamped inside dispatch,
/// so both run the same tail as a fresh answer.
#[test]
fn replay_and_cache_hit_reach_the_tail() {
    let mcp = "src/gateway/router/handlers/dispatch_tools_call.rs";
    let text = source(mcp);
    let screened = only(
        &text,
        "// Screened at delivery, in `finalize_content`, with every other frame.",
        mcp,
    );
    let replayed = only(
        &text,
        ".audit_replay(tool_name, &arguments, session, &caller, response, audit)",
        mcp,
    );
    assert!(
        screened < replayed,
        "{mcp}: the replay is returned to the route tail"
    );
    let direct = "src/gateway/router/backend_handlers/direct_idempotency.rs";
    only(
        &source(direct),
        "Ok(SyncAdmission::Replay(response, _, _, _, bindings)) => {",
        direct,
    );
    only(
        &source(direct),
        "Ok((None, Some((response, bindings))))",
        direct,
    );
    let tail = "src/gateway/router/backend_handlers/direct_dispatch.rs";
    only(&source(tail), "a cached replay included", tail);
    let stdio = "src/gateway/server/stdio_dispatch.rs";
    let text = source(stdio);
    let broke = only(&text, "break 'tool_call meta_mcp\n", stdio);
    let audited = only(
        &text,
        ".audit_replay(&tool_name, args, session, &caller, response, audit)",
        stdio,
    );
    assert!(
        broke < audited,
        "{stdio}: the replay leaves the tool-call block into the tail"
    );
    let hit = "src/gateway/meta_mcp/invoke/pre_dispatch.rs";
    let text = source(hit);
    let served = only(
        &text,
        "return Some(GuardedValue::from_cache(cached).augment(|v| {",
        hit,
    );
    let stamped = served
        + text[served..]
            .find("crate::trust::CacheOutcome::Hit,")
            .expect("the cache hit is re-stamped");
    assert!(
        text[served..stamped].contains("self.maybe_stamp_provenance("),
        "{hit}: a cache hit is re-stamped inside dispatch"
    );
}
