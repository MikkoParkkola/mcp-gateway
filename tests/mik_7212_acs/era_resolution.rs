// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use mcp_gateway::protocol::era::{Era, EraCache, ProbeOutcome, classify};
use serde_json::json;

fn discovery(versions: &serde_json::Value) -> serde_json::Value {
    json!({ "supportedVersions": versions, "capabilities": {} })
}

#[test]
fn a_result_that_is_not_a_discovery_document_is_not_modern() {
    // An unrelated result carrying a familiar key is not a peer announcing
    // this revision. Reading one as modern sends a request the peer never
    // said it could parse.
    let impostor = json!({ "supportedVersions": ["2026-07-28"] });
    assert_eq!(
        classify(&ProbeOutcome::Result(impostor)),
        Era::Legacy,
        "a document without capabilities is not a discovery document"
    );

    assert_eq!(
        classify(&ProbeOutcome::Result(discovery(&json!(["2026-07-28"])))),
        Era::Modern,
        "a complete document still resolves modern"
    );
}

#[tokio::test]
async fn a_probe_that_never_answered_is_not_remembered() {
    // Legacy is the right way to treat the next request and the wrong thing
    // to remember: a backend briefly unreachable would be pinned to the
    // legacy path for the life of the process, and a dual-era peer that
    // recovered would never be spoken to properly again.
    let cache = EraCache::for_backend("test");

    let first = cache
        .resolve_with(|| async { ProbeOutcome::NoAnswer })
        .await;
    assert_eq!(first, Era::Legacy, "silence is served as legacy");

    let second = cache
        .resolve_with(|| async { ProbeOutcome::Result(discovery(&json!(["2026-07-28"]))) })
        .await;
    assert_eq!(
        second,
        Era::Modern,
        "a recovered peer must be re-probed, not served from a cached failure"
    );
}

#[tokio::test]
async fn a_conclusive_answer_is_remembered() {
    // The cache must still do its job: one probe, then no more.
    let cache = EraCache::for_backend("test");
    let first = cache
        .resolve_with(|| async { ProbeOutcome::Result(discovery(&json!(["2026-07-28"]))) })
        .await;
    assert_eq!(first, Era::Modern);

    let second = cache
        .resolve_with(|| async { panic!("the cached era must be reused") })
        .await;
    assert_eq!(second, Era::Modern);
}
