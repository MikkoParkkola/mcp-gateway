// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The classic UI's registry loader reads the key the registry endpoint
//! returns its entries under, so the Add Server search has entries to show.

const INDEX: &str = include_str!("../src/gateway/ui/index.html");
const BACKENDS: &str = include_str!("../src/gateway/ui/backends.rs");

#[test]
fn the_registry_loader_reads_the_endpoints_entries() {
    assert!(
        BACKENDS.contains(r#"Json(json!({"entries": entries, "total": entries.len()}))"#),
        "the registry endpoint answers {{\"entries\": [...]}}"
    );
    let start = INDEX
        .find("async function loadRegistry(")
        .expect("the page defines loadRegistry()");
    let end = INDEX[start..].find("\n}\n").expect("loadRegistry() closes");
    let body = &INDEX[start..start + end];
    assert!(
        body.contains("d.entries") && !body.contains("d.servers"),
        "loadRegistry() must read the endpoint's `entries`: {body}"
    );
}
