// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The steps extracted from `invoke_tool_traced` keep its `tracing` target
//! (#2860): every event they raise names `INVOKE_TARGET`, so a filter or a
//! dashboard keyed on the invoke module still sees them. A new event written
//! without the pin would silently move to the child module's own target.

const STEPS: [(&str, &str); 3] = [
    ("pre_dispatch.rs", include_str!("pre_dispatch.rs")),
    ("post_dispatch.rs", include_str!("post_dispatch.rs")),
    ("legacy_bridge.rs", include_str!("legacy_bridge.rs")),
];

const EVENTS: [&str; 5] = ["trace!(", "debug!(", "info!(", "warn!(", "error!("];

#[test]
fn the_pinned_target_is_the_invoke_module() {
    assert_eq!(
        super::INVOKE_TARGET,
        "mcp_gateway::gateway::meta_mcp::invoke"
    );
}

#[test]
fn every_event_in_an_extracted_step_names_the_invoke_target() {
    let mut seen = 0;
    let mut unpinned = Vec::new();
    for (file, source) in STEPS {
        for event in EVENTS {
            for (at, _) in source.match_indices(event) {
                seen += 1;
                let args = source[at + event.len()..].trim_start();
                if !args.starts_with("target: INVOKE_TARGET,") {
                    let line = source[..at].lines().count();
                    unpinned.push(format!("{file}:{line}"));
                }
            }
        }
    }
    // A scan that found nothing would pass on any file it failed to read.
    assert!(seen > 0, "no tracing events found in the extracted steps");
    assert!(
        unpinned.is_empty(),
        "events without the invoke target: {unpinned:?}"
    );
}
