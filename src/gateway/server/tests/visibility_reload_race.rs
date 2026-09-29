// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2236: the identity-grant rule asked whether a tool exists and then read
//! its definition under a second lock. A reload that removed the tool in
//! between turned an ordinary skip into `Capability not found`, and the
//! dispatch path returned that config error to the caller.
//!
//! There is no seam between the two lookups, so this races them: one thread
//! removes and re-registers the tool while this one calls `may_invoke`. Red is
//! probabilistic on the two-lookup code; green is structural once the rule
//! looks the tool up once, because the error has no remaining source.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::json;

use super::visibility_allocations::meta_with;
use crate::gateway::meta_mcp::anonymous_caller;
use crate::protocol::RequestId;

#[test]
fn a_reload_racing_may_invoke_is_never_a_config_error() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (meta, backend) = rt.block_on(meta_with(dir.path(), "x"));
    let definition = backend.get("lookup").unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let toggler = {
        let (backend, stop) = (Arc::clone(&backend), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                backend.unload_capability("lookup");
                backend.register_capability(definition.clone()).unwrap();
            }
        })
    };

    let caller = anonymous_caller();
    let deadline = Instant::now() + Duration::from_secs(3);
    let (mut calls, mut raced) = (0_u64, None);
    while raced.is_none() && Instant::now() < deadline {
        if let Err(e) = meta.may_invoke("caps", "lookup", caller.scope(), None) {
            let e = e.to_string();
            if e.contains("Capability not found") {
                raced = Some(e);
            }
        }
        calls += 1;
    }
    stop.store(true, Ordering::Relaxed);
    toggler.join().unwrap();

    // A starved reader would pass without ever reaching the rule.
    assert!(
        calls >= 1_000,
        "only {calls} may_invoke calls ran in the window"
    );
    assert!(
        raced.is_none(),
        "may_invoke returned a config error on call {calls} while a reload removed the tool: {raced:?}"
    );
}

/// Absence fails closed: once removed, the tool is not listed, and a call to
/// it gets the refusal a name that never existed gets, never an admit.
#[test]
fn a_removed_tool_is_unlisted_and_refused_like_an_unknown_one() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (meta, backend) = rt.block_on(meta_with(dir.path(), "x"));
    let call = |tool: &str, arguments: serde_json::Value| {
        let id = RequestId::Number(1);
        rt.block_on(meta.handle_tools_call(id, tool, arguments, None, anonymous_caller()))
    };
    let list =
        || serde_json::to_string(&call("gateway_list_tools", json!({"server": "caps"}))).unwrap();

    let before = list();
    assert!(
        before.contains("lookup"),
        "positive control: lookup must be listed first: {before}"
    );
    assert!(backend.unload_capability("lookup"));
    let after = list();
    assert!(
        !after.contains("lookup"),
        "a removed tool is still listed: {after}"
    );

    // Admitted, the call would fail too (example.invalid), so an error alone
    // proves nothing: it must be the not-found refusal, naming the tool.
    for tool in ["lookup", "never_registered"] {
        let response = call(
            "gateway_invoke",
            json!({"server": "caps", "tool": tool, "arguments": {}}),
        );
        let text = serde_json::to_string(&response).unwrap().to_lowercase();
        assert!(
            text.contains(&format!("not found: '{tool}'")),
            "{tool} after removal did not get the not-found refusal: {text}"
        );
    }
}
