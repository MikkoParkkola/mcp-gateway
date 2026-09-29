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

use super::visibility_allocations::meta_with;
use crate::gateway::meta_mcp::anonymous_caller;

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

    assert!(
        raced.is_none(),
        "may_invoke returned a config error on call {calls} while a reload removed the tool: {raced:?}"
    );
}
