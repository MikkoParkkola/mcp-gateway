// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A descriptor the gateway holds without close-on-exec makes the preview
//! refuse instead of leaking into it (ADR-027, Linux step 1).
//!
//! Its own test binary: the leaked descriptor would reach every process any
//! concurrent test in the same binary starts. The one other test, the
//! home-routing row, holds the same lock ([`ALONE`]), so the two never overlap.
#![cfg(target_os = "linux")]

#[path = "common/private_home.rs"]
#[macro_use]
mod private_home;

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::os::fd::AsFd as _;
use std::path::Path;

use mcp_gateway::preview_sandbox::{Refusal, probe_with_helper};

/// The two tests here never overlap: the descriptor the preview row leaks on
/// purpose would reach the child the routing row starts. Each holds this lock
/// for its whole run; tokio's, as the preview row holds it across awaits.
static ALONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn an_inherited_descriptor_makes_the_preview_refuse() {
    require_private_home!();
    let _alone = ALONE.lock().await;
    let file = tempfile::tempfile().unwrap();
    rustix::io::fcntl_setfd(file.as_fd(), rustix::io::FdFlags::empty()).unwrap();
    // The descriptor check before the helper connects is host-level, so the
    // probe, which reads the sandbox's own words, is what reports it.
    let refused = probe_with_helper(Path::new(gateway_bin::path())).await;
    drop(file);
    // Only the host refusing the namespaces may skip, and not where the
    // sandbox is required; any other answer is this row's own.
    let host_refused = match &refused {
        Err(Refusal::AppArmorRestricted | Refusal::UserNamespacesDisabled | Refusal::Container) => {
            true
        }
        Err(Refusal::Step(step)) => step.starts_with("starting the namespaces"),
        _ => false,
    };
    if host_refused {
        assert!(
            std::env::var_os("PREVIEW_SANDBOX_REQUIRED").is_none(),
            "the sandbox is required here but refused: {refused:?}"
        );
        return;
    }
    assert!(
        matches!(&refused, Err(Refusal::Step(step)) if step.starts_with("checking descriptors (inherited")),
        "{refused:?}"
    );
}

/// T3-T5: this binary's gateway home routes to the test-home override.
#[test]
fn private_home_routes_to_the_override() {
    let _alone = ALONE.blocking_lock();
    private_home::assert_routes_to_the_override(
        module_path!(),
        "private_home_routes_to_the_override",
    );
}
