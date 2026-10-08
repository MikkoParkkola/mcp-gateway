// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8034`: the admin capability reload reaches the change drain, which
//! refreshes webhook routes and announces a catalogue that changed, exactly as
//! a file-watcher reload does.

use std::sync::Arc;

use crate::backend::BackendRegistry;
use crate::backend::tools_nudge::ToolsNudge;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::gateway::meta_mcp::MetaMcp;

#[tokio::test]
async fn an_admin_capability_reload_reports_its_catalogue_once() {
    let registry = Arc::new(BackendRegistry::new());
    let (feed, mut nudges) = tokio::sync::mpsc::unbounded_channel();
    registry.set_change_feed(feed);
    let meta = MetaMcp::new(Arc::clone(&registry));
    let capabilities = CapabilityBackend::new("capabilities", Arc::new(CapabilityExecutor::new()));
    *meta.capabilities.write() = Some(Arc::new(capabilities));

    meta.reload_capabilities()
        .await
        .expect("an empty catalogue reloads");

    assert_eq!(
        nudges.try_recv().ok(),
        Some(ToolsNudge::Catalogue {
            name: "capabilities".to_string(),
        }),
        "the reload must reach the change drain"
    );
    assert!(nudges.try_recv().is_err(), "and only once");
}
