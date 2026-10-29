// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An admin capability reload reports the change on the feed the
//! file watcher uses, so the drain refreshes the webhook routes and announces
//! the new tool list, as after a file reload.

use std::sync::Arc;

use crate::backend::BackendRegistry;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::gateway::meta_mcp::MetaMcp;

#[tokio::test]
async fn an_admin_reload_reports_the_change_like_a_file_reload() {
    let dir = tempfile::tempdir().expect("dir");
    let caps = Arc::new(CapabilityBackend::new(
        "hooks",
        Arc::new(CapabilityExecutor::new()),
    ));
    caps.load_from_directory(dir.path().to_str().expect("utf8"))
        .await
        .expect("load");
    let registry = Arc::new(BackendRegistry::new());
    let (feed, mut drain) = tokio::sync::mpsc::unbounded_channel();
    registry.set_change_feed(feed);
    let meta = MetaMcp::new(registry);
    meta.set_capabilities(caps);
    meta.reload_capabilities().await.expect("reload");
    assert!(
        matches!(
            drain.try_recv(),
            Ok(crate::backend::tools_nudge::ToolsNudge::Catalogue { name }) if name == "hooks"
        ),
        "the drain hears of the reload"
    );
    assert!(drain.try_recv().is_err(), "once, not twice");
}

/// `gateway_reload_config` on a file written as `yaml`, within a delivery
/// cell: the reload's answer and the effect the cell records.
async fn reload_effect(
    yaml: &str,
) -> (crate::Result<serde_json::Value>, Option<serde_json::Value>) {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let registry = Arc::new(BackendRegistry::new());
    let ctx = crate::config_reload::ReloadContext::new(
        path,
        Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        Arc::clone(&registry),
        crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    )
    .expect("the registry pairs with the config");
    let meta = MetaMcp::new(registry);
    meta.set_reload_context(Arc::new(ctx));
    Box::pin(crate::gateway::delivery_facts::scope(async move {
        let answer = Box::pin(meta.reload_config()).await;
        let mut fields = serde_json::Map::new();
        crate::gateway::delivery_facts::record_fields(
            crate::gateway::delivery_facts::snapshot().as_ref(),
            false,
            &mut fields,
        );
        (answer, fields.get("response_effect").cloned())
    }))
    .await
}

/// A reload the network-posture policy refuses is the gateway refusing
/// the operator's request: it records refused. A reload refused because
/// the file does not parse is no policy decision and records nothing
/// refused.
#[tokio::test]
async fn only_a_posture_refused_reload_records_refused() {
    // Publishing the gateway over open tools: the posture refusal.
    let (refused, effect) = Box::pin(reload_effect(
        "server:\n  public_url: \"https://gw.example.com\"\n",
    ))
    .await;
    let error = refused.expect_err("premise: the posture refusal");
    assert_eq!(
        error.to_rpc_code(),
        -32600,
        "premise: the posture refusal: {error}"
    );
    assert_eq!(effect, Some(serde_json::json!("refused")), "{error}");

    let (unparsed, effect) = Box::pin(reload_effect("server: [unclosed\n")).await;
    let error = unparsed.expect_err("premise: the file does not parse");
    assert_eq!(
        error.to_rpc_code(),
        -32603,
        "premise: not the posture refusal: {error}"
    );
    assert_ne!(effect, Some(serde_json::json!("refused")), "{error}");
}
