// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8520.RELOAD.1 / RELOAD.4: a config reload applies `surfaced_tools` to
//! the running gateway. Each row drives a real reload: the config is written
//! to a file, the gateway is attached to a reload context the way
//! `build_meta_mcp` attaches it, and `reload_outcome` reads the file.

use std::sync::Arc;
use std::time::Duration;

use crate::backend::BackendRegistry;
use crate::config::{Config, SurfacedToolConfig};
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::gateway::meta_mcp::MetaMcp;

fn surfaced(pairs: &[(&str, &str)]) -> Vec<SurfacedToolConfig> {
    pairs
        .iter()
        .map(|(server, tool)| SurfacedToolConfig {
            server: (*server).to_string(),
            tool: (*tool).to_string(),
        })
        .collect()
}

fn config_with(pairs: &[(&str, &str)]) -> Config {
    let mut config = Config::default();
    config.meta_mcp.surfaced_tools = surfaced(pairs);
    config
}

/// A gateway started on `start`, attached to a reload context over a config
/// file in `dir`, as `build_meta_mcp` attaches it.
fn started(dir: &tempfile::TempDir, start: &[(&str, &str)]) -> (MetaMcp, Arc<ReloadContext>) {
    let initial = config_with(start);
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(
        &path,
        serde_yaml::to_string(&initial).expect("yaml"),
    )
    .expect("write");
    let registry = Arc::new(BackendRegistry::new());
    let meta = MetaMcp::new(Arc::clone(&registry))
        .with_surfaced_tools(initial.meta_mcp.surfaced_tools.clone());
    let context = Arc::new(
        ReloadContext::new(
            path,
            Arc::new(LiveConfig::new(initial)),
            registry,
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config"),
    );
    meta.set_reload_context(Arc::clone(&context));
    (meta, context)
}

/// Rewrite the file to `pairs` and reload it.
async fn reload_to(dir: &tempfile::TempDir, context: &ReloadContext, pairs: &[(&str, &str)]) {
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(
        &path,
        serde_yaml::to_string(&config_with(pairs)).expect("yaml"),
    )
    .expect("write");
    context
        .reload_outcome()
        .await
        .expect("premise: the reload succeeds");
}

/// L1 (N1): a reload that adds a surfaced name surfaces it.
#[tokio::test]
async fn l1_a_reload_adds_a_surfaced_name() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, context) = started(&dir, &[("alpha", "read")]);
    reload_to(&dir, &context, &[("alpha", "read"), ("beta", "write")]).await;
    assert_eq!(
        meta.surfaced_server_unscoped("read"),
        Some("alpha"),
        "L1: kept"
    );
    assert_eq!(
        meta.surfaced_server_unscoped("write"),
        Some("beta"),
        "L1: the added name is not surfaced after the reload"
    );
}

/// L1 (N1): a reload that removes a surfaced name withdraws it.
#[tokio::test]
async fn l1_a_reload_removes_a_surfaced_name() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, context) = started(&dir, &[("alpha", "read"), ("beta", "write")]);
    reload_to(&dir, &context, &[("alpha", "read")]).await;
    assert_eq!(
        meta.surfaced_server_unscoped("write"),
        None,
        "L1: the removed name is still surfaced after the reload"
    );
    assert_eq!(
        meta.surfaced_server_unscoped("read"),
        Some("alpha"),
        "L1: kept"
    );
}

/// L1 (N1): a reload that moves a name to another server applies the move.
#[tokio::test]
async fn l1_a_reload_moves_a_surfaced_name() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, context) = started(&dir, &[("alpha", "read")]);
    reload_to(&dir, &context, &[("beta", "read")]).await;
    assert_eq!(
        meta.surfaced_server_unscoped("read"),
        Some("beta"),
        "L1: the moved name still resolves to its startup server"
    );
}

/// L1 (pin): an unchanged list leaves the surfaced set as it was.
#[tokio::test]
async fn l1_an_unchanged_reload_keeps_the_surfaced_set() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, context) = started(&dir, &[("alpha", "read")]);
    reload_to(&dir, &context, &[("alpha", "read")]).await;
    assert_eq!(
        meta.surfaced_server_unscoped("read"),
        Some("alpha"),
        "L1: kept"
    );
}

/// L4 (N4, N5): a reload validates the new list as startup does. A name that
/// collides with a meta tool and a duplicate are dropped; the rest applies.
/// A list of only invalid entries leaves an empty set, and the reload still
/// succeeds.
#[tokio::test]
async fn l4_a_reload_drops_invalid_entries_and_never_aborts() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, context) = started(&dir, &[("alpha", "read")]);
    reload_to(
        &dir,
        &context,
        &[
            ("alpha", "gateway_invoke"),
            ("beta", "write"),
            ("gamma", "write"),
        ],
    )
    .await;
    assert_eq!(
        meta.surfaced_server_unscoped("gateway_invoke"),
        None,
        "L4: a meta-tool collision was surfaced on reload"
    );
    assert_eq!(
        meta.surfaced_server_unscoped("write"),
        Some("beta"),
        "L4: the first of two duplicate names is not the one surfaced"
    );
    assert_eq!(
        meta.surfaced_server_unscoped("read"),
        None,
        "L4: the dropped name stayed"
    );
    reload_to(&dir, &context, &[("alpha", "gateway_invoke")]).await;
    assert_eq!(
        meta.surfaced_server_unscoped("write"),
        None,
        "L4: an all-invalid reload left the previous set in place"
    );
}

/// L5/L6 (N6, N6b): one request reads one surfaced map. Inside a request's
/// visibility memo, the first read (admission's, in production) fixes the
/// map for the rest of the request; a reload landing mid-request does not
/// split admission, policy, dispatch and the deferred-replay key across two
/// servers (MIK-8520.REPLAY.3).
#[tokio::test]
async fn l5_one_request_reads_one_surfaced_map() {
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_surfaced_tools(surfaced(&[("alpha", "read")]));
    let (first, second) = super::super::visible::memo::with_visibility_memo(async {
        let first = meta.surfaced_server_unscoped("read").map(str::to_owned);
        meta.resurface_for_test("read", "beta");
        let second = meta.surfaced_server_unscoped("read").map(str::to_owned);
        (first, second)
    })
    .await;
    assert_eq!(first.as_deref(), Some("alpha"), "premise: the first read");
    assert_eq!(
        second.as_deref(),
        Some("alpha"),
        "L5: a mid-request move reached the same request's second read"
    );
    assert_eq!(
        meta.surfaced_server_unscoped("read"),
        Some("beta"),
        "L5: outside the request the live map moved"
    );
}
