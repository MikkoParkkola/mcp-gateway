// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A config reload applies `surfaced_tools` to
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
    started_in(dir, start, Arc::new(BackendRegistry::new()))
}

/// [`started`] over a caller's `registry`, so a row can attach a nudge feed.
fn started_in(
    dir: &tempfile::TempDir,
    start: &[(&str, &str)],
    registry: Arc<BackendRegistry>,
) -> (MetaMcp, Arc<ReloadContext>) {
    let initial = config_with(start);
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(
        &path,
        serde_yaml::to_string(&initial).expect("yaml"),
    )
    .expect("write");
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
/// servers.
#[tokio::test]
async fn l5_one_request_reads_one_surfaced_map() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
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

/// L3 (N2, N3): the reload hook sends exactly one surfaced nudge for a
/// changed list, and none for an identical one, read at the nudge sender.
#[tokio::test]
async fn l3_a_changed_list_nudges_once_and_an_identical_one_never() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Arc::new(BackendRegistry::new());
    let (feed, mut nudges) = tokio::sync::mpsc::unbounded_channel();
    registry.set_change_feed(feed);
    let (_meta, context) = started_in(&dir, &[("t1", "alpha")], registry);
    let mut surfaced_nudges = || {
        let mut count = 0;
        while let Ok(nudge) = nudges.try_recv() {
            count += usize::from(matches!(
                nudge,
                crate::backend::tools_nudge::ToolsNudge::Surfaced
            ));
        }
        count
    };
    let _ = surfaced_nudges();
    reload_to(&dir, &context, &[("t1", "alpha")]).await;
    assert_eq!(surfaced_nudges(), 0, "L3: an identical list nudged");
    reload_to(&dir, &context, &[("t1", "beta")]).await;
    assert_eq!(
        surfaced_nudges(),
        1,
        "L3: a changed list must nudge exactly once"
    );
    reload_to(&dir, &context, &[("t1", "beta")]).await;
    assert_eq!(
        surfaced_nudges(),
        0,
        "L3: the repeat of the new list nudged"
    );
}

/// Rewrite the config file to `pairs` without reloading it.
fn write_file(dir: &tempfile::TempDir, pairs: &[(&str, &str)]) {
    crate::gateway::test_helpers::write_owner_only(
        &dir.path().join("gateway.yaml"),
        serde_yaml::to_string(&config_with(pairs)).expect("yaml"),
    )
    .expect("write");
}

/// L2 (N1): the `gateway_reload_config` meta tool applies a moved name.
#[tokio::test]
async fn l2_the_reload_meta_tool_applies_surfaced_tools() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, _context) = started(&dir, &[("alpha", "read")]);
    write_file(&dir, &[("beta", "read")]);
    meta.reload_config()
        .await
        .expect("premise: the meta tool reloads");
    assert_eq!(
        meta.surfaced_server_unscoped("read"),
        Some("beta"),
        "L2: gateway_reload_config left the surfaced set as it was"
    );
}

/// L2 (N1): a reload the file watcher drives applies a moved name. The
/// watcher runs its own reload context, so this row fails when the gateway
/// does not hand the watcher its surfaced hook.
#[tokio::test]
async fn l2_a_watcher_driven_reload_applies_surfaced_tools() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    let initial = config_with(&[("alpha", "read")]);
    crate::gateway::test_helpers::write_owner_only(
        &path,
        serde_yaml::to_string(&initial).expect("yaml"),
    )
    .expect("write");
    let registry = Arc::new(BackendRegistry::new());
    let meta = MetaMcp::new(Arc::clone(&registry))
        .with_surfaced_tools(initial.meta_mcp.surfaced_tools.clone());
    let (_shutdown, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let _watcher = crate::config_reload::ConfigWatcher::start_with_hook(
        path,
        Arc::new(LiveConfig::new(initial.clone())),
        registry,
        &initial,
        Arc::new(crate::config::LiveEnv::new(
            Arc::new(crate::config::EnvOverlay::none()),
            crate::config::ResolvedEnvFiles::default(),
        )),
        None,
        None,
        shutdown_rx,
        None,
        Some(meta.surfaced_hook()),
    )
    .expect("the watcher starts");
    write_file(&dir, &[("beta", "read")]);
    // The watcher debounces on a std `Instant`: poll real time past it.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while meta.surfaced_server_unscoped("read") != Some("beta")
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        meta.surfaced_server_unscoped("read"),
        Some("beta"),
        "L2: a watcher-driven reload left the surfaced set as it was"
    );
}

/// L15 (pin scope): a task's pin lasts only as long as its dispatch. A resume
/// reuses its answering request's memo, so a pin left in it would route the
/// rest of that request to the recorded server after a reload moved the name.
#[tokio::test]
async fn l15_a_pin_is_lifted_when_its_dispatch_ends_in_a_reused_memo() {
    use crate::gateway::meta_mcp::visible::memo::{
        pin_surfaced, surfaced_pin, with_visibility_memo,
    };
    with_visibility_memo(async {
        let outer = pin_surfaced("search", "alpha");
        assert_eq!(surfaced_pin("search"), Some("alpha"));
        with_visibility_memo(async {
            let _inner = pin_surfaced("search", "beta");
            assert_eq!(surfaced_pin("search"), Some("beta"));
        })
        .await;
        assert_eq!(surfaced_pin("search"), Some("alpha"), "inner pin leaked");
        drop(outer);
        assert_eq!(surfaced_pin("search"), None, "outer pin leaked");
    })
    .await;
}
