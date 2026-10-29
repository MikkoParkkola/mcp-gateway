// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A reload may not register a backend under the running capability
//! backend's name. The `capabilities` section applies only at restart, so a
//! reload that renames `capabilities.name` leaves the capability attached
//! under its old name; load validation compares the new name only.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::gateway::test_helpers::write_owner_only;

const BACKEND: &str = "    http_url: \"http://127.0.0.1:9/mcp\"\n";

fn config(capabilities: &str, backends: &[&str]) -> String {
    let mut yaml = format!("capabilities:\n  name: {capabilities}\nbackends:\n");
    for name in backends {
        let _ = write!(yaml, "  {name}:\n{BACKEND}");
    }
    yaml
}

/// A reload context on `path`, with a capability backend named `edits`
/// attached, as startup attaches it.
fn context(path: &std::path::Path, registry: &Arc<BackendRegistry>) -> ReloadContext {
    let running = Config::load(Some(path)).expect("the running config loads");
    ReloadContext::new(
        path.to_path_buf(),
        Arc::new(LiveConfig::new(running)),
        Arc::clone(registry),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config")
    .with_capabilities(Some(Arc::new(CapabilityBackend::new(
        "edits",
        Arc::new(CapabilityExecutor::new()),
    ))))
}

fn assert_clash_refused(refused: &str, registry: &BackendRegistry) {
    assert!(
        refused.contains("backends.edits has the name of the running capability backend"),
        "{refused}"
    );
    #[allow(
        clippy::disallowed_methods,
        reason = "Test: reads the registry the refused reload must not have touched"
    )]
    let registered = registry.get("edits");
    assert!(registered.is_none(), "nothing is registered under the name");
}

/// RUNCLASH.2: one reload renames `capabilities.name` and adds a backend
/// under the old name. Validation passes (the new name differs); the attached
/// capability still holds the old one, so the reload is refused.
#[tokio::test]
async fn a_reload_adding_a_backend_under_the_capability_name_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, config("edits", &["a"])).expect("write");
    let registry = Arc::new(BackendRegistry::new());
    let ctx = context(&path, &registry);

    write_owner_only(&path, config("renamed", &["a", "edits"])).expect("write");
    let refused = ctx
        .reload_outcome()
        .await
        .expect_err("the clash is refused");
    assert_clash_refused(&refused, &registry);
}

/// RUNCLASH.2, two steps: the rename is published by one reload and the
/// backend added by the next. The check reads the attached capability, not
/// the published config, so the second is refused too.
#[tokio::test]
async fn a_rename_then_a_clashing_add_in_the_next_reload_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, config("edits", &["a"])).expect("write");
    let registry = Arc::new(BackendRegistry::new());
    let ctx = context(&path, &registry);

    write_owner_only(&path, config("renamed", &["a"])).expect("write");
    ctx.reload_outcome()
        .await
        .expect("the rename alone is accepted");
    write_owner_only(&path, config("renamed", &["a", "edits"])).expect("write");
    let refused = ctx
        .reload_outcome()
        .await
        .expect_err("the clash is refused");
    assert_clash_refused(&refused, &registry);
}

/// RUNCLASH.3 control: a reload adding a backend under any other name applies.
#[tokio::test]
async fn a_reload_adding_an_unrelated_backend_still_applies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, config("edits", &["a"])).expect("write");
    let registry = Arc::new(BackendRegistry::new());
    let ctx = context(&path, &registry);

    write_owner_only(&path, config("edits", &["a", "other"])).expect("write");
    ctx.reload_outcome()
        .await
        .expect("an unrelated add applies");
    #[allow(
        clippy::disallowed_methods,
        reason = "Test: reads the registry the reload applied"
    )]
    let registered = registry.get("other");
    assert!(registered.is_some(), "the new backend is registered");
}

/// RUNCLASH.2, modified arm: a backend already running under the attached
/// capability's name (what a reload before this check could leave) is not
/// replaced by a reload that changes it.
#[tokio::test]
async fn a_reload_modifying_a_backend_under_the_capability_name_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, config("renamed", &["a", "edits"])).expect("write");
    let registry = Arc::new(BackendRegistry::new());
    let ctx = context(&path, &registry);

    let modified = config("renamed", &["a", "edits"]).replace(
        "  edits:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
        "  edits:\n    http_url: \"http://127.0.0.1:10/mcp\"\n",
    );
    write_owner_only(&path, modified).expect("write");
    let refused = ctx
        .reload_outcome()
        .await
        .expect_err("the clash is refused");
    assert_clash_refused(&refused, &registry);
}

/// RUNCLASH.3 control: removing the backend that holds the capability's name
/// is not refused, so an operator can always clear an existing clash.
#[tokio::test]
async fn a_reload_removing_the_clashing_backend_still_applies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, config("renamed", &["a", "edits"])).expect("write");
    let registry = Arc::new(BackendRegistry::new());
    let ctx = context(&path, &registry);

    write_owner_only(&path, config("renamed", &["a"])).expect("write");
    ctx.reload_outcome()
        .await
        .expect("removing the clashing backend applies");
}
