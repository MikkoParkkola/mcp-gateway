// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A reload that changes which of a backend's configured `headers:` values
//! count as secret replaces that backend's instance, which carries the new
//! record; a reload dropped before its publish leaves the instance it
//! registered with its own record.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::backend::Backend;
use crate::gateway::test_helpers::write_owner_only;

/// Long enough that no length gate applies.
const TOKEN: &str = "configured-token-4e7d19a0c2b8";

/// A config whose one backend, `b`, sends header `X-Key: <value>`.
fn config(value: &str) -> String {
    format!(
        "backends:\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    headers:\n      \
         X-Key: \"{value}\"\n"
    )
}

/// The registry and reload context startup would build for `path`.
fn started(path: &std::path::Path) -> (Arc<BackendRegistry>, ReloadContext) {
    let mut loaded = Config::load_evaluated(Some(path)).expect("the running config loads");
    let registry = Arc::new(BackendRegistry::new());
    registry.set_load_record(std::mem::take(&mut loaded.configured));
    let cfg = loaded.config.backends["b"].clone();
    #[allow(
        clippy::disallowed_methods,
        reason = "Test: registers the backend startup would register"
    )]
    let registered = registry.register(Arc::new(Backend::new(
        "b",
        cfg,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )));
    assert!(registered, "premise: registered");
    let ctx = ReloadContext::new(
        path.to_path_buf(),
        Arc::new(LiveConfig::new(loaded.config)),
        Arc::clone(&registry),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config");
    (registry, ctx)
}

fn instance(registry: &BackendRegistry) -> Arc<Backend> {
    #[allow(
        clippy::disallowed_methods,
        reason = "Test: reads which instance the reload left registered"
    )]
    registry.get("b").expect("b is registered")
}

/// The instance's record: whether it holds the token, and as what.
fn holds_token(backend: &Backend) -> bool {
    backend
        .configured_record()
        .iter()
        .any(|secret| secret.value == TOKEN)
}

/// A secret file holding the token, and the reference naming it.
fn secret_file(dir: &std::path::Path) -> String {
    let file = dir.join("x-key.secret");
    write_owner_only(&file, TOKEN).expect("write the secret file");
    format!("file:{}", file.display())
}

/// Marking: the same bytes rewritten from a literal to a `file:` reference.
/// The resolved config is identical, yet the reload replaces the instance,
/// and the new one holds the token as a secret.
#[tokio::test]
async fn a_value_newly_written_as_a_reference_replaces_the_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, config(TOKEN)).expect("write");
    let (registry, ctx) = started(&path);
    let before = instance(&registry);
    assert!(!holds_token(&before), "premise: a literal is not secret");

    write_owner_only(&path, config(&secret_file(dir.path()))).expect("write");
    ctx.reload_outcome().await.expect("the reload applies");
    let after = instance(&registry);
    assert!(
        !Arc::ptr_eq(&before, &after),
        "the instance was not replaced"
    );
    assert!(
        holds_token(&after),
        "the new instance does not hold the token"
    );
}

/// Unmarking: a reference rewritten back to the same literal replaces the
/// instance again, and the new one holds nothing.
#[tokio::test]
async fn a_reference_rewritten_as_a_literal_replaces_the_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, config(&secret_file(dir.path()))).expect("write");
    let (registry, ctx) = started(&path);
    let before = instance(&registry);
    assert!(holds_token(&before), "premise: a reference is secret");

    write_owner_only(&path, config(TOKEN)).expect("write");
    ctx.reload_outcome().await.expect("the reload applies");
    let after = instance(&registry);
    assert!(
        !Arc::ptr_eq(&before, &after),
        "the instance was not replaced"
    );
    assert!(
        !holds_token(&after),
        "the new instance still holds the token"
    );
}

/// Cancelled: a marking reload dropped after it registered the replacement
/// and before its publish. The replacement stays registered with its own
/// record, and the next reload of the unchanged file leaves it in place:
/// nothing retires the pins the running instance holds.
#[tokio::test]
async fn a_reload_dropped_before_its_publish_leaves_the_new_instance_its_pins() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, config(TOKEN)).expect("write");
    let (registry, ctx) = started(&path);
    let ctx = Arc::new(ctx);

    write_owner_only(&path, config(&secret_file(dir.path()))).expect("write");
    let pause = super::reload_pause::arm(&super::reload_pause::after_apply(&path));
    let running = tokio::spawn({
        let ctx = Arc::clone(&ctx);
        async move { ctx.reload_outcome().await }
    });
    // Bounded: a reload that applies no patch never reaches this pause, and
    // the row must fail rather than wait for it.
    tokio::time::timeout(crate::test_wait::HANG_BOUND, pause.reached.notified())
        .await
        .expect("the reload never reached the after-apply pause: it applied no patch");
    running.abort();
    let _ = running.await;
    let replaced = instance(&registry);
    assert!(
        holds_token(&replaced),
        "the registered replacement lost its record"
    );

    ctx.reload_outcome().await.expect("the next reload applies");
    let after = instance(&registry);
    assert!(
        Arc::ptr_eq(&replaced, &after),
        "an unchanged reload replaced it"
    );
    assert!(holds_token(&after), "the next reload dropped its record");
}
