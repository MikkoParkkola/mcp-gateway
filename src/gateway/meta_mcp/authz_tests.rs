// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the dispatch authorization chokepoint (MIK-7252).
//!
//! Plan: `docs/design/authorize-at-dispatch-test-plan.md`. Test names follow
//! its convention, `authz_<row>_<slug>`, so a row and its test are findable
//! from each other.
//!
//! One rule the plan states and these fixtures keep: no double reimplements
//! production. The only doubles here are a transport at the network boundary
//! and the authorizers `AllowAll` / `DenyAll` / `CountingAuthorizer`, none of
//! which contains policy logic. The thing under test is the real dispatch path.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::{AllowAll, CountingAuthorizer, DenyAll, ToolAuthorizer};
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::protocol::RequestId;
use crate::transport::Transport;

/// A backend transport that counts the calls that actually reach it.
///
/// The oracle for "a refused call never dispatched": a check placed after
/// dispatch still refuses, and only this counter can tell the two apart.
struct CountingTransport {
    calls: Arc<AtomicUsize>,
    result: Value,
}

#[async_trait::async_trait]
impl Transport for CountingTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        assert_eq!(method, "tools/call");
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            self.result.clone(),
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A registry holding one backend whose calls are counted.
fn counted_backend(name: &str) -> (Arc<BackendRegistry>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(CountingTransport {
        calls: Arc::clone(&calls),
        result: json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
    }));
    let _ = registry.register(backend);
    (registry, calls)
}

/// A caller context bound to a given authorizer.
///
/// Built exactly as `router/handlers.rs` and `server/mod.rs` build theirs: the
/// authorizer is the only thing that varies. A fixture that assembled the
/// context some other way would prove the double works rather than that the
/// chokepoint is reached.
fn ctx<'a>(authorizer: &'a (dyn ToolAuthorizer + Sync)) -> MetaMcpCallerContext<'a> {
    MetaMcpCallerContext {
        authorizer,
        api_key_name: Some("test-caller"),
        agent_id: None,
        grant_subject: None,
        verified_identity: None,
        is_admin: false,
    }
}

fn invoke_args(server: &str, tool: &str) -> Value {
    json!({ "server": server, "tool": tool, "arguments": {} })
}

// ===========================================================================
// AUTHZ.13a-13e — every meta-layer dispatch shape is refused when the
// authorizer denies. The chokepoint claim itself, and five independent cases
// on purpose: one case asserting five shapes stops at the first failure and
// reports one defect where there may be four.
// ===========================================================================

#[tokio::test]
async fn authz_13b_gateway_invoke_denied() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let result = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&DenyAll))
        .await;

    assert!(result.is_err(), "a denied gateway_invoke must be refused");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a refused call must never reach the backend"
    );
}

#[tokio::test]
async fn authz_13b_gateway_invoke_allowed() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let result = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;

    assert!(result.is_ok(), "an allowed invoke must succeed: {result:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the allow path must actually reach the backend, or the refusal above \
         proves nothing about authorization"
    );
}

#[tokio::test]
async fn authz_13c_code_mode_single_denied() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry).with_code_mode(true);

    let result = meta
        .code_mode_execute(
            &json!({ "tool": "alpha:read", "arguments": {} }),
            None,
            &ctx(&DenyAll),
        )
        .await;

    assert!(result.is_err(), "a denied code-mode call must be refused");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no backend call");
}

#[tokio::test]
async fn authz_13d_code_mode_chain_step_denied() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry).with_code_mode(true);

    let result = meta
        .code_mode_execute(
            &json!({ "chain": [ { "tool": "alpha:read", "arguments": {} } ] }),
            None,
            &ctx(&DenyAll),
        )
        .await;

    let refused = result.as_ref().map_or(true, |v| {
        v.get("isError").and_then(Value::as_bool).unwrap_or(false)
            || v.to_string().to_lowercase().contains("denied")
    });
    assert!(refused, "a denied chain step must be refused: {result:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no backend call");
}

// ===========================================================================
// AUTHZ.13e / 17 / 18 / 19 — the playbook path. This is the shape the router
// never authorized, because a playbook step's target comes from the playbook
// definition and never appears in the request the router inspects.
// ===========================================================================

/// Register a playbook and run it through the real `gateway_run_playbook`
/// entry point, so the test exercises the production path rather than the
/// engine in isolation.
async fn run_playbook_yaml(
    meta: &MetaMcp,
    yaml: &str,
    caller: &MetaMcpCallerContext<'_>,
) -> crate::Result<Value> {
    let definition: crate::playbook::PlaybookDefinition =
        serde_yaml::from_str(yaml).expect("playbook fixture must parse");
    let name = definition.name.clone();
    // Registered through the same public entry point an operator's config uses,
    // so the test drives the production path rather than a test-only seam.
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    meta.set_playbook_engine(engine);
    meta.run_playbook(&json!({ "name": name, "arguments": {} }), caller)
        .await
}

#[tokio::test]
async fn authz_13e_playbook_step_denied() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let result = run_playbook_yaml(
        &meta,
        r"
name: one_step
description: a single step against a backend
on_error: abort
steps:
  - name: read
    server: alpha
    tool: read
",
        &ctx(&DenyAll),
    )
    .await;

    assert!(
        result.is_err(),
        "a playbook step must face the caller's authorization: {result:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a refused step must never reach the backend"
    );
}

#[tokio::test]
async fn authz_13e_playbook_step_allowed() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let result = run_playbook_yaml(
        &meta,
        r"
name: one_step_ok
description: a single step against a backend
on_error: abort
steps:
  - name: read
    server: alpha
    tool: read
",
        &ctx(&AllowAll),
    )
    .await;

    assert!(result.is_ok(), "an allowed playbook must run: {result:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the allow path must reach the backend, or the refusal above proves \
         nothing about authorization"
    );
}

// ===========================================================================
// AUTHZ.17-19 — denial semantics. Every fixture sets `on_error` explicitly:
// the default is `Abort`, and an `Abort` fixture passes whether or not the
// rules below hold.
// ===========================================================================

/// A refusal is not retried, and says why.
///
/// One step, so the consultation count is unambiguous: a whole-run count is
/// satisfied by a terminal refusal, and a multi-step playbook under `DenyAll`
/// denies every step, so the total could never be one even when correct.
#[tokio::test]
async fn authz_17_denial_is_not_retried() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let counting = CountingAuthorizer::new(DenyAll);

    let result = run_playbook_yaml(
        &meta,
        r"
name: retrying
description: retries a failing step
on_error: retry
max_retries: 3
steps:
  - name: read
    server: alpha
    tool: read
",
        &ctx(&counting),
    )
    .await;

    assert_eq!(
        counting.count_for("alpha", "read"),
        1,
        "a denial must be consulted once, not once per retry attempt"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no backend call");

    let value = result.expect("retry continues past a failed step");
    let errors = value
        .get("step_errors")
        .expect("a denied step must record why it failed");
    assert!(
        errors.get("read").is_some(),
        "the refusal reason must be recorded under the step's name: {errors}"
    );
}

/// An ordinary error still retries. Without this control, an implementation
/// that stopped retrying *everything* would satisfy the case above.
///
/// The failure has to be a genuine `Err`, and that is narrower than it looks:
/// a missing backend comes back as `Ok` carrying an `isError` envelope, so the
/// engine records the step as COMPLETED and the retry loop never engages. An
/// invalid tool name is rejected after the chokepoint and does return `Err`,
/// so the authorizer is consulted once per attempt.
#[tokio::test]
async fn authz_17b_ordinary_error_still_retries() {
    let registry = Arc::new(BackendRegistry::new());
    let meta = MetaMcp::new(registry);
    let counting = CountingAuthorizer::new(AllowAll);

    let result = run_playbook_yaml(
        &meta,
        r"
name: retrying_ordinary
description: retries a step whose tool name cannot be dispatched
on_error: retry
max_retries: 3
steps:
  - name: read
    server: alpha
    tool: 'bad/name'
",
        &ctx(&counting),
    )
    .await;

    assert_eq!(
        counting.count_for("alpha", "bad/name"),
        3,
        "an ordinary failure must still be retried max_retries times; only a \
         denial short-circuits"
    );
    let value = result.expect("retry continues past a failed step");
    assert!(
        value
            .get("step_errors")
            .and_then(|e| e.get("read"))
            .is_some(),
        "an ordinary failure must be explained too, not only a refusal: {value}"
    );
}

/// Under `continue`, a denied step is recorded and the run carries on.
#[tokio::test]
async fn authz_18_continue_records_and_carries_on() {
    let (registry, _calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let value = run_playbook_yaml(
        &meta,
        r"
name: continuing
description: one denied step, then one allowed step
on_error: continue
steps:
  - name: denied
    server: alpha
    tool: read
  - name: also_denied
    server: alpha
    tool: write
",
        &ctx(&DenyAll),
    )
    .await
    .expect("continue must not abort the run");

    let failed = value
        .get("steps_failed")
        .and_then(Value::as_array)
        .expect("steps_failed must be present");
    assert_eq!(failed.len(), 2, "both steps ran and both were refused");

    let errors = value.get("step_errors").expect("reasons must be recorded");
    assert!(
        errors.get("denied").is_some() && errors.get("also_denied").is_some(),
        "a partial run must explain itself, or it reads as a success: {errors}"
    );
}

/// A run that fails nothing serialises exactly as it did before this change.
#[tokio::test]
async fn authz_24_successful_run_omits_step_errors() {
    let (registry, _calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let value = run_playbook_yaml(
        &meta,
        r"
name: clean
description: nothing fails
on_error: abort
steps:
  - name: read
    server: alpha
    tool: read
",
        &ctx(&AllowAll),
    )
    .await
    .expect("a clean run must succeed");

    assert!(
        value.get("step_errors").is_none(),
        "a run that denies nothing must produce the JSON it produced before \
         this field existed: {value}"
    );
}
