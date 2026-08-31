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
use crate::gateway::authz::{AllowAll, CountingAuthorizer, DenyAll, DenyOne, ToolAuthorizer};
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
fn ctx(authorizer: &(dyn ToolAuthorizer + Sync)) -> MetaMcpCallerContext<'_> {
    MetaMcpCallerContext {
        authorizer,
        api_key_name: Some("test-caller"),
        agent_id: None,
        grant_subject: None,
        verified_identity: None,
        is_admin: false,
        input_capabilities: &[],
        retry: &crate::protocol::mrtr::NO_RETRY,
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

    let err = result.expect_err("a denied chain step must be refused");
    assert!(
        matches!(err, crate::Error::Forbidden { .. }),
        "a chain must report a denial AS a denial, not flatten it into an \
         internal error: {err:?}"
    );
    assert!(
        err.to_string().contains("refused"),
        "and must say which step: {err}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no backend call");
}

/// The allow counterpart. Without it, 13c and 13d pass vacuously if code-mode
/// dispatch never reaches a backend for some unrelated reason.
#[tokio::test]
async fn authz_13cd_code_mode_allowed_reaches_the_backend() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry).with_code_mode(true);

    let single = meta
        .code_mode_execute(
            &json!({ "tool": "alpha:read", "arguments": {} }),
            None,
            &ctx(&AllowAll),
        )
        .await;
    assert!(
        single.is_ok(),
        "an allowed code-mode call must run: {single:?}"
    );

    let chain = meta
        .code_mode_execute(
            &json!({ "chain": [ { "tool": "alpha:read", "arguments": {} } ] }),
            None,
            &ctx(&AllowAll),
        )
        .await;
    assert!(chain.is_ok(), "an allowed chain must run: {chain:?}");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "both allowed shapes must actually reach the backend, or the two \
         refusals above prove nothing about authorization"
    );
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

/// Under `continue`, a denied step is recorded and the run carries on to a
/// step it IS allowed to take.
///
/// The authorizer is selective on purpose. `DenyAll` would deny the successor
/// too, so the case could show only that the run did not abort — never that a
/// permitted step afterwards actually executed, which is the whole promise of
/// `continue`. The backend counter is what proves it.
#[tokio::test]
async fn authz_18_continue_records_and_runs_the_permitted_successor() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let value = run_playbook_yaml(
        &meta,
        r"
name: continuing
description: a denied step, then one the caller is allowed to take
on_error: continue
steps:
  - name: denied
    server: alpha
    tool: blocked
  - name: allowed
    server: alpha
    tool: read
",
        &ctx(&DenyOne { tool: "blocked" }),
    )
    .await
    .expect("continue must not abort the run");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the permitted successor must actually have run — without this the \
         case shows only that the run did not abort"
    );

    let failed = value
        .get("steps_failed")
        .and_then(Value::as_array)
        .expect("steps_failed must be present");
    assert_eq!(failed.len(), 1, "only the denied step failed: {value}");
    assert!(
        failed.iter().any(|s| s == "denied"),
        "and it is the one that was denied: {value}"
    );

    let completed = value
        .get("steps_completed")
        .and_then(Value::as_array)
        .expect("steps_completed must be present");
    assert!(
        completed.iter().any(|s| s == "allowed"),
        "the successor must be recorded as completed: {value}"
    );

    let errors = value.get("step_errors").expect("reasons must be recorded");
    assert!(
        errors.get("denied").is_some(),
        "a partial run must explain itself, or it reads as a success: {errors}"
    );
    assert!(
        errors.get("allowed").is_none(),
        "and must not blame a step that succeeded: {errors}"
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

/// AUTHZ.19 — under `abort`, the run returns the denial's own code, and no
/// later step runs.
///
/// Asserting only "the run aborted" would pass for any error; the code is what
/// pins it to a refusal.
#[tokio::test]
async fn authz_19_abort_returns_the_denial_itself() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);

    let result = run_playbook_yaml(
        &meta,
        r"
name: aborting
description: a denied step followed by one that must not run
on_error: abort
steps:
  - name: denied
    server: alpha
    tool: read
  - name: never_runs
    server: alpha
    tool: write
",
        &ctx(&DenyAll),
    )
    .await;

    let err = result.expect_err("abort must surface the failure");
    assert!(
        matches!(err, crate::Error::Forbidden { .. }),
        "the run must return the denial, not a generic failure: {err:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "neither the denied step nor the one after it may dispatch"
    );
}

/// AUTHZ.18a — an ordinary failure is explained too, not only a refusal.
///
/// A fix that recorded refusals alone would leave a `continue` caller with an
/// unexplained null for every other kind of failure, which is the defect
/// `step_errors` exists to close.
#[tokio::test]
async fn authz_18a_ordinary_failure_is_also_recorded() {
    let registry = Arc::new(BackendRegistry::new());
    let meta = MetaMcp::new(registry);

    let value = run_playbook_yaml(
        &meta,
        r"
name: continuing_ordinary
description: an ordinary failure under continue
on_error: continue
steps:
  - name: bad
    server: alpha
    tool: 'bad/name'
",
        &ctx(&AllowAll),
    )
    .await
    .expect("continue must not abort the run");

    let errors = value
        .get("step_errors")
        .expect("an ordinary failure must be explained");
    assert!(
        errors.get("bad").is_some(),
        "and recorded under the step's own name: {errors}"
    );
}

/// AUTHZ.6 / 6a — a step skipped by its condition is never authorized.
///
/// The counting authorizer carries both halves: zero consultations for the
/// skipped step AND exactly one for the step that runs. A zero on its own is
/// satisfied by an authorizer that is never called at all.
#[tokio::test]
async fn authz_6a_skipped_step_is_never_authorized() {
    let (registry, _calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let counting = CountingAuthorizer::new(AllowAll);

    let value = run_playbook_yaml(
        &meta,
        r"
name: conditional
description: one skipped step and one that runs
on_error: continue
steps:
  - name: skipped
    server: forbidden_backend
    tool: never
    condition: 'false'
  - name: runs
    server: alpha
    tool: read
",
        &ctx(&counting),
    )
    .await
    .expect("the run must complete");

    assert_eq!(
        counting.count_for("forbidden_backend", "never"),
        0,
        "a step whose condition excluded it must never be authorized — \
         refusing a playbook for a step that would not have run is a \
         regression invented by the fix"
    );
    assert_eq!(
        counting.count_for("alpha", "read"),
        1,
        "and the step that does run must be authorized exactly once"
    );

    let skipped = value
        .get("steps_skipped")
        .and_then(Value::as_array)
        .expect("steps_skipped must be present");
    assert!(
        skipped.iter().any(|s| s == "skipped"),
        "the step must actually have been skipped, not merely absent: {value}"
    );
}

// ===========================================================================
// AUTHZ.7 / 12 / 20 — nothing happens before the check.
//
// These were previously justified by reading: the check sits at the top of
// `invoke_tool_traced`, above the nonce store, the cache and the budget. That
// proves PLACEMENT, not behaviour. A client `gateway_invoke` is the shape that
// can prove behaviour, because it carries no `_full` — that directive is
// injected only by `internal_invoke_args`, and it skips the cache and
// idempotency entirely, so a playbook step could never exercise them.
// ===========================================================================

/// AUTHZ.12 — a refused caller is not served a cached result.
///
/// The scenario the design calls authoritative: the router allowed a call,
/// policy changed, and the chokepoint must refuse before the cache is read.
#[tokio::test]
async fn authz_12_refused_caller_is_not_served_a_cached_result() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );

    // Prime the cache as a permitted caller.
    let primed = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(primed.is_ok(), "priming call must succeed: {primed:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the backend was called once"
    );

    // AUTHZ.12a — the cache is real and reachable, so the refusal below is not
    // just an empty cache.
    let hit = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(hit.is_ok(), "a second permitted call must succeed");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "and must be served from cache — if it reaches the backend again the \
         cache is not primed and AUTHZ.12 proves nothing"
    );

    // Now refuse the same target.
    let refused = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&DenyAll))
        .await;
    let refusal = refused.expect_err("a refused caller must not be served the cached payload");
    assert!(
        matches!(refusal, crate::Error::Forbidden { .. }),
        "and must be refused AS a denial, not fail for some other reason: {refusal:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "and must not dispatch either"
    );
}

/// AUTHZ.20 — a refused call consumes no nonce.
///
/// The nonce store is consulted at `invoke.rs:634`, below the chokepoint. If
/// the order were reversed, a refused call would burn the caller's nonce and
/// the legitimate retry below would be rejected as a replay — a refusal
/// causing a denial of service on the next honest request.
#[tokio::test]
async fn authz_20_refused_call_consumes_no_nonce() {
    let (registry, _calls) = counted_backend("alpha");
    let mut meta = MetaMcp::new(registry);
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            b"a-test-secret-of-sufficient-length".to_vec(),
            None,
            "test-key".to_string(),
        ),
        Duration::from_secs(300),
        false,
    );

    let mut args = invoke_args("alpha", "read");
    args["nonce"] = json!("nonce-used-once");

    let refused = meta.invoke_tool(&args, None, &ctx(&DenyAll)).await;
    assert!(refused.is_err(), "the call must be refused");

    // The same nonce must still be usable: the refusal happened before it was
    // registered.
    let allowed = meta.invoke_tool(&args, None, &ctx(&AllowAll)).await;
    assert!(
        allowed.is_ok(),
        "a refused call must not burn the nonce — the honest retry is being \
         rejected as a replay: {allowed:?}"
    );

    // And the nonce IS a real one: replaying it now must fail.
    let replayed = meta.invoke_tool(&args, None, &ctx(&AllowAll)).await;
    let replay_error = replayed.expect_err("a replayed nonce must be rejected");
    assert!(
        replay_error.to_string().to_lowercase().contains("nonce")
            || replay_error.to_string().to_lowercase().contains("replay"),
        "and rejected AS a replay — any other error would mean the nonce store \
         is not live and the assertion above passed for the wrong reason: \
         {replay_error}"
    );
}

/// AUTHZ.13a — a surfaced tool is refused when the authorizer denies.
///
/// The fifth dispatch shape, and the last one without a case. A surfaced tool
/// is dispatched by its bare name rather than through `gateway_invoke`, so it
/// takes a different branch at the top of `handle_tools_call` — covering the
/// other four proves nothing about this one.
#[tokio::test]
async fn authz_13a_surfaced_tool_denied() {
    let (registry, calls) = counted_backend("alpha");
    let meta =
        MetaMcp::new(registry).with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
            server: "alpha".to_string(),
            tool: "surfaced_read".to_string(),
        }]);

    let response = meta
        .handle_tools_call(
            crate::protocol::RequestId::Number(1),
            "surfaced_read",
            json!({}),
            None,
            ctx(&DenyAll),
        )
        .await;

    assert!(
        response.error.is_some(),
        "a denied surfaced tool must be refused: {response:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no backend call");
}

/// The allow counterpart, without which 13a passes if surfaced dispatch never
/// reaches a backend for some unrelated reason.
#[tokio::test]
async fn authz_13a_surfaced_tool_allowed_reaches_the_backend() {
    let (registry, calls) = counted_backend("alpha");
    let meta =
        MetaMcp::new(registry).with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
            server: "alpha".to_string(),
            tool: "surfaced_read".to_string(),
        }]);

    let response = meta
        .handle_tools_call(
            crate::protocol::RequestId::Number(1),
            "surfaced_read",
            json!({}),
            None,
            ctx(&AllowAll),
        )
        .await;

    assert!(
        response.error.is_none(),
        "an allowed surfaced tool must run: {response:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "and must actually reach the backend"
    );
}
