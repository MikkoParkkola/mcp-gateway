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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
        signing: None,
        execution: None,
        credential_principal: None,
        is_modern: false,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer,
        api_key_name: Some("test-caller"),
        agent_id: None,
        grant_subject: None,
        verified_identity: None,
        is_admin: false,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        task: None,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
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

/// Outer envelope a client sends: `tools/call` / `gateway_invoke` with the
/// nonce on `params.arguments`, the same shape `handlers.rs` captures.
fn captured_external_gateway_invoke(
    nonce: &str,
) -> (super::signing::SigningInvocationContext, Value) {
    let mut request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {
                "server": "alpha",
                "tool": "read",
                "arguments": {},
                "nonce": nonce,
            }
        }
    });
    let context = super::signing::SigningInvocationContext::capture(&mut request);
    let arguments = request
        .pointer("/params/arguments")
        .expect("arguments survive capture")
        .clone();
    (context, arguments)
}

/// AUTHZ.20 — a refused call consumes no nonce.
///
/// Replay admission is `prepare_signing_invocation` (`signing.rs:169`), which
/// registers the nonce only after policy, and only for a captured external
/// `gateway_invoke`. `invoke_tool` with `caller.signing = None` never reaches
/// the store, so a third call would succeed and this case would pass for the
/// wrong reason. Each step captures from a raw envelope the way the adapters
/// do.
#[tokio::test]
async fn authz_20_refused_call_consumes_no_nonce() {
    const NONCE: &str = "nonce-used-once";

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

    let (mut denied_signing, denied_args) = captured_external_gateway_invoke(NONCE);
    let refused =
        meta.prepare_signing_invocation(&mut denied_signing, &denied_args, None, &ctx(&DenyAll));
    assert!(refused.is_err(), "the call must be refused");

    // The same nonce must still be usable: the refusal happened before it was
    // registered. A new capture is a new request carrying that nonce, which
    // is how a retry arrives on the wire.
    let (mut allowed_signing, allowed_args) = captured_external_gateway_invoke(NONCE);
    meta.prepare_signing_invocation(&mut allowed_signing, &allowed_args, None, &ctx(&AllowAll))
        .expect("a refused call must not burn the nonce");
    let mut allowed_caller = ctx(&AllowAll);
    allowed_caller.signing = Some(&allowed_signing);
    let allowed = meta.invoke_tool(&allowed_args, None, &allowed_caller).await;
    assert!(
        allowed.is_ok(),
        "a refused call must not burn the nonce — the honest retry is being \
         rejected as a replay: {allowed:?}"
    );

    // And the nonce IS a real one: replaying it now must fail at admission.
    let (mut replay_signing, replay_args) = captured_external_gateway_invoke(NONCE);
    let replayed =
        meta.prepare_signing_invocation(&mut replay_signing, &replay_args, None, &ctx(&AllowAll));
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

    let response = Box::pin(meta.handle_tools_call(
        crate::protocol::RequestId::Number(1),
        "surfaced_read",
        json!({}),
        None,
        ctx(&DenyAll),
    ))
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

    let response = Box::pin(meta.handle_tools_call(
        crate::protocol::RequestId::Number(1),
        "surfaced_read",
        json!({}),
        None,
        ctx(&AllowAll),
    ))
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

// ===========================================================================
// CACHE.4b — policy epoch at the grant-store writer (4.f.1) and the
// in-flight bump between read-key and write-key (4.g).
//
// Plan: docs/design/2026-09-06-cache4-policy-epoch-test-plan.md.
// The caller stays AUTHORIZED across the grant mutation: a revocation is
// decided above the cache, so a denying swap would go green without an
// epoch anywhere. The observable is the backend call counter, never body
// text (the counted backend returns a constant).
// ===========================================================================

fn still_authorized_grants() -> crate::identity_grants::LocalIdentityGrantStore {
    use crate::identity_grants::{
        GrantAgent, GrantScope, GrantSubject, IdentityGrant, LocalIdentityGrantStore,
    };
    let subject = GrantSubject::new("test-authority", "user-still-allowed", None);
    LocalIdentityGrantStore::from_grants([IdentityGrant {
        grant_id: "grant-still-authorized".to_string(),
        subject,
        agent: GrantAgent::Any,
        capability: "unrelated".to_string(),
        tool: None,
        scope: GrantScope::Execute,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "cache-4b-test".to_string(),
        reason: "adds a permission; does not revoke the caller".to_string(),
    }])
}

/// CACHE.4b / 4.f.1 — a grant-store mutation that leaves the caller
/// authorized must strand the prior cache entry. The swapped store adds a
/// permission; it does not revoke. Dispatch after the swap is the
/// falsifier; an error is the wrong green.
#[tokio::test]
async fn authz_cache_4b_a_grant_change_strands_the_prior_entry() {
    let (registry, calls) = counted_backend("alpha");
    let cache = Arc::new(crate::cache::ResponseCache::new());
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::clone(&cache)),
        None,
        None,
        Duration::from_secs(300),
    );

    let primed = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(primed.is_ok(), "priming call must succeed: {primed:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the backend was called once"
    );

    let hit = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(hit.is_ok(), "hit control must succeed: {hit:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the cache must be live — if this dispatches, the miss half below \
         proves nothing"
    );

    meta.set_identity_grants(still_authorized_grants());

    assert_eq!(
        cache.stats().size,
        1,
        "stranding leaves the prior entry in the map; ResponseCache::clear() \
         would drop it, which is the racy alternative this change refuses"
    );

    let after = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(
        after.is_ok(),
        "the swapped grants must leave the caller authorized, not fail the \
         invoke: {after:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a post-bump invoke under still-authorized grants must miss and \
         dispatch; a hit here means the epoch was not mixed into the key"
    );
}

/// Transport that advances the handler's policy epoch once, on its first
/// backend call — the one interleave a test can drive through the production
/// path, sitting between the read-side key and the write-side key.
struct EpochBumpingTransport {
    calls: Arc<AtomicUsize>,
    epoch: Arc<AtomicU64>,
    bumped: AtomicBool,
    result: Value,
}

#[async_trait::async_trait]
impl Transport for EpochBumpingTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        assert_eq!(method, "tools/call");
        if !self.bumped.swap(true, Ordering::SeqCst) {
            self.epoch.fetch_add(1, Ordering::Release);
        }
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

/// CACHE.4b / 4.g — read and write keys share the pre-dispatch epoch.
///
/// Three invokes, no priming: a primed entry is hit before the bump fires.
/// Invoke 1 dispatches and bumps mid-call; invoke 2 must dispatch because
/// the first write landed under the pre-bump epoch; invoke 3 must hit
/// (count stays 2), or the first two only proved the backend ran twice.
#[tokio::test]
async fn authz_cache_4b_read_and_write_keys_share_the_pre_dispatch_epoch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let _ = registry.register(Arc::clone(&backend));
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    backend.set_transport_for_test(Arc::new(EpochBumpingTransport {
        calls: Arc::clone(&calls),
        epoch: Arc::clone(&meta.policy_epoch),
        bumped: AtomicBool::new(false),
        result: json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
    }));

    let first = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(first.is_ok(), "first invoke must dispatch: {first:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the backend was called once"
    );

    let second = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(second.is_ok(), "second invoke must succeed: {second:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the first write must have landed under the pre-bump epoch, so a \
         post-bump reader cannot retrieve it — re-reading the epoch at the \
         write site would serve this call from cache"
    );

    let third = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(third.is_ok(), "third invoke must succeed: {third:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a third call under the still-bumped epoch must hit; without this, \
         an implementation that writes nothing dispatches twice and passes"
    );
}

/// CACHE.4e production plumbing — two classified revisions do not share an
/// entry. Hit control: the first revision's second call stays at 1.
#[tokio::test]
async fn authz_cache_4e_two_revisions_do_not_share_an_entry() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    let mut first = ctx(&AllowAll);
    first.protocol_revision = Some("2025-03-26");
    let mut second = ctx(&AllowAll);
    second.protocol_revision = Some("2025-06-18");

    meta.invoke_tool(&invoke_args("alpha", "read"), None, &first)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &first)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "hit control: the first revision must be cached"
    );
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &second)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a second classified revision must miss"
    );
}

/// Unknown revision skips the response cache only. A later known-revision
/// call still hits the entry primed under that revision.
#[tokio::test]
async fn authz_cache_4e_unknown_revision_skips_cache_not_all_caching() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    let known = ctx(&AllowAll);
    let mut unknown = ctx(&AllowAll);
    unknown.protocol_revision = None;

    meta.invoke_tool(&invoke_args("alpha", "read"), None, &known)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &unknown)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "unknown revision must not read the known entry"
    );
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &known)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the known entry must still be live after an unknown-revision miss"
    );
}

/// CACHE.4b / 4.f.2 — `LiveConfig::set` bumps the shared epoch so a subsequent
/// invoke misses. Hit control before the set.
#[tokio::test]
async fn authz_cache_4b_live_config_set_strands_the_prior_entry() {
    let (registry, calls) = counted_backend("alpha");
    let cache = Arc::new(crate::cache::ResponseCache::new());
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::clone(&cache)),
        None,
        None,
        Duration::from_secs(300),
    );
    let live = crate::config_reload::LiveConfig::new(crate::config::Config::default())
        .with_policy_epoch(Arc::clone(&meta.policy_epoch));

    meta.invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await
        .unwrap();
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "hit control");

    live.set(crate::config::Config::default());
    assert_eq!(cache.stats().size, 1, "set strands, it does not clear");

    meta.invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a post-set invoke must miss"
    );
}

/// CACHE.4 outer — the shipped default (no identity propagation, no OIDC) must
/// still isolate two callers. Their only principal is the `GrantSubject` the
/// router derives from trusted headers / mTLS / an OAuth agent, so a key that
/// ignored it served one caller's body to the other. Hit control first: the
/// same principal twice must stay at one dispatch, or a miss below would be
/// explained equally well by a cache that never stores.
#[tokio::test]
async fn authz_cache_4_two_grant_subjects_do_not_share_an_outer_entry() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    let subject = |name: &'static str| {
        Some(crate::identity_grants::GrantSubject::new(
            "cloudflare_access",
            name,
            None,
        ))
    };
    let alice = MetaMcpCallerContext {
        grant_subject: subject("alice"),
        ..ctx(&AllowAll)
    };
    let alice_again = MetaMcpCallerContext {
        grant_subject: subject("alice"),
        ..ctx(&AllowAll)
    };
    let bob = MetaMcpCallerContext {
        grant_subject: subject("bob"),
        ..ctx(&AllowAll)
    };

    meta.invoke_tool(&invoke_args("alpha", "read"), None, &alice)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "alice primes the cache");
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &alice_again)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "hit control: the same principal must be served from cache"
    );
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &bob)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a second principal must not be served alice's body"
    );
}

/// A revision spelling the gateway never served names no bucket at all: it is
/// not trimmed onto the canonical one, and it gets no bucket of its own.
#[tokio::test]
async fn authz_cache_4e_whitespace_padded_revision_is_not_a_bucket() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    let known = ctx(&AllowAll);
    let mut padded = ctx(&AllowAll);
    padded.protocol_revision = Some(" 2025-11-25 ");

    meta.invoke_tool(&invoke_args("alpha", "read"), None, &known)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &known)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "hit control");
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &padded)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a padded spelling must not read the canonical entry"
    );
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &padded)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "and must not have stored a bucket of its own"
    );
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &known)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "the canonical entry must still be live"
    );
}

/// A verified OIDC identity distinguished only by its subject.
fn verified(subject: &str) -> crate::key_server::oidc::VerifiedIdentity {
    crate::key_server::oidc::VerifiedIdentity {
        subject: subject.to_string(),
        email: format!("{subject}@example.test"),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.example.test".to_string(),
    }
}

/// MIK-7408, production path. The helper-level forgery tests pin how the
/// retry key is COMPOSED; none of them pins that `invoke_tool` still hands the
/// identity to the composer. A wiring regression there is invisible to all of
/// them and visible here.
///
/// Two verified callers, one shared client key, identity propagation OFF —
/// `cache_binding` is `None`, which is the shipped default and the exact
/// configuration under which the suffix used to be empty for everyone.
#[tokio::test]
async fn a_second_verified_caller_is_not_served_the_firsts_idempotent_result() {
    let (registry, calls) = counted_backend("alpha");
    let mut meta = MetaMcp::new(registry);
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );

    let retry = crate::protocol::mrtr::RetryFields {
        input_responses: None,
        request_state: None,
        idempotency_key: Some("one-key-both-callers".to_string()),
        malformed: Vec::new(),
    };
    let alice = verified("alice");
    let bob = verified("bob");
    let args = invoke_args("alpha", "read");

    let first = meta
        .invoke_tool(
            &args,
            None,
            &MetaMcpCallerContext {
                verified_identity: Some(&alice),
                retry: &retry,
                ..ctx(&AllowAll)
            },
        )
        .await;
    assert!(first.is_ok(), "the first call must succeed: {first:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "and must reach the backend"
    );

    let second = meta
        .invoke_tool(
            &args,
            None,
            &MetaMcpCallerContext {
                verified_identity: Some(&bob),
                retry: &retry,
                ..ctx(&AllowAll)
            },
        )
        .await;
    assert!(second.is_ok(), "the second call must succeed: {second:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "bob was served alice's stored result — the verified identity is not \
         reaching the retry key on the production path"
    );

    // And the key IS live, so the assertion above cannot have passed because
    // idempotency was inert: alice repeating her own call is de-duplicated.
    let repeat = meta
        .invoke_tool(
            &args,
            None,
            &MetaMcpCallerContext {
                verified_identity: Some(&alice),
                retry: &retry,
                ..ctx(&AllowAll)
            },
        )
        .await;
    assert!(repeat.is_ok(), "alice's repeat must succeed: {repeat:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "alice's own repeat reached the backend a second time — idempotency is \
         inert here, and the caller-separation assertion above proved nothing"
    );
}
