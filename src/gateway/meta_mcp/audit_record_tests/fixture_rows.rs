// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision fixture table, meta-route refusal rows: one concrete call per
//! decider site, each pinning its whole decision with `assert_row`.
//!
//! What every refusal row pins, read at 01aa22f2cc:
//! - `rule_id` absent: each site below notes its kind with `None`.
//! - `grant_id` absent: the decision constructor sets `grant_id: None`
//!   (`decision_record.rs:304`) and nothing writes it; flipped when a writer of
//!   the decision's grant id lands.
//! - findings `NotRun`: no production writer of `request_findings` yet;
//!   flipped when the request-findings writer lands.
//! - no effect: an effect is noted only after admission.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::{Scripted, api_key_caller, context, ok_result, records};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::visible::memo::with_visibility_memo;
use crate::security::decision_fixture_table::{DecisionRow, Findings, RuleId, assert_row};
use crate::security::transparency_log::TransparencyLogConfig;

/// `Scripted` that counts the `tools/call`s it answers.
struct Counted(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl crate::transport::Transport for Counted {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/call" {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        Scripted(Ok(ok_result())).request(method, params).await
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

/// One table gateway: backend `alpha` under `config`, logging to `dir`, and
/// the count of calls `alpha` was sent.
fn table_meta(dir: &tempfile::TempDir, config: BackendConfig) -> (MetaMcp, Arc<AtomicUsize>) {
    let sent = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Counted(Arc::clone(&sent))));
    let _ = registry.register(backend);
    let logger = crate::security::TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir
            .path()
            .join("audit.jsonl")
            .to_string_lossy()
            .into_owned(),
        key_id: "d1".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    let mut meta = MetaMcp::new(registry);
    meta.enable_transparency_log(Arc::new(logger));
    (meta, sent)
}

/// How a refused call is answered to its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// A tool result with `isError: true`.
    IsErrorResult,
    /// A JSON-RPC error.
    RpcError,
}

/// What a refusal row expects of the call's record and answer, each value
/// read from the source line its row cites.
#[derive(Debug, Clone, Copy)]
struct Refusal {
    form: Form,
    /// The record's `outcome`.
    outcome: &'static str,
    /// The record's `error_code`; `None` requires the key absent.
    code: Option<i64>,
}

/// `server`'s `read`, invoked by an API-key caller inside one request memo,
/// refused as `want` says: its answer's form and its record's outcome and
/// code. Returns the call's one decision.
async fn refused(meta: &MetaMcp, dir: &tempfile::TempDir, server: &str, want: Refusal) -> Value {
    let who = api_key_caller();
    let args = json!({"server": server, "tool": "read", "arguments": {}});
    let answer =
        with_visibility_memo(meta.invoke_tool(&args, None, &context(&AllowAll, &who))).await;
    let (form, answer) = match answer {
        Ok(result) => {
            assert_eq!(
                result["isError"], true,
                "premise: the call is refused: {result}"
            );
            (Form::IsErrorResult, result.to_string())
        }
        Err(error) => (Form::RpcError, format!("{error:?}")),
    };
    assert_eq!(form, want.form, "the answer's form: {answer}");
    let all = records(dir);
    let [record] = all.as_slice() else {
        panic!("premise: one invocation record: {all:?}; answer {answer}");
    };
    assert_eq!(record["outcome"], want.outcome, "{answer}: {record}");
    assert_eq!(
        record.get("error_code").and_then(Value::as_i64),
        want.code,
        "{answer}: {record}"
    );
    if want.code.is_none() {
        assert!(record.get("error_code").is_none(), "{answer}: {record}");
    }
    record["decision"].clone()
}

/// A refusal row: `kind` at a kind-only site, nothing else recorded.
const fn refusal(name: &'static str, kind: &'static str) -> DecisionRow {
    DecisionRow {
        name,
        kind,
        rule_id: RuleId::Absent("kind-only site: noted with no rule id"),
        grant_id: None,
        findings: Findings::NotRun,
        effect: None,
        decided: "fresh",
    }
}

/// T1: the backend's `allowed_tools` leaves `read` out (`visible.rs:46`,
/// `Withholding::Unselected`, via `descriptor_gate.rs:305`).
#[tokio::test]
async fn t1_meta_allowed_tools() {
    let dir = tempfile::tempdir().expect("a log directory");
    let config = BackendConfig {
        allowed_tools: Some(vec!["write".to_string()]),
        ..BackendConfig::default()
    };
    let (meta, sent) = table_meta(&dir, config);
    // The gate answers a withheld tool as an absent one, an `isError` result
    // (`gate.rs:296`); a tool result reads as `tool_error`, with no code
    // (`audit.rs:68-70`).
    let withheld = Refusal {
        form: Form::IsErrorResult,
        outcome: "tool_error",
        code: None,
    };
    let decision = refused(&meta, &dir, "alpha", withheld).await;
    assert_eq!(
        sent.load(Ordering::SeqCst),
        0,
        "the backend was sent the call"
    );
    assert_row(
        &decision,
        &refusal("t1_meta_allowed_tools", "allowed_tools"),
    );
}

/// C1: a disabled capability (`dispatch_guards.rs:319`, in `admit_target`).
#[tokio::test]
async fn c1_meta_capability_disabled() {
    let dir = tempfile::tempdir().expect("a log directory");
    let (meta, sent) = table_meta(&dir, BackendConfig::default());
    let budget = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    for _ in 0..20 {
        meta.kill_switch
            .record_capability_failure("alpha", "read", &budget);
    }
    assert!(
        meta.kill_switch.is_capability_disabled("alpha", "read"),
        "premise: the capability is disabled"
    );
    // `Error::gateway_refused(-32000, ..)` (`dispatch_guards.rs:308`), an
    // error that reads as `error` with its own code (`audit.rs:94`).
    let disabled = Refusal {
        form: Form::RpcError,
        outcome: "error",
        code: Some(-32000),
    };
    let decision = refused(&meta, &dir, "alpha", disabled).await;
    assert_eq!(
        sent.load(Ordering::SeqCst),
        0,
        "the backend was sent the call"
    );
    assert_row(
        &decision,
        &refusal("c1_meta_capability_disabled", "capability_disabled"),
    );
}

/// The gateway's default routing profile leaves `read` out.
fn without_read(meta: MetaMcp) -> MetaMcp {
    use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
    let profiles = std::collections::HashMap::from([(
        "restricted".to_string(),
        RoutingProfileConfig {
            deny_tools: Some(vec!["read".to_string()]),
            ..RoutingProfileConfig::default()
        },
    )]);
    meta.with_profile_registry(ProfileRegistry::from_config(&profiles, "restricted"))
}

/// P2: the session's routing profile leaves the tool out, judged at the
/// gate's invoke-scope check (`visibility.rs:118`, reached through
/// `may_invoke_explained`, `gate.rs:660`; confirmed by the site probe).
#[tokio::test]
async fn p2_meta_routing_profile_in_scope() {
    let dir = tempfile::tempdir().expect("a log directory");
    let (meta, sent) = table_meta(&dir, BackendConfig::default());
    let meta = without_read(meta);
    // The gate notes the profile refusal's own code, `Error::Protocol`'s
    // -32600 (`gate.rs:665`), which the record keeps as `denied`
    // (`denial.rs:45-47`); the caller is answered as for an absent tool.
    let profiled = Refusal {
        form: Form::IsErrorResult,
        outcome: "denied",
        code: Some(-32600),
    };
    let decision = refused(&meta, &dir, "alpha", profiled).await;
    assert_eq!(
        sent.load(Ordering::SeqCst),
        0,
        "the backend was sent the call"
    );
    assert_row(
        &decision,
        &refusal("p2_meta_routing_profile_in_scope", "routing_profile"),
    );
}

/// N2: an unscoped caller names a server that matches nothing; the gate
/// marks the name absent and the dispatch's miss notes `not_found`
/// (`denial.rs:21`; confirmed by the site probe).
#[tokio::test]
async fn n2_meta_not_found_at_dispatch() {
    let dir = tempfile::tempdir().expect("a log directory");
    let (meta, sent) = table_meta(&dir, BackendConfig::default());
    // The miss is answered as an `isError` result with a recovery hint
    // (`errors.rs:54-66`); its record is `denied` with the miss's -32001
    // (`denial.rs:45-47`).
    let missed = Refusal {
        form: Form::IsErrorResult,
        outcome: "denied",
        code: Some(-32001),
    };
    let decision = refused(&meta, &dir, "nowhere", missed).await;
    assert_eq!(
        sent.load(Ordering::SeqCst),
        0,
        "a backend was sent the call"
    );
    let row = DecisionRow {
        rule_id: RuleId::Absent("the target matches nothing"),
        ..refusal("n2_meta_not_found_at_dispatch", "not_found")
    };
    assert_row(&decision, &row);
}

/// P4: the routing profile at admission (`dispatch_guards.rs:204` in
/// `admit_named_target_explained`). Over HTTP the preflight and the
/// invoke-scope check run the same profile first, so admission refuses only
/// when the profile changes after them (a reload: `admit_after_credential`,
/// `dispatch_guards.rs:242`). This unit row calls admission directly with a
/// profile that excludes the tool, as if it had changed after preflight, and
/// builds the decision the route would from the notes admission left.
#[tokio::test]
async fn p4_admission_routing_profile() {
    use crate::gateway::meta_mcp::invoke::audit::with_dispatch_scope;
    use crate::gateway::meta_mcp::invoke::dispatch_guards::BackendCall;
    let dir = tempfile::tempdir().expect("a log directory");
    let (meta, sent) = table_meta(&dir, BackendConfig::default());
    let meta = without_read(meta);
    let call = BackendCall {
        server: "alpha",
        tool: "read",
        session_id: None,
        api_key_name: None,
        cost_key: None,
        trace_id: "",
        caller_key: None,
        generation: None,
    };
    let (admitted, notes) = with_dispatch_scope(async { meta.admit_target(&call) }).await;
    // The profile's refusal is `Error::Protocol` (`accessors.rs:129-131`),
    // whose code is -32600.
    let error = admitted.expect_err("premise: admission refuses the tool");
    assert!(matches!(error, crate::Error::Protocol(_)), "{error:?}");
    assert_eq!(error.to_rpc_code(), -32600, "{error:?}");
    assert_eq!(
        sent.load(Ordering::SeqCst),
        0,
        "the backend was sent the call"
    );
    let outcome = crate::security::audit::AuditOutcome::from_result(&Err(error))
        .expect("an outcome for a refusal");
    let decision =
        serde_json::to_value(notes.decided(&meta, outcome)).expect("a decision serialises");
    assert_row(
        &decision,
        &refusal("p4_admission_routing_profile", "routing_profile"),
    );
}
