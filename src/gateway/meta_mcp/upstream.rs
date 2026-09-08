// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The native SEP-2663 upstream-task adapter: submission, recognition, query.
//!
//! Wire vocabulary is the pinned contract observed against fastmcp 4.0.3 /
//! fastmcp-tasks 4.0.3, not a draft:
//!
//! * a peer declares the extension in `server/discover` under
//!   `capabilities.extensions["io.modelcontextprotocol/tasks"]`;
//! * a `tools/call` runs as a task only when THAT request repeats the opt-in in
//!   `params._meta["io.modelcontextprotocol/clientCapabilities"].extensions` —
//!   written by the transport's own declaration, never by these params;
//! * the peer answers with a flat `{"resultType":"task","taskId":…}` envelope;
//! * `tasks/get` takes `{"taskId":…}` and the same opt-in, and answers
//!   `{"status":…, "result"|"error"|"inputRequests"}`.
//!
//! Per-tool `execution.taskSupport` is NOT observable at 2026-07-28 — the
//! revision removed the field and the SDK's serializer drops it — so no enum is
//! asserted here. Eligibility is configured trust plus the peer's own
//! declaration, and the ACTUAL reply shape decides whether a job became a task.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use serde_json::{Value, json};

use super::MetaMcp;
use crate::backend::{Backend, BackendRegistry};
use crate::gateway::task_service::{UpstreamAnswer, UpstreamHandle, UpstreamRecovery};
use crate::protocol::extensions::Extension;
use crate::protocol::{JsonRpcError, JsonRpcResponse};

/// Reverse-DNS identifier of the SEP-2663 tasks extension. Read from the one
/// enum that names it, so this adapter and the transport's declaration cannot
/// drift into two spellings.
pub(crate) const TASKS_EXTENSION: &str = Extension::Tasks.id();
/// The gateway's own namespace for recovery-read metadata. Explicit, and
/// documented beside the code that reads it: a fresh attestation token for a
/// recovery read travels at `_meta[RECOVERY_META].attestation` and nowhere else.
pub(crate) const RECOVERY_META: &str = "io.mcp-gateway/recovery";
/// Upper bound on one recovery query, before the backend's own timeout is
/// applied on top. Bounded so a read cannot hang on a silent peer.
pub(crate) const QUERY_DEADLINE: Duration = Duration::from_secs(10);

/// Recognise a genuine raw upstream `CreateTaskResult`.
///
/// Deliberately strict, and deliberately applied to the RAW backend reply
/// before anything shapes it: the gateway stamps `resultType: "task"` on its
/// OWN task envelope too, so a shape test alone would let a gateway-authored
/// envelope be mistaken for a peer's job — and vice versa. This value has not
/// passed through the invoke funnel, so nothing this gateway wrote is in it.
pub(crate) fn upstream_task_handle(result: &Value) -> Option<&str> {
    if result.get("resultType").and_then(Value::as_str) != Some("task") {
        return None;
    }
    let handle = result.get("taskId").and_then(Value::as_str)?;
    if handle.is_empty() {
        return None;
    }
    // A peer's task id is opaque and is NEVER parsed as a gateway `task-<uuid>`.
    // Only the presence of the fields the envelope is defined by is checked.
    result.get("status").and_then(Value::as_str)?;
    Some(handle)
}

/// One bounded `tasks/get` answer, mapped onto the executor's vocabulary.
fn read_query(response: JsonRpcResponse) -> UpstreamAnswer {
    if let Some(error) = response.error {
        // A refusal is not an outcome. `-32021` (the client did not declare the
        // extension) and `-32602` (unknown task) alike leave the record as it
        // is: neither says what the job did.
        tracing::warn!(code = error.code, "upstream tasks/get refused");
        return UpstreamAnswer::Unavailable;
    }
    let Some(result) = response.result else {
        return UpstreamAnswer::Unavailable;
    };
    match result.get("status").and_then(Value::as_str) {
        Some("completed") => result
            .get("result")
            .cloned()
            .map_or(UpstreamAnswer::Unavailable, UpstreamAnswer::Completed),
        Some("failed") => UpstreamAnswer::Failed(failed_error(result.get("error"))),
        Some("cancelled") => UpstreamAnswer::Failed(JsonRpcError {
            code: -32603,
            message: "the upstream task was cancelled".into(),
            data: None,
        }),
        // `working` and `input_required` alike: still live. The interrupted
        // input round keeps its reviewed I3 treatment and is not continued
        // here; this adapter has no continuation vocabulary and claims none.
        Some("working" | "input_required") => UpstreamAnswer::Live,
        _ => UpstreamAnswer::Unavailable,
    }
}

/// The peer's `error` payload, or a stated substitute when it sent none.
fn failed_error(error: Option<&Value>) -> JsonRpcError {
    let code = error
        .and_then(|error| error.get("code"))
        .and_then(Value::as_i64)
        .and_then(|code| i32::try_from(code).ok())
        .unwrap_or(-32603);
    let message = error
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("the upstream task failed without a message")
        .to_owned();
    JsonRpcError {
        code,
        message,
        data: error.and_then(|error| error.get("data").cloned()),
    }
}

/// The trusted, query-only adapter.
///
/// It holds a backend registry and a set of configured names, and its whole
/// vocabulary is one `tasks/get`. It cannot name a tool or arguments, so it
/// could not resubmit the original operation if it tried to.
pub(crate) struct NativeUpstreamTasks {
    backends: Arc<BackendRegistry>,
    /// Names from `tasks.recovery_adapters`. Read on every claim, so an
    /// operator's removal takes effect at the next read rather than the next
    /// restart of a caller's memory of it.
    trusted: HashSet<String>,
    /// Per-backend memo of the peer's own `server/discover` declaration.
    /// Negotiation is real: it is read from the peer, once per process, and a
    /// peer that does not declare the extension is never queried.
    declared: DashMap<String, bool>,
}

impl NativeUpstreamTasks {
    pub(crate) fn new(backends: Arc<BackendRegistry>, trusted: &[String]) -> Self {
        Self {
            backends,
            trusted: trusted.iter().cloned().collect(),
            declared: DashMap::new(),
        }
    }

    /// Whether `backend` is configured, trusted, reachable with the GATEWAY's
    /// own credential, and declared the extension.
    ///
    /// The credential clause is the stated prerequisite, not a hidden one: an
    /// identity-propagated or per-user-OAuth backend would need a per-user
    /// credential this process does not hold after a restart, so those rows
    /// take the conservative branch and no vault is proposed here.
    async fn eligible(&self, name: &str) -> Option<Arc<Backend>> {
        if !self.trusted.contains(name) {
            return None;
        }
        let backend = self.backends.get(name)?;
        if backend.identity_propagation_config().is_some()
            || backend.oauth_requires_per_user_isolation()
        {
            return None;
        }
        self.declares_tasks(&backend).await.then_some(backend)
    }

    /// One bounded `server/discover`, memoized per backend.
    async fn declares_tasks(&self, backend: &Arc<Backend>) -> bool {
        // Copied out of the map before anything awaits: a `DashMap` guard is
        // not `Send`, and this future has to be.
        let memoized = self.declared.get(&backend.name).map(|known| *known);
        if let Some(known) = memoized {
            return known;
        }
        let deadline = QUERY_DEADLINE.min(backend.request_timeout());
        let answer = tokio::time::timeout(
            deadline,
            backend.request_with_headers("server/discover", None, &[], None),
        )
        .await;
        // Silence, a transport failure and a JSON-RPC REFUSAL are all "the peer
        // said nothing", and none of them is memoized: a discovery this gateway
        // sent badly, or a peer that was briefly down, must not leave the
        // adapter permanently believing the extension is absent.
        let document = match answer {
            Ok(Ok(response)) if response.error.is_none() => response.result,
            Ok(Ok(_)) | Ok(Err(_)) | Err(_) => return false,
        };
        let declared = document.is_some_and(|document| {
            document
                .get("capabilities")
                .and_then(|capabilities| capabilities.get("extensions"))
                .and_then(|extensions| extensions.get(TASKS_EXTENSION))
                .is_some()
        });
        self.declared.insert(backend.name.clone(), declared);
        declared
    }
}

#[async_trait::async_trait]
impl UpstreamRecovery for NativeUpstreamTasks {
    async fn claims(&self, backend: &str) -> bool {
        self.eligible(backend).await.is_some()
    }

    async fn query(&self, handle: &UpstreamHandle, deadline: Duration) -> UpstreamAnswer {
        let Some(backend) = self.eligible(&handle.backend).await else {
            return UpstreamAnswer::Unavailable;
        };
        let deadline = deadline.min(backend.request_timeout());
        // The declaration is the transport's, and `tasks/get` is one of the two
        // methods it will carry it on. One attempt, no retry loop, no other
        // method, and nothing that writes upstream.
        match tokio::time::timeout(
            deadline,
            backend.request_with_task_capability(
                "tasks/get",
                Some(json!({ "taskId": handle.handle })),
                &[],
                None,
            ),
        )
        .await
        {
            Ok(Ok(response)) => read_query(response),
            Ok(Err(error)) => {
                tracing::warn!(backend = %handle.backend, %error, "upstream tasks/get unavailable");
                UpstreamAnswer::Unavailable
            }
            Err(_) => {
                tracing::warn!(backend = %handle.backend, "upstream tasks/get timed out");
                UpstreamAnswer::Unavailable
            }
        }
    }
}

/// The fresh attestation token a recovery read supplies, if it supplied one.
///
/// Namespaced under [`RECOVERY_META`] and read only here. This is a small,
/// explicit extension to recovery reads — the token is spent by the checker on
/// this request and is never persisted, and a missing or expired one denies
/// before any query rather than after.
pub(crate) fn recovery_attestation(params: Option<&Value>) -> Option<&str> {
    params?
        .get("_meta")?
        .get(RECOVERY_META)?
        .get("attestation")?
        .as_str()
}

/// The `gateway_invoke`-shaped argument value the original target is
/// re-authorized through, rebuilt from the persisted descriptor.
///
/// The same shape `check_invocation_policy` reads on a live dispatch, so the
/// recovery read faces the identical gate rather than a parallel one: current
/// `RouterAuthorizer`, current tool policy, current attestation and the active
/// profile. The token is this request's; nothing signed or spent is restored.
pub(crate) fn recovery_policy_args(
    backend: &str,
    tool: &str,
    arguments: &Value,
    attestation: Option<&str>,
) -> Value {
    let mut args = json!({
        "server": backend,
        "tool": tool,
        "arguments": arguments.clone(),
    });
    if let (Some(token), Some(object)) = (attestation, args.as_object_mut()) {
        object.insert("attestation".into(), json!(token));
    }
    args
}

/// The one place a raw upstream `CreateTask` envelope crosses from the dispatch
/// funnel to the task worker.
///
/// A task-local slot rather than a parameter or a caller-context field, for the
/// reason `gateway::trace::TRACE_ID` is one: the value belongs to exactly the
/// future the worker awaits, and threading it would change the signature of
/// every `MetaMcpCallerContext` construction and every dispatch entry point
/// this crate has. Scoped by [`with_upstream_submission`] and read only by the
/// backend leg of `accounted_dispatch`, on that same task.
///
/// It is armed for ONE `(server, tool)` and answers `false` to anything else,
/// so a nested dispatch to a different target cannot pick it up, and it keeps
/// only the FIRST handle it is offered.
pub(crate) struct UpstreamSubmission {
    server: String,
    tool: String,
    handle: parking_lot::Mutex<Option<String>>,
}

impl UpstreamSubmission {
    pub(crate) fn armed_for(server: &str, tool: &str) -> Self {
        Self {
            server: server.to_owned(),
            tool: tool.to_owned(),
            handle: parking_lot::Mutex::new(None),
        }
    }

    /// Whether this dispatch is the submission the slot was armed for.
    pub(crate) fn wants(&self, server: &str, tool: &str) -> bool {
        self.server == server && self.tool == tool
    }

    /// Offer the RAW backend reply. Stores the handle iff it is a genuine
    /// upstream task envelope and none has been stored yet.
    pub(crate) fn offer(&self, raw: &Value) {
        if let Some(handle) = upstream_task_handle(raw) {
            let mut slot = self.handle.lock();
            if slot.is_none() {
                *slot = Some(handle.to_owned());
            }
        }
    }

    /// The captured handle, if the peer really did start a task.
    pub(crate) fn handle(&self) -> Option<String> {
        self.handle.lock().clone()
    }
}

tokio::task_local! {
    /// The armed submission slot for the current dispatch, if any.
    static UPSTREAM_SUBMISSION: std::sync::Arc<UpstreamSubmission>;
}

/// Run `future` with `submission` armed for this task and nothing else.
pub(crate) async fn with_upstream_submission<F: std::future::Future>(
    submission: std::sync::Arc<UpstreamSubmission>,
    future: F,
) -> F::Output {
    UPSTREAM_SUBMISSION.scope(submission, future).await
}

/// The armed slot for THIS dispatch of `(server, tool)`, or `None`.
///
/// `None` outside a scope, and `None` for any target the slot was not armed
/// for: an ordinary synchronous call can never take the task-augmented leg.
pub(crate) fn armed_submission(
    server: &str,
    tool: &str,
) -> Option<std::sync::Arc<UpstreamSubmission>> {
    UPSTREAM_SUBMISSION
        .try_with(std::sync::Arc::clone)
        .ok()
        .filter(|submission| submission.wants(server, tool))
}

/// The one direct backend job an upstream handle can honestly describe.
///
/// Selection semantics, stated rather than implied. Supported:
///
/// * `gateway_invoke`, whose `{server, tool, arguments}` names exactly one
///   backend call;
/// * a statically surfaced tool, which is that same single call under another
///   name.
///
/// Unsupported, and taking the unchanged conservative branch: `gateway_execute`
/// and `gateway_run_playbook`. Those run a program — several calls, branches,
/// gateway-side state between steps — and one upstream handle describes at most
/// one of their steps. Presenting such a job as recoverable would claim that
/// re-reading one peer's task told us what the whole playbook did.
pub(crate) struct DirectJob {
    pub server: String,
    pub tool: String,
    pub arguments: Value,
}

impl MetaMcp {
    /// Resolve the outer call to a single direct backend job, or `None`.
    pub(crate) fn direct_job(&self, tool_name: &str, arguments: &Value) -> Option<DirectJob> {
        if tool_name == "gateway_invoke" {
            return Some(DirectJob {
                server: arguments.get("server")?.as_str()?.to_owned(),
                tool: arguments.get("tool")?.as_str()?.to_owned(),
                // `{}` and not `null`: the router's own target builder defaults a
                // missing inner `arguments` to an empty object, and two gates
                // that see different targets are two gates that can disagree.
                arguments: arguments
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
            });
        }
        // A multi-step meta-tool is deliberately absent from this match.
        Some(DirectJob {
            server: self.surfaced_tool_server(tool_name)?.to_owned(),
            tool: tool_name.to_owned(),
            arguments: arguments.clone(),
        })
    }

    /// The ordinary post-dispatch processing for a result that arrived late.
    ///
    /// The identical output-schema enforcement and response gates a live
    /// dispatch applies, in the same order and from the same implementations.
    /// The dispatch half is unreachable from here: this takes a result, never
    /// arguments, so recovering an answer cannot cause a call.
    ///
    /// # Errors
    ///
    /// Returns the gate's own refusal when a configured output policy blocks or
    /// rewrites the recovered payload into a denial.
    pub(crate) fn recover_task_result(
        &self,
        server: &str,
        tool: &str,
        api_key_name: Option<&str>,
        trace_id: &str,
        result: Value,
    ) -> crate::Result<Value> {
        let output_schema = self
            .get_tool_registry()
            .and_then(|registry| registry.get(&format!("{server}:{tool}")))
            .and_then(|entry| entry.tool.output_schema)
            .or_else(|| {
                self.backends
                    .get(server)
                    .and_then(|backend| backend.get_cached_tool(tool))
                    .and_then(|cached| cached.output_schema)
            });
        let validated =
            super::invoke::enforce_output_schema(server, tool, result, output_schema.as_ref());
        self.apply_response_gates(server, tool, api_key_name, trace_id, validated)
    }

    /// The ordinary post-dispatch processing for a FAILURE that arrived late.
    ///
    /// A peer's `error.message` and its nested `error.data` are upstream text
    /// like any recovered result, so they face the same configured gates —
    /// response contract, anomaly screening, context integrity — carried in the
    /// shape those gates read. Refusal or content rewriting withholds the raw
    /// content; observe-mode annotations retain the configured pass-through.
    ///
    /// The outcome stays a failure and keeps the peer's `code`: there is no
    /// return path here through which an error could become a result.
    pub(crate) fn recover_task_error(
        &self,
        server: &str,
        tool: &str,
        api_key_name: Option<&str>,
        trace_id: &str,
        error: JsonRpcError,
    ) -> JsonRpcError {
        let mut content = vec![json!({"type": "text", "text": error.message})];
        if let Some(data) = &error.data {
            // Inspected too: a gate shown only the message would let the same
            // secret through one field over.
            content.push(json!({"type": "text", "text": data.to_string()}));
        }
        let carrier = json!({"content": content, "isError": true});
        let submitted = crate::security::response_inspect::extract_text_from_result(&carrier);
        let gated = self.apply_response_gates(server, tool, api_key_name, trace_id, carrier);
        let clean = gated.as_ref().is_ok_and(|value| {
            // An annotation alone is not a refusal. Preserve the operator's
            // observe mode, but never persist content that a gate rewrote.
            crate::security::response_inspect::extract_text_from_result(value) == submitted
        });
        if clean {
            error
        } else {
            tracing::warn!(
                server,
                tool,
                code = error.code,
                "recovered upstream failure withheld by the configured response policy"
            );
            JsonRpcError {
                code: error.code,
                message: RECOVERED_ERROR_WITHHELD.into(),
                data: None,
            }
        }
    }
}

/// What a recovered failure says once a gate has acted on its content.
pub(crate) const RECOVERED_ERROR_WITHHELD: &str =
    "the upstream task failed; its error was withheld by the configured response policy";

#[cfg(test)]
#[path = "upstream/error_policy_tests.rs"]
mod error_policy_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gateway_task_envelope_is_not_an_upstream_handle() {
        // The gateway stamps `resultType: "task"` on its own `tools/call`
        // answer; without a peer `taskId` and `status` it is not a job handle.
        assert!(upstream_task_handle(&json!({"resultType": "task"})).is_none());
        assert!(
            upstream_task_handle(
                &json!({"resultType": "complete", "taskId": "x", "status": "working"})
            )
            .is_none()
        );
        assert!(
            upstream_task_handle(&json!({"resultType": "task", "taskId": "", "status": "working"}))
                .is_none()
        );
        assert_eq!(
            upstream_task_handle(
                &json!({"resultType": "task", "taskId": "abc", "status": "working"})
            ),
            Some("abc")
        );
    }

    #[tokio::test]
    async fn an_armed_slot_is_invisible_to_every_other_dispatch() {
        let armed = std::sync::Arc::new(UpstreamSubmission::armed_for("peer", "slow_echo"));
        assert!(
            armed_submission("peer", "slow_echo").is_none(),
            "outside a scope nothing is armed, so an ordinary call can never \
             take the task-augmented leg"
        );
        with_upstream_submission(std::sync::Arc::clone(&armed), async {
            assert!(armed_submission("peer", "slow_echo").is_some());
            assert!(
                armed_submission("peer", "other_tool").is_none(),
                "a nested dispatch to another tool must not be submitted as a task"
            );
            assert!(armed_submission("other_peer", "slow_echo").is_none());
        })
        .await;
    }

    #[test]
    fn only_the_first_genuine_envelope_is_kept() {
        let armed = UpstreamSubmission::armed_for("peer", "slow_echo");
        armed.offer(&json!({"resultType": "complete", "content": []}));
        assert_eq!(armed.handle(), None, "a synchronous answer is not a handle");
        armed.offer(&json!({"resultType": "task", "taskId": "first", "status": "working"}));
        armed.offer(&json!({"resultType": "task", "taskId": "second", "status": "working"}));
        assert_eq!(armed.handle().as_deref(), Some("first"));
    }

    #[test]
    fn a_live_upstream_job_is_never_a_terminal_answer() {
        for status in ["working", "input_required"] {
            let answer = read_query(JsonRpcResponse::success(
                crate::protocol::RequestId::Number(1),
                json!({"resultType": "complete", "taskId": "a", "status": status}),
            ));
            assert!(matches!(answer, UpstreamAnswer::Live));
        }
    }
}
