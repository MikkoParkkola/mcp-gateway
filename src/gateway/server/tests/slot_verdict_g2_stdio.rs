// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3, C3 and the stdio twin of C10: a stdio `tools/call`
//! of a surfaced per-user tool is judged by the caller's own catalogue slot.
//!
//! Production stdio carries no verified identity, so the per-user fixture is
//! the supported stdio case: a managed account held by the sole operator
//! (`DirectAccountGateway`, production compile, install and custody). The
//! loopback twin harness (`withheld_parity_stdio`) builds through
//! `Gateway::new`, which cannot carry a managed binding without opening a
//! real store, so these rows use the managed door instead of extending
//! `withheld_twin_tests::Spec`.
//!
//! Twins differ only in the sole operator's slot (or, for the absent twin,
//! in whether the name is surfaced); the shared slot always holds the tool
//! with a valid schema, so on base the shared verdict lets it dispatch.

use std::sync::Arc;

use serde_json::{Value, json};

use super::super::stdio_tasks::{self, StdioTasks};
use super::super::{STDIO_SESSION_ID, StdioClient};
use crate::config::{AuthConfig, InputSchemaEnforcement, SurfacedToolConfig};
use crate::gateway::Gateway;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway,
};
use crate::gateway::server::account_bindings::ServeMode;
use crate::protocol::meta::Declared;

const TOOL: &str = "read";
const SIBLING: &str = "note";

/// What the sole operator's own slot holds for [`TOOL`].
#[derive(Clone, Copy, Debug)]
enum Slot {
    Valid,
    /// Structurally invalid schema ("withheld").
    Invalid,
    /// A complete list without it ("lacked").
    Lacks,
}

fn tool(name: &str, schema: &Value) -> crate::protocol::Tool {
    serde_json::from_value(
        json!({"name": name, "description": "A mail tool.", "inputSchema": schema}),
    )
    .expect("a tool")
}

fn valid() -> Value {
    json!({"type": "object", "properties": {"folder": {"type": "string"}}})
}

/// The session's durable task store, held for the life of a row that needs one.
struct TaskStore {
    tasks: Arc<StdioTasks>,
    _expiry: crate::gateway::task_service::execution::ExpirySweep,
    _dir: tempfile::TempDir,
}

/// A stdio gateway over the sole operator's managed backend, both slots warm.
struct Stdio {
    meta: Arc<crate::gateway::meta_mcp::MetaMcp>,
    /// `None` serves no `tasks/*`, as the rows that need no task store.
    tasks: Option<TaskStore>,
    /// Last: it owns the Meta-MCP's audit log, which must outlive every
    /// field above that holds the logger.
    gateway: DirectAccountGateway,
}

impl Stdio {
    fn new(slot: Slot, surfaced: bool, enforcement: InputSchemaEnforcement) -> Self {
        let mut gateway = DirectAccountGateway::new_with(
            ServeMode::Stdio,
            AuthConfig::default(),
            &Binding::Connected,
            Some(enforcement),
        );
        let surfaced = if surfaced {
            vec![SurfacedToolConfig {
                server: BACKEND.to_string(),
                tool: TOOL.to_string(),
            }]
        } else {
            Vec::new()
        };
        let meta = Arc::new(gateway.take_meta().with_surfaced_tools(surfaced));
        let backend = gateway.backends().get(BACKEND).expect("the backend");
        assert_eq!(
            backend.input_schema_enforcement_for_test(),
            enforcement,
            "premise: the fixture's enforcement did not survive compilation"
        );
        backend.store_shared_tools_for_test(vec![tool(TOOL, &valid()), tool(SIBLING, &valid())]);
        let mut own = vec![tool(SIBLING, &valid())];
        match slot {
            Slot::Valid => own.push(tool(TOOL, &valid())),
            Slot::Invalid => own.push(tool(TOOL, &json!({"type": "array"}))),
            Slot::Lacks => {}
        }
        backend.store_per_user_tools_for_test(&DirectAccountGateway::operator_binding(), own);
        Self {
            gateway,
            meta,
            tasks: None,
        }
    }

    /// One stdio `tools/call` of [`TOOL`]: the answer, and the `tools/call`
    /// sends it added at the backend.
    async fn call(&self) -> (Value, usize) {
        let before = self.gateway.tool_calls().len();
        let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": TOOL, "arguments": {"folder": "inbox"}}});
        let answer = Gateway::dispatch_single_for_client(
            &self.meta,
            &Arc::new(crate::security::ToolPolicy::default()),
            &Arc::new(crate::mtls::MtlsPolicy::from_config(
                &crate::mtls::MtlsConfig::default(),
            )),
            request,
            StdioClient {
                session_id: STDIO_SESSION_ID,
                channel: &crate::gateway::input_bridge::NoClientChannel,
                handshake_capabilities: Declared::NONE,
                tasks: self.tasks.as_ref().map(|store| &*store.tasks),
                serving: crate::gateway::server::stdio_single::ModernServing::Enabled,
                discover: crate::gateway::server::stdio_single::DiscoverListing::Configured,
                sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
            },
        )
        .await
        .expect("a request is answered");
        (answer, self.gateway.tool_calls().len() - before)
    }
}

/// The twin rule at `enforcement` for one caller `slot`: the caller-Valid
/// control dispatches (the fixture resolves the sole operator's slot), a
/// name nothing surfaces answers -32601, then `slot` answers exactly as that
/// absent name and sends nothing.
async fn assert_twin(row: &str, slot: Slot, enforcement: InputSchemaEnforcement) {
    let (control, sent) = Stdio::new(Slot::Valid, true, enforcement).call().await;
    assert_eq!(
        sent, 1,
        "{row} premise: the caller-Valid control did not dispatch: {control}"
    );
    let (absent, _) = Stdio::new(Slot::Lacks, false, enforcement).call().await;
    assert_eq!(
        absent.pointer("/error/code"),
        Some(&json!(-32601)),
        "{row} premise: an absent name answers -32601: {absent}"
    );
    let (answer, sent) = Stdio::new(slot, true, enforcement).call().await;
    assert_eq!(sent, 0, "{row} {slot:?}: dispatched; answer {answer}");
    assert_eq!(
        answer, absent,
        "{row} {slot:?}: {answer} vs absent {absent}"
    );
}

/// C3, withheld: stdio `tools/call` by surfaced name of a tool the sole
/// operator's slot holds with an invalid schema. RED on base: the shared
/// slot (valid) decides, so it dispatches.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c3_stdio_per_user_caller_slot_withholds() {
    assert_twin("C3", Slot::Invalid, InputSchemaEnforcement::Closed).await;
}

/// C3, lacked: the same where the slot's complete list lacks the tool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c3_stdio_per_user_caller_slot_lacks() {
    assert_twin("C3", Slot::Lacks, InputSchemaEnforcement::Closed).await;
}

/// C10, stdio twin, withheld: C3 at argument-key enforcement Off. RED on
/// base, as C3.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c10_stdio_per_user_visibility_runs_with_enforcement_off() {
    assert_twin("C10-stdio", Slot::Invalid, InputSchemaEnforcement::Off).await;
}

/// C10, stdio twin, lacked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c10_stdio_per_user_lacked_with_enforcement_off() {
    assert_twin("C10-stdio", Slot::Lacks, InputSchemaEnforcement::Off).await;
}

impl Stdio {
    async fn rpc(&self, id: u64, method: &str, params: Value) -> Value {
        let request = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        Gateway::dispatch_single_for_client(
            &self.meta,
            &Arc::new(crate::security::ToolPolicy::default()),
            &Arc::new(crate::mtls::MtlsPolicy::from_config(
                &crate::mtls::MtlsConfig::default(),
            )),
            request,
            StdioClient {
                session_id: STDIO_SESSION_ID,
                channel: &crate::gateway::input_bridge::NoClientChannel,
                handshake_capabilities: Declared::NONE,
                tasks: self.tasks.as_ref().map(|store| &*store.tasks),
                serving: crate::gateway::server::stdio_single::ModernServing::Enabled,
                discover: crate::gateway::server::stdio_single::DiscoverListing::Configured,
                sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
            },
        )
        .await
        .expect("a request is answered")
    }

    /// Whether the surfaced [`TOOL`] in `tools/list` carries the shared
    /// slot's schema B (a `folder` property) rather than the fill's schema A.
    async fn listed_schema_has_folder(&self, id: u64) -> bool {
        let answer = self.rpc(id, "tools/list", json!({})).await;
        let entry = answer
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .and_then(|tools| tools.iter().find(|t| t["name"] == TOOL))
            .unwrap_or_else(|| panic!("premise: tools/list surfaces {TOOL}: {answer}"));
        entry.pointer("/inputSchema/properties/folder").is_some()
    }
}

#[path = "slot_verdict_g2_stdio_listing.rs"]
mod listing;

/// The stdio gateway over the sole operator's managed backend, [`TOOL`]
/// surfaced and the shared slot warm: the operator's slot is cold.
fn operator_stdio() -> Stdio {
    operator_stdio_armed(|_| {})
}

/// [`operator_stdio`] with `arm` applied to the Meta-MCP before it is shared.
fn operator_stdio_armed(arm: impl FnOnce(&mut crate::gateway::meta_mcp::MetaMcp)) -> Stdio {
    let mut gateway =
        DirectAccountGateway::new_in(ServeMode::Stdio, AuthConfig::default(), &Binding::Connected);
    let mut meta = gateway
        .take_meta()
        .with_surfaced_tools(vec![SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: TOOL.to_string(),
        }]);
    arm(&mut meta);
    let meta = Arc::new(meta);
    let backend = gateway.backends().get(BACKEND).expect("the backend");
    backend.store_shared_tools_for_test(vec![tool(TOOL, &valid())]);
    Stdio {
        gateway,
        meta,
        tasks: None,
    }
}

impl Stdio {
    /// The first line of `initialize`'s greeting.
    async fn greeting_count(&self, id: u64) -> String {
        let params = json!({"protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "mik-8356", "version": "1"}});
        let answer = self.rpc(id, "initialize", params).await;
        answer
            .pointer("/result/instructions")
            .and_then(Value::as_str)
            .and_then(|text| text.lines().next())
            .unwrap_or_else(|| panic!("premise: initialize carries a greeting: {answer}"))
            .to_owned()
    }
}

/// A rotated grant's slot never feeds `initialize`'s count (stdio twin of
/// the HTTP row). After rotation the caller is cold, so its greeting is the
/// one a never-filled caller gets (SLOTVIS.6). RED without the recheck.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn initialize_never_counts_a_rotated_grants_slot_stdio() {
    let cold = operator_stdio().greeting_count(1).await;
    let stdio = operator_stdio();
    let filled = stdio
        .rpc(
            1,
            "tools/call",
            json!({"name": "gateway_list_tools", "arguments": {"server": BACKEND}}),
        )
        .await;
    let warm = stdio.greeting_count(2).await;
    assert_ne!(
        warm, cold,
        "premise: the warm slot's count differs from the cold rule's: {filled}"
    );
    stdio.gateway.rotate_operator_grant().await;
    let old = DirectAccountGateway::operator_binding();
    let backend = stdio.gateway.backends().get(BACKEND).expect("the backend");
    assert!(
        backend
            .populated_per_user_bindings_for_test()
            .contains(&old),
        "premise: rotation leaves the old slot warm, so this is initialize's check"
    );
    assert_eq!(
        stdio.greeting_count(3).await,
        cold,
        "initialize counted the rotated grant's stale slot"
    );
}

/// The `_meta` of a modern call declaring form elicitation and tasks.
fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "elicitation": {"form": {}},
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
        "io.modelcontextprotocol/clientInfo": {"name": "mik-8356", "version": "1"}
    })
}

impl Stdio {
    /// Open the session's durable task store (the fixture otherwise serves
    /// `tasks: None`, so X14 never runs).
    async fn with_tasks(mut self) -> Self {
        let dir = tempfile::tempdir().expect("store root");
        let mut config = crate::config::Config::default();
        config.tasks.store_dir = dir.path().display().to_string();
        let policy = Arc::new(crate::security::ToolPolicy::default());
        let (tasks, expiry) = stdio_tasks::open(
            &config,
            &crate::config::EnvOverlay::default(),
            &self.meta,
            &policy,
            (
                &std::sync::Arc::new(
                    crate::gateway::record_principal::RecordPrincipalKey::from_text(
                        crate::gateway::record_principal::TEST_RECORD_KEY,
                    )
                    .expect("test key"),
                ),
                &std::sync::Arc::new(crate::config_reload::LiveConfig::new(config.clone())),
            ),
        )
        .await
        .expect("the stdio store opens");
        self.tasks = Some(TaskStore {
            tasks,
            _expiry: expiry,
            _dir: dir,
        });
        self
    }

    /// One modern task `tools/call` of [`TOOL`]: the answer, and the
    /// `tools/call` sends it added at the backend.
    async fn task_call(&self) -> (Value, usize) {
        let before = self.gateway.tool_calls().len();
        let mut meta = modern_meta();
        meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("slot-verdict-p1");
        let answer = self
            .rpc(
                1,
                "tools/call",
                json!({"name": TOOL, "arguments": {"folder": "inbox"},
                    "task": {}, "_meta": meta}),
            )
            .await;
        (answer, self.gateway.tool_calls().len() - before)
    }
}

/// P1 + P4, stdio twin (withheld, lacked), with a task store open: a modern
/// task call naming a surfaced tool the sole operator's own catalogue
/// withholds or lacks gets no confirmation prompt and makes no task. It
/// answers exactly as the same call where nothing surfaces the tool, and
/// sends nothing. RED on base: the shared slot (valid) decides.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p1_stdio_withheld_task_call_gets_no_prompt_and_no_task() {
    let enforcement = InputSchemaEnforcement::Closed;
    let unknown = Stdio::new(Slot::Lacks, false, enforcement)
        .with_tasks()
        .await;
    let (absent, _) = unknown.task_call().await;
    assert!(
        absent.pointer("/result/taskId").is_none(),
        "premise: an unknown name made a task: {absent}"
    );
    for slot in [Slot::Invalid, Slot::Lacks] {
        let stdio = Stdio::new(slot, true, enforcement).with_tasks().await;
        let (answer, sent) = stdio.task_call().await;
        assert!(
            answer.pointer("/result/taskId").is_none(),
            "P4 stdio {slot:?}: a task was made: {answer}"
        );
        assert!(
            answer.pointer("/result/inputRequests").is_none(),
            "P1 stdio {slot:?}: a confirmation prompt was issued: {answer}"
        );
        assert_eq!(sent, 0, "P1 stdio {slot:?}: dispatched; {answer}");
        assert_eq!(
            answer, absent,
            "P1 stdio {slot:?}: {answer} vs unknown {absent}"
        );
    }
}

/// Whether a stdio answer is a refusal (a JSON-RPC error or an error result).
#[cfg(feature = "firewall")]
fn refused(answer: &Value) -> bool {
    answer.get("error").is_some() || answer.pointer("/result/isError") == Some(&json!(true))
}

#[path = "slot_verdict_g2_stdio_f5a.rs"]
mod f5a;

#[path = "slot_verdict_g2_stdio_noview_cooldown.rs"]
mod noview_cooldown;

/// F5(b), stdio (guard, kills M17): a request the request firewall refuses (a
/// path-traversal argument) resolves nothing and fills nothing for a surfaced
/// tool with the operator's slot cold. A verdict taken ahead of the firewall
/// would fill and release.
#[cfg(feature = "firewall")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f5b_stdio_firewall_refusal_resolves_nothing() {
    let stdio = operator_stdio_armed(|meta| {
        let firewall = Arc::new(
            crate::security::firewall::Firewall::from_config(
                crate::security::firewall::FirewallConfig {
                    enabled: true,
                    scan_responses: true,
                    scan_requests: true,
                    ..crate::security::firewall::FirewallConfig::default()
                },
                None,
            )
            .with_continuations(meta.continuation()),
        );
        meta.set_firewall(Some(firewall));
    });
    let (releases, requests) = (stdio.gateway.releases(), stdio.gateway.requests().len());
    let answer = stdio
        .rpc(
            1,
            "tools/call",
            json!({"name": TOOL, "arguments": {"folder": "../../../etc/passwd"}}),
        )
        .await;
    assert!(
        refused(&answer),
        "premise: the firewall let it through: {answer}"
    );
    assert_eq!(
        stdio.gateway.releases(),
        releases,
        "F5(b) stdio: a credential was resolved: {answer}"
    );
    assert_eq!(
        stdio.gateway.requests().len(),
        requests,
        "F5(b) stdio: the backend was asked: {answer}"
    );
}

/// What the managed backend answers the first call with, so a replay of it
/// is recognisable.
const STORED: &str = "stored-output-r1-stdio";

/// A signed, keyed modern `gateway_invoke` of [`TOOL`] carrying `nonce`.
fn signed_keyed_invoke(nonce: &str) -> Value {
    json!({
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            crate::gateway::meta_mcp::signing::NONCE_META: nonce,
            crate::protocol::mrtr::IDEMPOTENCY_KEY_META: "r1-stdio-signed",
        }
    })
}

/// R1-stdio-signed, end to end (MIK-8356 delta review): on stdio, signing
/// prepares a `gateway_invoke` before the route stage records the caller
/// verdict. The sole operator's signed keyed call dispatches while its own
/// slot offers [`TOOL`]; its slot then withholds it (invalid schema). The
/// same call with the same key and a fresh nonce answers -32601 and is never
/// served the stored output. The real stdio path, no hand-built signing
/// context: the layers that skip the policy for a prepared target refuse it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r1_stdio_signed_keyed_replay_of_a_withheld_name_answers_absent() {
    let stdio = operator_stdio_armed(|meta| {
        meta.enable_message_signing(
            crate::security::message_signing::MessageSigner::new(
                b"r1-stdio-signing-secret-at-least-32-bytes!!".to_vec(),
                None,
                "r1-stdio".to_owned(),
            ),
            std::time::Duration::from_secs(300),
            false,
        );
    });
    let backend = stdio.gateway.backends().get(BACKEND).expect("the backend");
    let binding = DirectAccountGateway::operator_binding();
    backend.store_per_user_tools_for_test(
        &binding,
        vec![tool(TOOL, &valid()), tool(SIBLING, &valid())],
    );
    stdio.gateway.answer_next(json!({
        "content": [{"type": "text", "text": STORED}], "isError": false
    }));
    let first = stdio
        .rpc(1, "tools/call", signed_keyed_invoke("r1-stdio-nonce-0001"))
        .await;
    assert!(
        first.to_string().contains(STORED),
        "premise: the signed call dispatches and answers: {first}"
    );
    let sent = stdio.gateway.tool_calls().len();
    let withheld = json!({"type": "object", "properties": 7});
    backend.store_per_user_tools_for_test(
        &binding,
        vec![tool(TOOL, &withheld), tool(SIBLING, &valid())],
    );
    let replay = stdio
        .rpc(2, "tools/call", signed_keyed_invoke("r1-stdio-nonce-0002"))
        .await;
    assert!(
        !replay.to_string().contains(STORED),
        "R1-stdio-signed: a withheld name's signed retry was served the stored output: {replay}"
    );
    assert_eq!(
        replay.pointer("/error/code"),
        Some(&json!(-32601)),
        "R1-stdio-signed: {replay}"
    );
    assert_eq!(
        stdio.gateway.tool_calls().len(),
        sent,
        "R1-stdio-signed: the retry reached the backend: {replay}"
    );
}

/// N1 (the no-view marker from the call path; muse delta LOW): the sole
/// operator's slot is warm and indexed by a real listing, then its managed
/// grant is revoked. Readers that recheck the grant (initialize, `tools/list`,
/// `list_servers`, the disabled list) write the no-view marker themselves;
/// next-tool predictions read the index and do not. A surfaced call by the
/// revoked operator is answered as absent and writes the marker, so every
/// later reader withholds the backend at once. RED without the verdict's
/// `record_no_view`: the index still holds the revoked grant's slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n1_a_revoked_operators_surfaced_call_marks_no_view() {
    let stdio = operator_stdio();
    let filled = stdio
        .rpc(
            1,
            "tools/call",
            json!({"name": "gateway_list_tools", "arguments": {"server": BACKEND}}),
        )
        .await;
    let backend = stdio.gateway.backends().get(BACKEND).expect("the backend");
    assert!(
        backend
            .populated_per_user_bindings_for_test()
            .contains(&DirectAccountGateway::operator_binding()),
        "premise: a real fill warmed the operator's slot: {filled}"
    );
    stdio.gateway.revoke_operator_grant().await;
    let operator = DirectAccountGateway::operator_subject();
    assert!(
        !backend.caller_has_no_view(&operator),
        "premise: the revocation alone writes no marker"
    );
    let answer = stdio
        .rpc(
            2,
            "tools/call",
            json!({"name": TOOL, "arguments": {"folder": "inbox"}}),
        )
        .await;
    assert_eq!(
        answer.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: the revoked operator's surfaced call answers as absent: {answer}"
    );
    assert!(
        backend.caller_has_no_view(&operator),
        "N1: the call left no no-view marker, so predictions still read the revoked slot"
    );
}

/// X1, stdio twin (MIK-8356 ruling (a)): on stdio, with input sanitizing on,
/// a call by the surfaced name of a tool on a per-user `passthrough` backend
/// is sanitized: its NUL argument is refused and nothing is dispatched. The
/// sole operator's own catalogue is what judges the name later, so intake
/// must not exempt it. RED before the fix: intake exempts it and the NUL is
/// dispatched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x1_stdio_per_user_surfaced_name_is_sanitized() {
    let mut gateway = DirectAccountGateway::new_configured(
        ServeMode::Stdio,
        AuthConfig::default(),
        &Binding::Connected,
        |config| config.passthrough = true,
    );
    let meta = Arc::new(
        gateway
            .take_meta()
            .with_surfaced_tools(vec![SurfacedToolConfig {
                server: BACKEND.to_string(),
                tool: TOOL.to_string(),
            }]),
    );
    gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .store_shared_tools_for_test(vec![tool(TOOL, &valid())]);
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": TOOL, "arguments": {"folder": "a\u{0}b"}}});
    let answer = Gateway::dispatch_single_for_client(
        &meta,
        &Arc::new(crate::security::ToolPolicy::default()),
        &Arc::new(crate::mtls::MtlsPolicy::from_config(
            &crate::mtls::MtlsConfig::default(),
        )),
        request,
        StdioClient {
            session_id: STDIO_SESSION_ID,
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: Declared::NONE,
            tasks: None,
            serving: crate::gateway::server::stdio_single::ModernServing::Enabled,
            discover: crate::gateway::server::stdio_single::DiscoverListing::Configured,
            sanitize: crate::gateway::server::stdio_single::InputSanitizing::On,
        },
    )
    .await
    .expect("a request is answered");
    assert!(
        answer.to_string().contains("null bytes"),
        "X1 stdio: a per-user surfaced name was exempt from sanitizing: {answer}"
    );
    assert_eq!(
        gateway.tool_calls().len(),
        0,
        "X1 stdio: the NUL argument was dispatched: {answer}"
    );
}

/// A signed, keyed modern `gateway_invoke` of [`TOOL`] under `key` and `nonce`.
fn signed_invoke_as(key: &str, nonce: &str, folder: &str) -> Value {
    json!({
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": folder}, "nonce": nonce},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            crate::protocol::mrtr::IDEMPOTENCY_KEY_META: key,
        }
    })
}

/// W2 (MIK-8356 x MIK-8353), the stdio twin of the HTTP witness row: the
/// route stage's caller verdict releases the sole operator's managed
/// credential, then execution admission refuses the call (its key reused for
/// other arguments, 409). Something acted, so the nonce stays spent: the
/// honest call re-sent under it is a replay. RED while the stdio witness,
/// minted before the route stage, ignores what the verdict did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w2_stdio_a_verdict_release_then_an_admission_refusal_keeps_the_nonce() {
    let stdio = operator_stdio_armed(|meta| {
        meta.enable_message_signing(
            crate::security::message_signing::MessageSigner::new(
                b"w2-stdio-signing-secret-at-least-32-bytes!!".to_vec(),
                None,
                "w2-stdio".to_owned(),
            ),
            std::time::Duration::from_secs(300),
            true,
        );
    });
    let backend = stdio.gateway.backends().get(BACKEND).expect("the backend");
    backend.store_per_user_tools_for_test(
        &DirectAccountGateway::operator_binding(),
        vec![tool(TOOL, &valid()), tool(SIBLING, &valid())],
    );
    stdio.gateway.answer_next(json!({
        "content": [{"type": "text", "text": "w2-first"}], "isError": false
    }));
    let first = stdio
        .rpc(1, "tools/call", signed_invoke_as("w2-k1", "w2-n1", "inbox"))
        .await;
    assert!(
        first.to_string().contains("w2-first"),
        "premise: the first signed call ran: {first}"
    );
    let sent = stdio.gateway.tool_calls().len();
    let released = stdio.gateway.releases();

    let refused = stdio
        .rpc(2, "tools/call", signed_invoke_as("w2-k1", "w2-n2", "other"))
        .await;
    assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(409)),
        "premise: execution admission's own refusal: {refused}"
    );
    assert!(
        stdio.gateway.releases() > released,
        "premise: the refused call's verdict released a managed credential"
    );
    assert_eq!(
        stdio.gateway.tool_calls().len(),
        sent,
        "premise: the refusal reached no upstream"
    );

    let resent = stdio
        .rpc(3, "tools/call", signed_invoke_as("w2-k2", "w2-n2", "other"))
        .await;
    assert!(
        resent.to_string().contains("Nonce replay detected"),
        "the nonce was given back after the verdict released a credential: {resent}"
    );
}

#[path = "slot_verdict_g2_stdio_cooldown.rs"]
mod cooldown;
