// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8340 rows on stdio (test plan r2.1): a surfaced tool withheld from
//! stdio answers exactly as the same name does where it is absent. The twin
//! set is the `/mcp` one's (`router::withheld_twin_tests::Spec`), served
//! over a loopback backend to a production-built stdio gateway. The grant
//! reason is N/A here: stdio carries no personal identity to deny.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::owner2_stdio_tasks::{BACKEND, Fixture, dispatch, fixture_on_with};
use crate::gateway::router::withheld_twin_tests::{ASKING, Absence, Reason, Side, Spec, catalogue};

/// The reasons a stdio row runs on.
const REASONS: [Reason; 3] = [Reason::Policy, Reason::Schema, Reason::Descriptor];

/// A loopback backend serving `tools`, counting each `tools/call` except
/// [`ASKING`]'s, which asks one question every time.
async fn serve(tools: Value) -> (String, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let counted = Arc::clone(&counted);
            let tools = tools.clone();
            async move {
                let name = request["params"]["name"].as_str().unwrap_or_default();
                let result = match request["method"].as_str() {
                    Some("initialize") => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": BACKEND, "version": "0"},
                    }),
                    Some("tools/list") => json!({"tools": tools}),
                    Some("tools/call") if name == ASKING => json!({
                        "resultType": "input_required",
                        "inputRequests": {"k1": {"method": "elicitation/create",
                            "params": {"message": "Which account?",
                                "requestedSchema": {"type": "object"}}}},
                        "requestState": "backend-state-1"
                    }),
                    Some("tools/call") => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        json!({"content": [{"type": "text", "text": "ok"}]})
                    }
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": request.get("id"), "result": result}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let address = listener.local_addr().expect("backend address");
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    (format!("http://{address}/"), calls)
}

/// One stdio twin: the gateway and the backend's call counter.
struct Twin {
    fixture: Fixture,
    calls: Arc<AtomicUsize>,
}

/// Build `spec`'s stdio twin: policy fixtures deny the tool in stdio's tool
/// policy (all but the control); the backend's cache is warmed.
async fn twin(spec: Spec) -> Twin {
    twin_with(spec, |_| {}).await
}

/// [`twin`] with `configure` applied to the gateway config after surfacing.
async fn twin_with(spec: Spec, configure: impl FnOnce(&mut crate::config::Config)) -> Twin {
    let (url, calls) = serve(catalogue(spec)).await;
    let policy = (spec.reason == Reason::Policy && spec.side != Side::Control).then(|| {
        crate::security::ToolPolicyConfig {
            deny: vec![spec.tool.to_string()],
            ..crate::security::ToolPolicyConfig::default()
        }
    });
    let surfaced = spec.surfaced_on(BACKEND);
    let fixture = Box::pin(fixture_on_with(
        (url, Arc::clone(&calls)),
        policy,
        |config| {
            config.meta_mcp.surfaced_tools = surfaced;
            configure(config);
        },
    ))
    .await;
    let backend = fixture
        .meta
        .backends
        .for_test()
        .get(BACKEND)
        .expect("backend");
    backend
        .get_tools_shared()
        .await
        .expect("warm the catalogue");
    let blocked = backend.is_blocked_tool(spec.tool);
    let descriptor_withheld = spec.reason == Reason::Descriptor
        && matches!(
            spec.side,
            Side::Withheld | Side::Absent(Absence::NotSurfaced)
        );
    assert_eq!(
        blocked, descriptor_withheld,
        "premise: `{}` blocked={blocked} on {spec:?}",
        spec.tool
    );
    Twin { fixture, calls }
}

/// What one stdio call answered, with the backend sends.
struct Answered {
    body: Value,
    calls: usize,
}

impl Twin {
    /// `tools/call` of `name` with `params` extending its params.
    async fn call(&self, name: &str, extra: &Value) -> Answered {
        let mut params = json!({"name": name, "arguments": {}});
        if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
            params.extend(extra.clone());
        }
        let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params});
        let body = dispatch(&self.fixture, request).await;
        Answered {
            body,
            calls: self.calls.load(Ordering::SeqCst),
        }
    }
}

/// The `_meta` of a modern call declaring form elicitation and tasks.
fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "elicitation": {"form": {}},
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
        "io.modelcontextprotocol/clientInfo": {"name": "wh", "version": "1"}
    })
}

/// Oracle rule 2, call half: the withheld fresh call reaches the backend 0
/// times; the control's fresh call succeeds.
async fn assert_call_premise(spec: Spec) {
    let refused = twin(spec.with_side(Side::Withheld))
        .await
        .call(spec.tool, &json!({}))
        .await;
    assert_eq!(
        refused.calls, 0,
        "premise ({:?}): the withheld call reached the backend: {}",
        spec.reason, refused.body
    );
    let allowed = twin(spec.with_side(Side::Control))
        .await
        .call(spec.tool, &json!({}))
        .await;
    assert!(
        allowed.body.get("error").is_none() && allowed.calls == 1,
        "premise ({:?}): the control call did not succeed: {}",
        spec.reason,
        allowed.body
    );
}

/// `extra` on a modern call of the tool, withheld vs `NotSurfaced`, after
/// the premise.
async fn modern_pair(spec: Spec, extra: &Value) -> (Answered, Answered) {
    assert_call_premise(spec).await;
    let mut extra = extra.clone();
    let mut meta = modern_meta();
    if let (Some(meta), Some(more)) = (meta.as_object_mut(), extra["_meta"].as_object()) {
        meta.extend(more.clone());
    }
    extra["_meta"] = meta;
    let withheld = twin(spec.with_side(Side::Withheld)).await;
    let absent = twin(spec.with_side(Side::Absent(Absence::NotSurfaced))).await;
    (
        withheld.call(spec.tool, &extra).await,
        absent.call(spec.tool, &extra).await,
    )
}

fn assert_same(row: &str, reason: Reason, withheld: &Answered, absent: &Answered) {
    if let Some(mismatch) = mismatch(row, reason, withheld, absent) {
        panic!("{mismatch}");
    }
}

fn mismatch(row: &str, reason: Reason, withheld: &Answered, absent: &Answered) -> Option<String> {
    (withheld.body != absent.body).then(|| {
        format!(
            "{row} stdio ({reason:?}): withheld {} vs absent {}",
            withheld.body, absent.body
        )
    })
}

/// Fail with every collected cell, so a red run publishes each cell's answer.
fn assert_cells(row: &str, cells: &[String]) {
    assert!(cells.is_empty(), "{row} stdio:\n{}", cells.join("\n"));
}

/// Row 1 stdio (ORACLE.1): bogus `requestState`, every stdio reason. RED.
#[tokio::test]
async fn row1_stdio_bogus_request_state_answers_as_absent() {
    let mut cells = Vec::new();
    for reason in REASONS {
        let spec = Spec::of(reason, Side::Withheld);
        let extra = json!({"requestState": "not-an-envelope"});
        let (withheld, absent) = Box::pin(modern_pair(spec, &extra)).await;
        cells.extend(mismatch("row 1", reason, &withheld, &absent));
        assert_eq!(
            withheld.calls, 0,
            "row 1 stdio ({reason:?}): {}",
            withheld.body
        );
    }
    assert_cells("row 1", &cells);
}

/// Row 2 stdio (ORACLE.1): an envelope minted for the asking tool. RED.
/// The envelope names its server, so the absent twin reaches the policy check
/// and answers 403 "blocked by client policy"; after the fix the withheld name
/// answers that same 403.
#[tokio::test]
async fn row2_stdio_envelope_for_another_call_answers_as_absent() {
    let spec = Spec::of(Reason::Policy, Side::Withheld);
    assert_call_premise(spec).await;
    let mut answers = Vec::new();
    for side in [Side::Withheld, Side::Absent(Absence::NotSurfaced)] {
        let fx = twin(spec.with_side(side)).await;
        let asked = fx.call(ASKING, &json!({"_meta": modern_meta()})).await;
        let envelope = asked.body["result"]["requestState"].clone();
        assert!(
            envelope.is_string(),
            "premise: the asking tool minted no envelope: {}",
            asked.body
        );
        let extra = json!({
            "requestState": envelope,
            "inputResponses": {"k1": {"action": "accept", "content": {}}},
            "_meta": modern_meta()
        });
        answers.push(fx.call(spec.tool, &extra).await);
    }
    assert_same("row 2", Reason::Policy, &answers[0], &answers[1]);
}

/// Row 3 stdio (ORACLE.1): `inputResponses` with no `requestState`. RED.
#[tokio::test]
async fn row3_stdio_unsolicited_answers_answer_as_absent() {
    let spec = Spec::of(Reason::Policy, Side::Withheld);
    let extra = json!({"inputResponses": {"k1": {"action": "accept", "content": {}}}});
    let (withheld, absent) = Box::pin(modern_pair(spec, &extra)).await;
    assert_same("row 3", Reason::Policy, &withheld, &absent);
}

/// Row 4 stdio: task member plus bogus `requestState`. RED.
#[tokio::test]
async fn row4_stdio_task_with_bogus_state_answers_as_absent() {
    let spec = Spec::of(Reason::Policy, Side::Withheld);
    let extra = json!({"task": {}, "requestState": "not-an-envelope"});
    let (withheld, absent) = Box::pin(modern_pair(spec, &extra)).await;
    assert_same("row 4", Reason::Policy, &withheld, &absent);
}

/// Row 4b stdio: a plain modern task of a destructive withheld tool. GREEN
/// for policy (WH.2), RED for schema and descriptor.
#[tokio::test]
async fn row4b_stdio_plain_task_answers_as_absent() {
    let mut cells = Vec::new();
    for reason in REASONS {
        let spec = Spec {
            destructive: true,
            ..Spec::of(reason, Side::Withheld)
        };
        let extra = json!({"task": {}, "_meta": {"io.mcp-gateway/idempotency-key": "wh-4b"}});
        let (withheld, absent) = Box::pin(modern_pair(spec, &extra)).await;
        if withheld.body.pointer("/result/taskId").is_some() {
            cells.push(format!(
                "row 4b stdio ({reason:?}): a task was made: {}",
                withheld.body
            ));
        }
        cells.extend(mismatch("row 4b", reason, &withheld, &absent));
    }
    assert_cells("row 4b", &cells);
}

/// Row 5 stdio (ORACLE.2): `gateway_invok` keeps the absent suggestion. RED.
#[tokio::test]
async fn row5_stdio_near_meta_name_keeps_the_suggestion() {
    let mut cells = Vec::new();
    for reason in [Reason::Policy, Reason::Schema] {
        let spec = Spec {
            tool: "gateway_invok",
            ..Spec::of(reason, Side::Withheld)
        };
        assert_call_premise(spec).await;
        let withheld = twin(spec).await.call(spec.tool, &json!({})).await;
        let absent = twin(spec.with_side(Side::Absent(Absence::NotSurfaced)))
            .await
            .call(spec.tool, &json!({}))
            .await;
        assert!(
            absent.body.to_string().contains("gateway_invoke"),
            "premise ({reason:?}): the absent answer suggests nothing: {}",
            absent.body
        );
        cells.extend(mismatch("row 5", reason, &withheld, &absent));
    }
    assert_cells("row 5", &cells);
}

/// Row 6 stdio (ORACLE.3): exactly one operator record per withheld stdio
/// call, for every stdio reason; only the call is captured. GREEN or RED as
/// observed.
#[test]
fn row6_stdio_one_operator_record_per_withheld_call() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mut cells = Vec::new();
    for reason in REASONS {
        let spec = Spec::of(reason, Side::Withheld);
        let fx = runtime.block_on(twin(spec));
        let (answered, warnings) = crate::test_log_capture::capture_warnings(|| {
            runtime.block_on(fx.call(spec.tool, &json!({})))
        });
        assert_eq!(answered.calls, 0, "premise ({reason:?}): {}", answered.body);
        let records: Vec<&str> = warnings
            .lines()
            .filter(|line| line.contains(spec.tool))
            .filter(|line| {
                let lower = line.to_lowercase();
                lower.contains("refus") || lower.contains("withh")
            })
            .collect();
        if records.len() != 1 {
            cells.push(format!(
                "row 6 stdio ({reason:?}): {} operator records:\n{warnings}",
                records.len()
            ));
        }
    }
    assert_cells("row 6", &cells);
}

/// A gateway signing chains, with the backend requiring one (inc3 R2).
fn require_chain(config: &mut crate::config::Config) {
    use base64::Engine as _;
    config.security.signature_chain = Some(crate::config::SignatureChainConfig {
        signing_key: base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
        key_id: "gw-self".to_string(),
        emit: crate::config::ChainEmit::default(),
        resolved_identity: None,
    });
    // The upstream origin key the backend's chains must start from.
    config.security.remote_server_signing.trusted_keys.insert(
        "gw-up".to_string(),
        crate::security::remote_provenance::TrustedRemoteServerKeyConfig {
            algorithm: crate::security::remote_provenance::RemoteServerSignatureAlgorithm::Ed25519,
            public_key: base64::engine::general_purpose::STANDARD.encode([9u8; 32]),
        },
    );
    if let Some(backend) = config.backends.get_mut(BACKEND) {
        backend.signature_chain = crate::config::ChainMode::Require;
        backend.chain_origins = vec!["gw-up".to_string()];
        backend.chain_signer = Some("gw-up".to_string());
    }
}

/// A task call of the surfaced `tool` straight into the Meta-MCP (below the
/// route stage), as stdio's caller with a task intent.
async fn direct_task_call(fx: &Twin, tool: &str) -> Value {
    let retry = super::owner2_stdio_tasks::keyed("wh-13");
    let authorizer = crate::gateway::authz::ToolPolicyAuthorizer {
        tool_policy: &fx.fixture.policy,
        generation: None,
    };
    let mut caller = crate::gateway::Gateway::build_stdio_caller_context(
        true,
        None,
        &authorizer,
        &retry,
        &crate::protocol::meta::RequestShape::Legacy,
        super::super::StdioClient {
            session_id: super::super::STDIO_SESSION_ID,
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: crate::protocol::meta::Declared::NONE,
            tasks: Some(&fx.fixture.tasks),
            serving: crate::gateway::server::stdio_single::ModernServing::Enabled,
            discover: crate::gateway::server::stdio_single::DiscoverListing::Configured,
            sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
        },
        &crate::gateway::record_principal::test_record_key(),
    );
    caller.task = Some(super::owner2_stdio_tasks::intent(
        &fx.fixture.tasks,
        tool,
        &retry,
    ));
    let arguments = json!({});
    let answered = fx
        .fixture
        .meta
        .handle_tools_call_ref(
            crate::protocol::RequestId::Number(1),
            tool,
            std::borrow::Cow::Borrowed(&arguments),
            Some(super::super::STDIO_SESSION_ID),
            caller,
        )
        .await;
    serde_json::to_value(&answered).expect("a response serialises")
}

/// Row 13 (require chain, direct `MetaMcp`): a task call of a withheld
/// surfaced name on a `require`-chain backend answers as the absent name;
/// the visible control gets the require-chain refusal. RED on base
/// (`refuse_chained_task` reads the gateway-wide map).
#[tokio::test]
async fn row13_require_chain_refusal_answers_as_absent() {
    let spec = Spec::of(Reason::Policy, Side::Withheld);
    let control = twin_with(spec.with_side(Side::Control), require_chain).await;
    let visible = direct_task_call(&control, spec.tool).await;
    assert!(
        visible.to_string().contains("signature chain"),
        "premise: the visible control is not refused for its chain: {visible}"
    );
    let withheld = twin_with(spec, require_chain).await;
    let absent = twin_with(
        spec.with_side(Side::Absent(Absence::NotSurfaced)),
        require_chain,
    )
    .await;
    // The decision is compared, not the task: an id and its clock are minted
    // per task (test plan r2.1: no task creation compared).
    let decision = |mut body: Value| {
        if let Some(result) = body["result"].as_object_mut() {
            for minted in ["taskId", "createdAt", "lastUpdatedAt"] {
                result.remove(minted);
            }
        }
        body
    };
    let w = decision(direct_task_call(&withheld, spec.tool).await);
    let a = decision(direct_task_call(&absent, spec.tool).await);
    assert_eq!(w, a, "row 13: withheld {w} vs absent {a}");
}

/// A hardened stdio gateway signing every `tools/call` (MIK-7886).
fn signed(config: &mut crate::config::Config) {
    config.server.modern_protocol = true;
    config.security.posture = crate::security::SecurityPosture::Hardened;
    // The loopback backend is a private address, which hardened refuses unless named.
    config.security.hardened.private_backends = vec![BACKEND.to_string()];
    config.security.message_signing.enabled = true;
    config.security.message_signing.shared_secret =
        "withheld-parity-signing-secret-of-32-bytes!".to_string();
    config.security.message_signing.replay_window = 300;
    config.security.message_signing.key_id = "withheld-parity".to_string();
}

/// The answer without what each call mints: its trace id and signature.
fn unminted(mut body: Value) -> Value {
    if let Some(result) = body["result"].as_object_mut() {
        result.remove("_trace_id");
    }
    if let Some(signature) = body["result"]["_signature"].as_object_mut() {
        signature.remove("sig");
        signature.remove("ts");
    }
    body
}

/// A refusal of `first` carrying `meta`, then the sibling carrying `meta`,
/// on a fresh fixture built by `configure`; `None` when that reuse answers as
/// the sibling's probe on an untouched fixture.
async fn reuse_after(
    first: &str,
    meta: &Value,
    configure: fn(&mut crate::config::Config),
) -> Option<String> {
    use crate::gateway::router::withheld_twin_tests::SIBLING;
    let spec = Spec::of(Reason::Policy, Side::Withheld);
    let mut extra = json!({"_meta": modern_meta()});
    if let (Some(into), Some(more)) = (extra["_meta"].as_object_mut(), meta.as_object()) {
        into.extend(more.clone());
    }
    let probe = twin_with(spec, configure).await.call(SIBLING, &extra).await;
    assert_eq!(
        probe.calls, 1,
        "premise: the probe did not dispatch: {}",
        probe.body
    );
    let fx = twin_with(spec, configure).await;
    let refused = fx.call(first, &extra).await;
    assert!(
        refused.body.get("error").is_some(),
        "premise: {}",
        refused.body
    );
    let reuse = fx.call(SIBLING, &extra).await;
    (unminted(reuse.body.clone()) != unminted(probe.body.clone()))
        .then(|| format!("reuse {} vs untouched {}", reuse.body, probe.body))
}

/// Row 8 stdio (ORACLE.3): a withheld call and an absent-name call each
/// leave the idempotency key unspent. GREEN or RED as observed.
#[tokio::test]
async fn row8_stdio_refusals_park_no_idempotency_key() {
    let keyed = json!({"io.mcp-gateway/idempotency-key": "wh-8"});
    let mut cells = Vec::new();
    for (label, first) in [("withheld", "read"), ("absent", "no_such_tool")] {
        if let Some(m) = reuse_after(first, &keyed, |_| {}).await {
            cells.push(format!("row 8 stdio key ({label} first): {m}"));
        }
    }
    assert_cells("row 8", &cells);
}

/// Row 8 stdio, nonce half: a withheld call spends no signing nonce. GREEN.
#[tokio::test]
async fn row8_stdio_withheld_call_spends_no_signing_nonce() {
    let nonce = json!({crate::gateway::meta_mcp::signing::NONCE_META: "wh-8-nonce"});
    if let Some(m) = reuse_after("read", &nonce, signed).await {
        panic!("row 8 stdio nonce (withheld first): {m}");
    }
}

/// Row 8b stdio, design addendum A4: an absent-name refusal gives its signing
/// nonce back (MIK-8150 rule). RED or GREEN on base as observed.
#[tokio::test]
async fn row8b_stdio_absent_name_refusal_refunds_the_signing_nonce() {
    let nonce = json!({crate::gateway::meta_mcp::signing::NONCE_META: "wh-8-nonce"});
    if let Some(m) = reuse_after("no_such_tool", &nonce, signed).await {
        panic!("row 8b stdio (absent first): {m}");
    }
}

/// MIK-8160.X14.2 (control): a modern task call of a HARMLESS surfaced tool
/// over stdio is admitted as before. X14 answers `NotRequired`: a `taskId`, no
/// X14 challenge, and the task runs.
#[tokio::test]
async fn x14_2_a_harmless_surfaced_stdio_task_is_admitted() {
    let spec = Spec::of(Reason::Policy, Side::Control);
    assert!(!spec.destructive, "premise: the control tool is harmless");
    let fx = twin(spec).await;
    let mut extra = json!({"task": {}, "_meta": modern_meta()});
    extra["_meta"]["io.mcp-gateway/idempotency-key"] = json!("x14-2");
    let answered = fx.call(spec.tool, &extra).await;
    let task_id = answered
        .body
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!(
                "X14.2: no task for a harmless surfaced tool: {}",
                answered.body
            )
        })
        .to_owned();
    assert!(
        answered.body.pointer("/result/inputRequests").is_none(),
        "X14.2: a harmless tool was challenged: {}",
        answered.body
    );
    let done = super::owner2_stdio_tasks::wait_terminal(&fx.fixture, task_id).await;
    let task = fx
        .fixture
        .tasks
        .service
        .get(crate::gateway::meta_mcp::LOCAL_OPERATOR_PRINCIPAL, &done)
        .expect("the local operator owns its task");
    assert!(
        matches!(
            task.task.status(),
            crate::protocol::tasks::TaskStatus::Completed
        ),
        "X14.2: the admitted task did not run: {:?}",
        task.task.status()
    );
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "X14.2: the task reached its backend once"
    );
}
