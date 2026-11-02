// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The egress matrix over stdio (design `2026-10-08-one-egress-scan.md`,
//! MIK-8139 family): the stdio twin of `router/egress_matrix_tests.rs`. A
//! credential a backend plants in any part of any method's answer, or in a
//! notification it streams mid-call, never reaches the stdio client.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::egress_fixture::{
    BACKEND_METHODS, Delivery, NAME, Part, Planted, URI, secret, unclassified_additions,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::security::firewall::{Firewall, FirewallAction, FirewallConfig, FirewallRule};

/// How a cell's gateway screens what it delivers (the HTTP twin's `Setup`).
#[derive(Clone, Copy, Debug)]
enum Setup {
    /// The firewall with no rule.
    Default,
    /// The firewall with a Warn rule on `read`.
    Warn,
    /// No firewall; response inspection in action mode is the only screen.
    InspectionOnly,
    /// No firewall; response inspection in observe mode, which annotates.
    ObserveOnly,
    /// No firewall and response inspection turned off: no screen at all.
    InspectionOff,
    /// The firewall present with response scanning off.
    ScanOff,
    /// The firewall present and disabled.
    FirewallOff,
}

/// The stdio gateway over one planted backend, `alpha`, and its firewall.
async fn stdio_on(backend: Arc<Planted>, setup: Setup) -> (Arc<MetaMcp>, Option<Arc<Firewall>>) {
    let registry = Arc::new(BackendRegistry::new());
    let alpha = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    alpha.set_transport_for_test(backend as Arc<dyn crate::transport::Transport>);
    // Warmed when it can be: a row planting an error in `tools/list` fails it.
    let _ = alpha.get_tools_shared().await;
    assert!(registry.register(alpha));
    let rules = match setup {
        Setup::Warn => vec![FirewallRule {
            tool_match: NAME.to_string(),
            action: FirewallAction::Warn,
            reason: None,
            scan: Vec::new(),
            servers: None,
            keys: None,
            except: None,
            allowed_roots: None,
            path_args: None,
        }],
        _ => Vec::new(),
    };
    let mut meta = MetaMcp::new(registry);
    if matches!(setup, Setup::InspectionOnly) {
        meta.enable_response_inspection_action_mode();
        return (Arc::new(meta), None);
    }
    if matches!(setup, Setup::ObserveOnly) {
        return (Arc::new(meta), None);
    }
    if matches!(setup, Setup::InspectionOff) {
        meta.disable_response_inspection();
        return (Arc::new(meta), None);
    }
    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                enabled: !matches!(setup, Setup::FirewallOff),
                scan_responses: !matches!(setup, Setup::ScanOff),
                scan_requests: false,
                credential_redaction: true,
                rules,
                ..FirewallConfig::default()
            },
            None,
        )
        .with_continuations(meta.continuation()),
    );
    meta.set_firewall(Some(Arc::clone(&firewall)));
    (Arc::new(meta), Some(firewall))
}

/// The stdio method and params that reach `method`'s answer. A backend's tool
/// descriptions reach a stdio client through `gateway_list_tools`, not
/// `tools/list` (which lists the gateway's own tools).
fn params(method: &'static str, part: Part) -> (&'static str, Value) {
    let (sent, mut params) = match method {
        "tools/call" => (
            method,
            json!({"name": "gateway_invoke", "arguments": {
                "server": "alpha", "tool": NAME, "arguments": {}
            }}),
        ),
        "tools/list" => (
            "tools/call",
            json!({"name": "gateway_list_tools",
            "arguments": {"server": "alpha"}}),
        ),
        "prompts/get" => (method, json!({"name": format!("alpha/{NAME}")})),
        "resources/read" => (method, json!({"uri": URI})),
        _ => (method, json!({})),
    };
    if part.is_notification() {
        params["_meta"] = json!({"progressToken": "p1"});
    }
    if matches!(part, Part::InterimQuestion | Part::InterimState) {
        params["_meta"] = answering_client();
    }
    (sent, params)
}

/// What one cell observed: every frame the client was written
/// (notifications, then the answer) as one text, the backend's answers, and
/// the firewall's inspections.
struct Seen {
    body: String,
    calls: usize,
    inspections: usize,
}

/// One stdio request inside the notification scope the stdio server opens.
async fn cell(setup: Setup, method: &'static str, part: Part, text: String) -> Seen {
    let backend = Arc::new(Planted::with_text(method, part, text));
    let calls = Arc::clone(&backend.calls);
    let (meta, firewall) = stdio_on(backend, setup).await;
    let count = || {
        firewall
            .as_ref()
            .map_or(0, |f| f.response_inspection_counts().inspections)
    };
    let before = count();
    let body = send(&meta, method, part).await;
    Seen {
        body,
        calls: calls.load(Ordering::SeqCst),
        inspections: count() - before,
    }
}

/// `method`'s request for `part`, sent through the stdio dispatch inside the
/// notification scope the stdio server opens: every frame the client was
/// written, notifications first, as one text.
async fn send(meta: &Arc<MetaMcp>, method: &'static str, part: Part) -> String {
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let reads = crate::gateway::outbound::StdioReads::new(
        None,
        Arc::new(crate::gateway::outbound::RejectionAudit::new(None, 1)),
        None,
    );
    let (writer, mut queue) = tokio::sync::mpsc::channel(super::super::STDOUT_QUEUE_DEPTH);
    let (sent, params) = params(method, part);
    let request = json!({"jsonrpc": "2.0", "id": 7, "method": sent, "params": params});
    let (answer, _) = Box::pin(super::super::Gateway::dispatch_streaming_notifications(
        Box::pin(super::super::Gateway::dispatch_single(
            meta,
            &policy,
            &mtls,
            &request,
            "stdio-egress",
        )),
        &writer,
        &reads,
        Some(meta.notification_screen(("stdio", "stdio-egress"), None)),
    ))
    .await;
    drop(writer);
    let mut seen = String::new();
    while let Ok(frame) = queue.try_recv() {
        if let Some(value) = frame.stdio_value() {
            seen.push_str(&value.to_string());
        }
    }
    if let Some(answer) = answer {
        seen.push_str(&answer.to_string());
    }
    seen
}

/// A 2026-07-28 request's `_meta` declaring `elicitation`: an interim
/// question reaches the egress only for a client that said it can answer it
/// (otherwise the capability gate refuses it first, -32021).
fn answering_client() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
        "io.modelcontextprotocol/clientInfo": {"name": "EgressMatrix", "version": "1.0.0"}
    })
}

/// Whether a question reached the client rewritten: MIK-8155 forbids it on
/// every route (refused, or never asked, are both whole-question outcomes).
fn rewritten(body: &str) -> bool {
    body.contains("[REDACTED")
}

fn refused(body: &str) -> bool {
    body.contains("Response blocked by security firewall") || body.contains("\"code\":-32600")
}

fn report(failures: &[String]) {
    assert!(
        failures.is_empty(),
        "{} cells failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The matrix over stdio: no planted credential arrives, an interim
/// question carrying one is refused, every cell reached its backend.
#[tokio::test]
async fn egress_no_planted_credential_reaches_a_stdio_client() {
    let leak = secret();
    let mut failures = Vec::new();
    for method in BACKEND_METHODS {
        for part in Part::ALL.into_iter().filter(|p| p.applies_to(method)) {
            let at = format!("stdio {method} {part:?}");
            let seen = Box::pin(cell(Setup::Default, method, part, leak.clone())).await;
            if seen.calls == 0 {
                failures.push(format!("{at}: never reached the backend: {}", seen.body));
            }
            if seen.body.contains(&leak) {
                failures.push(format!("{at}: credential delivered: {}", seen.body));
            }
            if part == Part::InterimQuestion && rewritten(&seen.body) {
                failures.push(format!("{at}: question rewritten: {}", seen.body));
            }
        }
    }
    report(&failures);
}

/// MIK-8155 over stdio: a Warn rule redacts a completed answer and still
/// refuses an interim question carrying a credential.
#[tokio::test]
async fn egress_warn_redacts_an_answer_and_refuses_a_question_on_stdio() {
    let leak = secret();
    let seen = Box::pin(cell(
        Setup::Warn,
        "tools/call",
        Part::ResultText,
        leak.clone(),
    ))
    .await;
    assert!(
        !seen.body.contains(&leak) && seen.body.contains("[REDACTED:credential]"),
        "answer not redacted and delivered: {}",
        seen.body
    );
    let seen = Box::pin(cell(
        Setup::Warn,
        "tools/call",
        Part::InterimQuestion,
        leak.clone(),
    ))
    .await;
    assert!(
        !seen.body.contains(&leak) && !rewritten(&seen.body) && refused(&seen.body),
        "question not refused whole: {}",
        seen.body
    );
}

/// MIK-8146 CATSCAN.1, MIK-8139 over stdio: with no firewall, the content
/// inspection alone withholds a credential in any method's answer or error.
#[tokio::test]
async fn egress_content_inspection_screens_every_answer_on_stdio() {
    let leak = secret();
    let mut failures = Vec::new();
    for method in BACKEND_METHODS {
        for part in [Part::ResultText, Part::ErrorMessage, Part::ErrorData] {
            let seen = Box::pin(cell(Setup::InspectionOnly, method, part, leak.clone())).await;
            if seen.calls == 0 {
                failures.push(format!(
                    "stdio {method} {part:?}: never reached: {}",
                    seen.body
                ));
            }
            if seen.body.contains(&leak) {
                failures.push(format!("stdio {method} {part:?}: delivered: {}", seen.body));
            }
        }
    }
    report(&failures);
}

/// `NFR.WORKLOAD.1` over stdio: one firewall inspection per answer.
#[tokio::test]
async fn egress_every_stdio_answer_is_inspected_once() {
    let mut failures = Vec::new();
    for method in BACKEND_METHODS {
        let text = "harmless".to_string();
        let seen = Box::pin(cell(Setup::Default, method, Part::ResultText, text)).await;
        if seen.inspections != 1 {
            failures.push(format!("stdio {method}: {} inspections", seen.inspections));
        }
    }
    report(&failures);
}

/// Controls: harmless text at the same places reaches the stdio client.
#[tokio::test]
async fn egress_harmless_text_reaches_a_stdio_client() {
    let mut failures = Vec::new();
    for method in BACKEND_METHODS {
        for part in [Part::ResultText, Part::Progress, Part::CustomNote] {
            if part.is_notification() && method != "tools/call" {
                continue;
            }
            let text = format!("harmless-{}", method.replace('/', "-"));
            let seen = Box::pin(cell(Setup::Default, method, part, text.clone())).await;
            if !seen.body.contains(&text) {
                failures.push(format!(
                    "stdio {method} {part:?}: not delivered: {}",
                    seen.body
                ));
            }
        }
    }
    report(&failures);
}

/// Every catalogue method the stdio server dispatches is a matrix row.
#[test]
fn egress_every_stdio_catalogue_method_is_a_matrix_row() {
    for method in super::super::stdio_catalogue::METHODS {
        assert!(
            BACKEND_METHODS.contains(&method),
            "{method} is not a matrix row"
        );
    }
}

/// A stdio answer the egress refuses as it is finalized (an interim question
/// carrying a credential) is replaced by the gateway's refusal, which keeps
/// the invocation's trace: the refused delivery joins its invocation record.
#[tokio::test]
async fn a_refused_stdio_answer_joins_its_invocation() {
    use crate::gateway::router::route_matrix_driver_tests::response::{delivery_rows, temp_log};
    let backend = Arc::new(Planted::with_text(
        "tools/call",
        Part::InterimQuestion,
        secret(),
    ));
    let (mut meta, _firewall) = stdio_on(backend, Setup::Default).await;
    let (_dir, log) = temp_log(None);
    Arc::get_mut(&mut meta)
        .expect("the only handle")
        .enable_transparency_log(Arc::clone(&log));
    let body = send(&meta, "tools/call", Part::InterimQuestion).await;
    assert!(refused(&body), "premise: refused whole: {body}");
    let deliveries = delivery_rows(&log).await;
    let invocations: Vec<Value> = std::fs::read_to_string(log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry.get("route").is_some() && entry.get("kind").is_none())
        .collect();
    let ([delivery], [invocation]) = (deliveries.as_slice(), invocations.as_slice()) else {
        panic!("one delivery and one invocation: {deliveries:?} {invocations:?}");
    };
    assert_eq!(delivery["trace_id"], invocation["trace_id"], "{delivery}");
}

/// One stdio `tools/call` of `part` carrying `text` under `setup`, with a
/// transparency log on: what the client got, and the one delivery record.
async fn recorded_delivery(setup: Setup, part: Part, text: String) -> (String, Value) {
    use crate::gateway::router::route_matrix_driver_tests::response::{delivery_rows, temp_log};
    let backend = Arc::new(Planted::with_text("tools/call", part, text));
    let (mut meta, _firewall) = stdio_on(backend, setup).await;
    let (_dir, log) = temp_log(None);
    Arc::get_mut(&mut meta)
        .expect("the only handle")
        .enable_transparency_log(Arc::clone(&log));
    let body = send(&meta, "tools/call", part).await;
    let rows = delivery_rows(&log).await;
    let [row] = rows.as_slice() else {
        panic!("one delivery record: {rows:?}");
    };
    (body, row.clone())
}

/// A clean stdio answer under a scanning firewall: delivered, scanned clean.
#[tokio::test]
async fn a_clean_stdio_delivery_records_delivered() {
    let (body, row) = recorded_delivery(Setup::Default, Part::ResultText, "plain".into()).await;
    assert!(!refused(&body), "premise: delivered: {body}");
    assert_eq!(row["response_effect"], "delivered", "{row}");
    assert_eq!(row["response_findings"], json!([]), "{row}");
}

/// On stdio, response inspection's finding is recorded
/// beside a firewall scan that found nothing.
#[tokio::test]
async fn a_stdio_inspection_finding_is_recorded() {
    let text = format!("base64: {}", "A".repeat(120));
    let (body, row) = recorded_delivery(Setup::Default, Part::ResultText, text.clone()).await;
    assert!(!refused(&body), "premise: delivered: {body}");
    let findings = row["response_findings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        findings
            .iter()
            .any(|f| f["kind"] == "inspect:encoding" && f["where"] == "result"),
        "inspection's finding is missing: {row}"
    );
    assert!(!row.to_string().contains(&text), "no content: {row}");
}

/// On stdio, the same answer goes out with the gateway's
/// `_security_findings` added: the record says `annotated`.
#[tokio::test]
async fn a_stdio_annotated_answer_records_annotated() {
    let text = format!("base64: {}", "A".repeat(120));
    let (body, row) = recorded_delivery(Setup::Default, Part::ResultText, text.clone()).await;
    assert!(
        body.contains("_security_findings") && body.contains(&text),
        "premise: annotated, text unchanged: {body}"
    );
    assert_eq!(row["response_effect"], "annotated", "{row}");
}

/// On stdio, a backend error comes back as a tool error carrying the
/// gateway's `recovery` hint and nothing else added: the hint is noted, so
/// the record says `annotated`.
#[tokio::test]
async fn a_stdio_recovery_hint_records_annotated() {
    let (body, row) = recorded_delivery(
        Setup::FirewallOff,
        Part::ErrorMessage,
        "upstream unavailable".into(),
    )
    .await;
    assert!(
        body.contains("recovery")
            && !body.contains("_context_integrity")
            && !body.contains("_security_findings"),
        "premise: the hint is the only addition: {body}"
    );
    assert_eq!(row["response_effect"], "annotated", "{row}");
}

/// On stdio, a context-integrity verdict attached to an unchanged answer,
/// the only member the gateway adds, records `annotated`.
#[tokio::test]
async fn a_stdio_verdict_records_annotated() {
    let text = "Contact: keeper@orchardcoop.fi".to_owned();
    let (body, row) = recorded_delivery(Setup::FirewallOff, Part::ResultText, text.clone()).await;
    assert!(
        body.contains(&text)
            && body.contains("_context_integrity")
            && !body.contains("_security_findings"),
        "premise: unchanged, the verdict the only addition: {body}"
    );
    assert_eq!(row["response_effect"], "annotated", "{row}");
}

/// A firewall with response scanning off reads nothing, so it states no
/// finding of its own: a credential is listed by response inspection only,
/// which always reads the answer, never as a firewall finding.
#[tokio::test]
async fn a_scan_off_firewall_states_no_finding() {
    for setup in [Setup::ScanOff, Setup::FirewallOff] {
        let leak = secret();
        let (body, row) = recorded_delivery(setup, Part::ResultText, leak.clone()).await;
        assert!(!refused(&body), "premise: delivered: {body}");
        let findings = row["response_findings"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            findings.iter().any(|f| f["kind"] == "inspect:secret"),
            "{setup:?}: inspection's finding: {row}"
        );
        assert!(
            !findings.iter().any(|f| f["kind"]
                .as_str()
                .is_some_and(|k| k.starts_with("firewall:"))),
            "{setup:?}: a firewall that read nothing states nothing: {row}"
        );
        assert!(
            !row.to_string().contains(&leak),
            "{setup:?}: no content: {row}"
        );
    }
}

/// A credential redacted under a Warn rule on stdio: rewritten, with its
/// finding by kind and never its text.
#[tokio::test]
async fn a_redacted_stdio_delivery_records_rewritten() {
    let leak = secret();
    let (body, row) = recorded_delivery(Setup::Warn, Part::ResultText, leak.clone()).await;
    assert!(
        rewritten(&body) && !body.contains(&leak),
        "premise: redacted: {body}"
    );
    assert_eq!(row["response_effect"], "rewritten", "{row}");
    assert!(!row.to_string().contains(&leak), "no content: {row}");
    let findings = row["response_findings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        findings.iter().any(|f| f["kind"]
            .as_str()
            .is_some_and(|k| k.starts_with("firewall:"))),
        "{row}"
    );
}

/// An interim question carrying a credential on stdio: refused whole.
#[tokio::test]
async fn a_refused_stdio_delivery_records_refused() {
    let (body, row) = recorded_delivery(Setup::Default, Part::InterimQuestion, secret()).await;
    assert!(refused(&body), "premise: refused whole: {body}");
    assert_eq!(row["response_effect"], "refused", "{row}");
}

/// A progress notification carrying a credential is screened and withheld
/// mid-call; the answer after it is another artifact, and its delivery
/// records only its own scan: delivered, clean (A4).
#[tokio::test]
async fn a_screened_notification_leaves_the_answers_facts_alone() {
    let leak = secret();
    let (body, row) = recorded_delivery(Setup::Default, Part::Progress, leak.clone()).await;
    assert!(!body.contains(&leak), "premise: withheld: {body}");
    assert_eq!(row["response_effect"], "delivered", "{row}");
    assert_eq!(row["response_findings"], json!([]), "{row}");
}

/// The operator kill switch refuses a stdio `gateway_invoke`: the wire answer
/// is unchanged, and the delivery records `refused`.
#[tokio::test]
async fn a_killed_stdio_call_records_refused() {
    use crate::gateway::router::route_matrix_driver_tests::response::{delivery_rows, temp_log};
    let backend = Arc::new(Planted::with_text(
        "tools/call",
        Part::ResultText,
        "plain".into(),
    ));
    let (mut meta, _firewall) = stdio_on(Arc::clone(&backend), Setup::Default).await;
    let (_dir, log) = temp_log(None);
    Arc::get_mut(&mut meta)
        .expect("the only handle")
        .enable_transparency_log(Arc::clone(&log));
    meta.kill_switch().kill("alpha");
    let body = send(&meta, "tools/call", Part::ResultText).await;
    let answer: Value = serde_json::from_str(&body).expect("one JSON answer");
    assert_eq!(answer["error"]["code"], -32000, "pin: {body}");
    assert_eq!(
        answer["error"]["message"],
        "JSON-RPC error -32000: Server 'alpha' is currently disabled by operator kill switch",
        "pin: {body}"
    );
    let rows = delivery_rows(&log).await;
    let [row] = rows.as_slice() else {
        panic!("one delivery record: {rows:?}");
    };
    assert_eq!(row["response_effect"], "refused", "{row}");
}

/// The stdio twin of the HTTP row: every member the gateway adds to a
/// backend's answer is a row of the member table. A listing is merged from
/// the gateway's own entries and every backend's, so the backend's entry is
/// found in it and diffed.
#[tokio::test]
async fn every_member_the_gateway_adds_on_stdio_is_in_the_member_table() {
    let mut failures = Vec::new();
    for setup in [Setup::ObserveOnly, Setup::InspectionOnly] {
        for method in BACKEND_METHODS {
            for part in [Part::ResultText, Part::ErrorData] {
                for text in ["harmless".to_owned(), secret()] {
                    let seen = cell(setup, method, part, text.clone()).await;
                    let delivery = match method {
                        "tools/call" => Delivery::Wrapped,
                        m if m.ends_with("/list") => Delivery::Merged,
                        _ => Delivery::Passthrough,
                    };
                    for path in unclassified_additions((method, part, &text), delivery, &seen.body)
                    {
                        failures.push(format!(
                            "{setup:?} stdio {method} {part:?}: `{path}` added outside the member table"
                        ));
                    }
                }
            }
        }
    }
    report(&failures);
}

/// `security.response_inspection.enabled: false` over stdio: for a tool
/// result, a backend error and another method's answer, a text carrying a
/// pattern inspection finds is delivered and not inspected at all (no
/// refusal, no `_security_findings`, no "Response inspection finding" log, no
/// inspection run), while the same text under action-mode inspection in the
/// same process is still inspected and screened.
#[test]
fn inspection_off_inspects_nothing_on_stdio() {
    use crate::test_classification_count::{MARKER, runs};
    let cells = [
        ("tools/call", Part::ResultText),
        ("tools/call", Part::ErrorMessage),
        ("prompts/get", Part::ResultText),
    ];
    let mut failures = Vec::new();
    for (n, (method, part)) in cells.into_iter().enumerate() {
        let marker = format!("{MARKER}inspection-off-stdio-{n}");
        let text = format!("{} {marker}", secret());
        for setup in [Setup::InspectionOff, Setup::InspectionOnly] {
            let at = format!("{method} {part:?} {setup:?}");
            let before = runs("d2_inspection", &marker);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let (seen, warnings) = crate::test_log_capture::capture_warnings(|| {
                runtime.block_on(cell(setup, method, part, text.clone()))
            });
            let inspected = runs("d2_inspection", &marker) - before;
            if seen.calls == 0 {
                failures.push(format!("{at}: never reached the backend"));
            }
            if matches!(setup, Setup::InspectionOff) {
                if inspected != 0 {
                    failures.push(format!("{at}: inspected {inspected} times"));
                }
                if refused(&seen.body) || !seen.body.contains(&marker) {
                    failures.push(format!("{at}: not delivered: {}", seen.body));
                }
                if seen.body.contains("_security_findings") {
                    failures.push(format!("{at}: annotated: {}", seen.body));
                }
                if warnings.contains("Response inspection finding") {
                    failures.push(format!("{at}: logged a finding: {warnings}"));
                }
            } else {
                if inspected == 0 {
                    failures.push(format!("{at}: premise: never inspected"));
                }
                if seen.body.contains(&secret()) {
                    failures.push(format!("{at}: premise: not screened: {}", seen.body));
                }
            }
        }
    }
    report(&failures);
}
