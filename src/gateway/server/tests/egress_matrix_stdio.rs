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
use crate::gateway::egress_fixture::{BACKEND_METHODS, NAME, Part, Planted, URI, secret};
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
        }],
        _ => Vec::new(),
    };
    let mut meta = MetaMcp::new(registry);
    if matches!(setup, Setup::InspectionOnly) {
        meta.enable_response_inspection_action_mode();
        return (Arc::new(meta), None);
    }
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_responses: true,
            scan_requests: false,
            credential_redaction: true,
            rules,
            ..FirewallConfig::default()
        },
        None,
    ));
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
            &meta,
            &policy,
            &mtls,
            &request,
            "stdio-egress",
        )),
        &writer,
        &reads,
        Some(meta.notification_screen("stdio", "stdio-egress")),
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
    Seen {
        body: seen,
        calls: calls.load(Ordering::SeqCst),
        inspections: count() - before,
    }
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
