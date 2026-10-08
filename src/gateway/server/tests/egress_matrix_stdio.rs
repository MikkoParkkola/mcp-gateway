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
use crate::security::firewall::{Firewall, FirewallConfig};

/// The stdio gateway over one planted backend, `alpha`.
async fn stdio_on(backend: Arc<Planted>) -> Arc<MetaMcp> {
    let registry = Arc::new(BackendRegistry::new());
    let alpha = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    alpha.set_transport_for_test(backend as Arc<dyn crate::transport::Transport>);
    alpha.get_tools_shared().await.expect("warm the tool cache");
    assert!(registry.register(alpha));
    let firewall = Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_responses: true,
            scan_requests: false,
            credential_redaction: true,
            ..FirewallConfig::default()
        },
        None,
    );
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(Some(Arc::new(firewall)));
    Arc::new(meta)
}

/// The stdio request for `method`, naming the backend's one tool, prompt or
/// resource.
fn params(method: &str, part: Part) -> Value {
    let mut params = match method {
        "tools/call" => json!({"name": "gateway_invoke", "arguments": {
            "server": "alpha", "tool": NAME, "arguments": {}
        }}),
        "prompts/get" => json!({"name": format!("alpha/{NAME}")}),
        "resources/read" => json!({"uri": URI}),
        _ => json!({}),
    };
    if part.is_notification() {
        params["_meta"] = json!({"progressToken": "p1"});
    }
    params
}

/// One stdio request inside the notification scope the stdio server opens;
/// every frame the client is written (notifications, then the answer) as
/// one text, and how often the backend answered.
async fn cell(method: &'static str, part: Part, text: String) -> (String, usize) {
    let backend = Arc::new(Planted::with_text(method, part, text));
    let calls = Arc::clone(&backend.calls);
    let meta = stdio_on(backend).await;
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
    let request =
        json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params(method, part)});
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
    (seen, calls.load(Ordering::SeqCst))
}

fn refused(body: &str) -> bool {
    body.contains("Response blocked by security firewall") || body.contains("\"code\":-32600")
}

/// The matrix over stdio: no planted credential arrives, an interim
/// question carrying one is refused (MIK-8155), every cell reached its
/// backend.
#[tokio::test]
async fn egress_no_planted_credential_reaches_a_stdio_client() {
    let leak = secret();
    let mut failures = Vec::new();
    for method in BACKEND_METHODS {
        for part in Part::ALL.into_iter().filter(|p| p.applies_to(method)) {
            let at = format!("stdio {method} {part:?}");
            let (seen, calls) = Box::pin(cell(method, part, leak.clone())).await;
            if calls == 0 {
                failures.push(format!("{at}: never reached the backend: {seen}"));
            }
            if seen.contains(&leak) {
                failures.push(format!("{at}: credential delivered: {seen}"));
            }
            if part == Part::InterimQuestion && !refused(&seen) {
                failures.push(format!("{at}: question rewritten, not refused: {seen}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} cells failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
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
            let (seen, _) = Box::pin(cell(method, part, text.clone())).await;
            if !seen.contains(&text) {
                failures.push(format!("stdio {method} {part:?}: not delivered: {seen}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} cells failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
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
