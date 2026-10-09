// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8176 stage 2 (family continuation-slot-release): a sealed question
//! withheld after finalization gives its slot back on the JSON arm of `/mcp`
//! and on the direct route, and keeps it when delivered. The SSE arm stays
//! count-only until stage 3, so its rows are listed as known leaks.

use super::*;
use crate::security::firewall::tenant_guard::CrossTenantReads;

/// How a row reaches the gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// `POST /mcp`, `gateway_invoke`, no event stream offered.
    MetaJson,
    /// `POST /mcp`, `gateway_invoke`, offering an event stream.
    MetaSse,
    /// `POST /mcp/alpha`, `tools/call t`.
    Direct,
}

const ARMS: [Arm; 3] = [Arm::MetaJson, Arm::MetaSse, Arm::Direct];

/// A backend question naming `tenant`, so the read judge can attribute it.
fn question(tenant: &str) -> Value {
    json!({
        "resultType": "input_required",
        "inputRequests": {"k1": {
            "method": "elicitation/create",
            "params": {"message": "Which account?", "requestedSchema": {"type": "object"}}
        }},
        "requestState": "backend-state",
        "content": [{"type": "text",
                     "text": json!({"customer_id": tenant}).to_string()}]
    })
}

/// A modern call answered by a client that can answer a question, made as
/// the verified subject `alice`, reading `tenant`. Returns the body as text
/// (JSON or SSE).
async fn call(fx: &Fixture, arm: Arm, id: u64, tenant: &str) -> String {
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
        "io.modelcontextprotocol/clientInfo": {"name": "SlotRelease", "version": "1.0.0"}
    });
    let (uri, name, params) = match arm {
        Arm::MetaJson | Arm::MetaSse => (
            "/mcp",
            "gateway_invoke",
            json!({"name": "gateway_invoke", "_meta": meta,
                   "arguments": {"server": "alpha", "tool": "t",
                                 "arguments": {"customer_id": tenant}}}),
        ),
        Arm::Direct => (
            "/mcp/alpha",
            "t",
            json!({"name": "t", "_meta": meta, "arguments": {"customer_id": tenant}}),
        ),
    };
    let accept = if arm == Arm::MetaSse {
        "application/json, text/event-stream"
    } else {
        "application/json"
    };
    let body = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("accept", accept)
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    request
        .extensions_mut()
        .insert(crate::key_server::oidc::VerifiedIdentity {
            subject: "alice".to_string(),
            email: "alice@example.invalid".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://a.example.invalid".to_string(),
        });
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Slots this fixture's gateway holds open now.
async fn held(fx: &Fixture) -> usize {
    let now = crate::protocol::continuation::now_unix_secs();
    fx.state.meta_mcp.continuation().in_flight().len(now).await
}

/// Whether `body` delivered a sealed question: a minted envelope replaced the
/// backend's own state.
fn delivered(body: &str) -> bool {
    body.contains("requestState") && !body.contains("backend-state") && !body.contains("\"error\"")
}

fn report(failures: &[String]) {
    assert!(
        failures.is_empty(),
        "{} rows failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// What happens to the sealed question after finalization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Path {
    /// It reaches the client: the slot is kept for the retry.
    Delivered,
    /// Its delivery record cannot be written under fail-closed (SLOT.2, SLOT.4).
    DeliveryRecordRefused,
    /// The read judge withholds a second tenant's read (SLOT.1, SLOT.4).
    ReadJudgeWithheld,
    /// The direct route's invocation record cannot be written (SLOT.4).
    InvocationRecordRefused,
}

const PATHS: [Path; 4] = [
    Path::Delivered,
    Path::DeliveryRecordRefused,
    Path::ReadJudgeWithheld,
    Path::InvocationRecordRefused,
];

/// Rows that still leak after stage 2: the SSE arm is count-only until stage 3
/// gives it its yield-point handoff (MIK-8176 SLOT.1, SLOT.2 SSE arms).
const KNOWN_LEAK: [(Arm, Path); 2] = [
    (Arm::MetaSse, Path::DeliveryRecordRefused),
    (Arm::MetaSse, Path::ReadJudgeWithheld),
];

/// Slots a row must leave held: the delivered first read keeps one.
fn want(arm: Arm, path: Path) -> usize {
    let kept = match path {
        Path::Delivered | Path::ReadJudgeWithheld => 1,
        Path::DeliveryRecordRefused | Path::InvocationRecordRefused => 0,
    };
    kept + usize::from(KNOWN_LEAK.contains(&(arm, path)))
}

/// Run one row; `None` when the route cannot take the path.
async fn row(arm: Arm, path: Path, relay: Relay) -> Option<String> {
    if path == Path::InvocationRecordRefused && arm != Arm::Direct {
        return None;
    }
    let fx = fixture(Setup {
        reply: Some(question("t1")),
        fail_closed: matches!(
            path,
            Path::DeliveryRecordRefused | Path::InvocationRecordRefused
        ),
        tenant_limit: Some(0),
        cross_tenant_reads: if path == Path::ReadJudgeWithheld {
            CrossTenantReads::Block
        } else {
            CrossTenantReads::Observe
        },
        relay,
        ..Setup::default()
    })
    .await;
    let label = format!("{arm:?} {path:?} relay={relay:?}");
    let body = match path {
        Path::Delivered => call(&fx, arm, 5, "t1").await,
        Path::DeliveryRecordRefused => {
            fx.log
                .fail_next_append_of_kind_for_test("response_delivery_attempt");
            call(&fx, arm, 5, "t1").await
        }
        Path::InvocationRecordRefused => {
            fx.log.fail_next_append_for_test();
            call(&fx, arm, 5, "t1").await
        }
        Path::ReadJudgeWithheld => {
            let first = call(&fx, arm, 5, "t1").await;
            if !delivered(&first) {
                return Some(format!(
                    "{label}: the first read was not delivered: {first}"
                ));
            }
            call(&fx, arm, 6, "t2").await
        }
    };
    let took = match path {
        Path::Delivered => delivered(&body),
        Path::DeliveryRecordRefused | Path::InvocationRecordRefused => body.contains("-32005"),
        Path::ReadJudgeWithheld => body.contains("withheld") && !delivered(&body),
    };
    if !took {
        return Some(format!("{label}: did not take its path: {body}"));
    }
    let (held, want) = (held(&fx).await, want(arm, path));
    (held != want).then(|| format!("{label}: {held} slots held, want {want}: {body}"))
}

/// MIK-8176 SLOT.1, SLOT.2, SLOT.4 and SLOT.6: every arm x path x relay row.
#[tokio::test]
async fn a_question_withheld_after_finalization_gives_its_slot_back() {
    let mut failures = Vec::new();
    for relay in [Relay::Off, Relay::On] {
        for arm in ARMS {
            for path in PATHS {
                if let Some(failure) = row(arm, path, relay).await {
                    failures.push(failure);
                }
            }
        }
    }
    report(&failures);
}
