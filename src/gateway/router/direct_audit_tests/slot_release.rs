// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8176 (family continuation-slot-release): a sealed question withheld
//! after finalization gives its slot back on `/mcp` (JSON, and both arms of an
//! event stream) and on the direct route, and keeps it when delivered.

use super::*;
use crate::security::firewall::tenant_guard::CrossTenantReads;

/// How a row reaches the gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// `POST /mcp`, `gateway_invoke`, no event stream offered.
    MetaJson,
    /// `POST /mcp`, `gateway_invoke`, offering an event stream.
    MetaSse,
    /// [`Arm::MetaSse`] whose backend sends a notification first, so the
    /// answer leaves on the stream's streaming arm (MIK-8176 stage 3).
    MetaSseStreamed,
    /// `POST /mcp/alpha`, `tools/call t`.
    Direct,
}

const ARMS: [Arm; 4] = [
    Arm::MetaJson,
    Arm::MetaSse,
    Arm::MetaSseStreamed,
    Arm::Direct,
];

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
    call_with(fx, arm, id, tenant, &json!({})).await
}

/// [`call`] with `extra` merged into the call's params (a retry's
/// `requestState` and `inputResponses`).
async fn call_with(fx: &Fixture, arm: Arm, id: u64, tenant: &str, extra: &Value) -> String {
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
        "io.modelcontextprotocol/clientInfo": {"name": "SlotRelease", "version": "1.0.0"}
    });
    let (uri, name, params) = match arm {
        Arm::MetaJson | Arm::MetaSse | Arm::MetaSseStreamed => (
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
    let mut params = params;
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        params.extend(extra.clone());
    }
    if arm == Arm::MetaSseStreamed
        && let Some(meta) = params.get_mut("_meta")
    {
        meta["progressToken"] = json!("p1");
    }
    let accept = if matches!(arm, Arm::MetaSse | Arm::MetaSseStreamed) {
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

/// Rows that still leak. Empty since stage 3, when the SSE arm gained its
/// yield-point handoff (MIK-8176 SLOT.1, SLOT.2 SSE arms).
const KNOWN_LEAK: [(Arm, Path); 0] = [];

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
    if arm == Arm::MetaSseStreamed && !body.contains("notifications/progress") {
        return Some(format!(
            "{label}: the notification did not go first: {body}"
        ));
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

/// The sealed state a delivered JSON answer carries for the retry.
fn state_of(body: &str) -> Option<String> {
    let reply: Value = serde_json::from_str(body).ok()?;
    reply["result"]["requestState"].as_str().map(str::to_owned)
}

/// The control the design asks for (r5b O): a delivered question is not only
/// still held, it is redeemable. The retry is accepted (the backend asks
/// again, so one slot is held after it, the new one), and the spent envelope
/// is refused on a second retry.
#[tokio::test]
async fn a_delivered_question_is_redeemed_once() {
    let mut failures = Vec::new();
    for arm in [Arm::MetaJson, Arm::Direct] {
        let fx = fixture(Setup {
            reply: Some(question("t1")),
            tenant_limit: Some(0),
            ..Setup::default()
        })
        .await;
        let asked = call(&fx, arm, 5, "t1").await;
        let Some(state) = state_of(&asked) else {
            failures.push(format!("{arm:?}: no sealed state to retry with: {asked}"));
            continue;
        };
        let answers = json!({"k1": {"action": "accept", "content": {"account": "work"}}});
        let retry = json!({"requestState": state, "inputResponses": answers});
        let done = call_with(&fx, arm, 6, "t1", &retry).await;
        if done.contains("\"error\"") {
            failures.push(format!("{arm:?}: the retry was refused: {done}"));
        }
        if fx.calls.load(Ordering::SeqCst) != 2 {
            failures.push(format!("{arm:?}: the retry was not dispatched: {done}"));
        }
        if held(&fx).await != 1 {
            failures.push(format!("{arm:?}: want the retry's own slot only: {done}"));
        }
        let again = call_with(&fx, arm, 7, "t1", &retry).await;
        if !again.contains("\"error\"") {
            failures.push(format!(
                "{arm:?}: a spent envelope was redeemed twice: {again}"
            ));
        }
        if fx.calls.load(Ordering::SeqCst) != 2 {
            failures.push(format!(
                "{arm:?}: the spent retry reached the backend: {again}"
            ));
        }
    }
    report(&failures);
}

/// The scripted backend's side of [`Arm::MetaSseStreamed`]: a `tools/call`
/// carrying a progress token gets a progress notification first; `true` when
/// one was published, so the backend answers on a later poll and the stream's
/// biased select takes the notification first (the streaming arm, never the
/// buffered one). No other row sends a progress token.
pub(super) fn notify_first(method: &str, params: Option<&Value>) -> bool {
    if method != "tools/call" {
        return false;
    }
    let Some(token) = params.and_then(|p| p.pointer("/_meta/progressToken")) else {
        return false;
    };
    crate::transport::notification_sink::publish(vec![crate::protocol::JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: "notifications/progress".to_string(),
        params: Some(json!({"progressToken": token, "progress": 1})),
    }]);
    true
}

/// MIK-8276: both of this fixture's firewalls know the keyring its gateway
/// mints continuations with, as the gateway's own do (#2210, MIK-8092).
/// Random ciphertext holds a credential shape about once in 20,000
/// envelopes; without the keyring the redactor rewrites the sealed
/// `requestState` and the answer is refused (-32600) instead of withheld or
/// delivered, which is how the streamed `ReadJudgeWithheld` row failed.
#[tokio::test]
async fn the_fixtures_firewalls_deliver_a_minted_continuation() {
    use crate::gateway::meta_mcp::response_security::ResponseDeliveryContext;
    use crate::security::firewall::response_tests::minted_value::mint_credential_shaped;
    use crate::security::response_policy::{ResponseCorrelation, ResponsePolicyTarget};

    let fx = fixture(Setup {
        reply: Some(question("t1")),
        tenant_limit: Some(0),
        ..Setup::default()
    })
    .await;
    let token = mint_credential_shaped(fx.state.meta_mcp.continuation().keyring());
    let targets = [ResponsePolicyTarget {
        server: "alpha".to_string(),
        tool: "t".to_string(),
    }];
    let context = ResponseDeliveryContext {
        method: "tools/call",
        targets: &targets,
        correlation: ResponseCorrelation {
            session_id: "",
            caller: "anonymous",
            external_server: "alpha",
            external_tool: "t",
            subject: None,
        },
        signing: None,
        chain_source: crate::protocol::ChainSource::default(),
        chain_nonce: None,
    };
    // The router's firewall judges a routed `tools/call`; without one, the
    // Meta-MCP's own does.
    // Without a router firewall the first pass would judge with the
    // Meta-MCP's, and the row would test one firewall twice.
    assert!(fx.state.firewall.is_some(), "the fixture's router firewall");
    for (name, router) in [("router", fx.state.firewall.as_deref()), ("meta", None)] {
        let answer = json!({
            "resultType": "input_required",
            "inputRequests": {"q1": {"params": {"message": "Choose"}}},
            "requestState": token,
        });
        let response = JsonRpcResponse::success(RequestId::Number(1), answer);
        let delivered = fx
            .state
            .meta_mcp
            .finalize_routed(response, &context, router);
        assert!(
            delivered.error.is_none(),
            "the {name} firewall refused the minted handle: {delivered:?}"
        );
        assert_eq!(
            delivered
                .result
                .as_ref()
                .and_then(|r| r.get("requestState")),
            Some(&json!(token)),
            "the {name} firewall changed the minted handle"
        );
    }
}
