// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D3-a, harness H2: grant decision records through the real `/mcp` route,
//! synchronous calls (T9, T10, T11, T20, T27). The personal capability is
//! owned by `key-a`'s verified subject, the grant subject the route derives
//! (`router/identity.rs:267`).
use super::super::*;
use super::support::*;

use crate::gateway::meta_mcp::grant_audit_fixture::{
    CAPS, DECISION_KIND, Endpoint, PERSONAL, capability_backend, decisions, grant, grants,
    invocations, logger, trace_of,
};
use crate::security::audit::AuditFailurePolicy;

/// `key-a`'s grant subject at the route.
pub(super) const OWNER: (&str, &str) = ("https://idp.adapter.test", "alice");

/// What an H2 row holds for its lifetime.
pub(super) struct Armed {
    pub(super) state: Arc<AppState>,
    pub(super) endpoint: Endpoint,
    pub(super) dir: tempfile::TempDir,
    pub(super) log: Arc<crate::security::TransparencyLogger>,
    _store: tempfile::TempDir,
}

/// Keys scoped to the capability backend and the suite's mock.
fn auth() -> AuthConfig {
    let mut auth = two_principal_auth();
    for key in &mut auth.api_keys {
        key.backends = vec![CAPS.to_string(), BACKEND.to_string()];
    }
    auth
}

/// The route with the personal capability at a (held, when `hold`) endpoint,
/// `key-a` granted when `granted`, a log under `policy`, and `configure`
/// applied to the Meta-MCP before it is shared.
pub(super) async fn armed(
    granted: bool,
    hold: bool,
    policy: AuditFailurePolicy,
    configure: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Armed {
    let dir = tempfile::tempdir().expect("a private log directory");
    let endpoint = Endpoint::start(hold).await;
    let log = logger(&dir, policy);
    let sink = Arc::clone(&log);
    let (state, store) =
        super::super::meta_fixture::test_router_app_state_with_meta(&auth(), None, move |meta| {
            let mut meta = configure(meta.with_code_mode(true));
            meta.enable_transparency_log(sink);
            meta
        })
        .await;
    state
        .meta_mcp
        .set_capabilities(capability_backend(endpoint.port, OWNER));
    let rows = if granted {
        vec![grant("g1", OWNER, OWNER)]
    } else {
        vec![]
    };
    state.meta_mcp.set_identity_grants(grants(rows));
    Armed {
        state,
        endpoint,
        dir,
        log,
        _store: store,
    }
}

/// A `gateway_invoke` of the personal capability.
pub(super) fn personal_invoke(id: i64) -> Value {
    modern(
        id,
        "tools/call",
        json!({
            "name": "gateway_invoke",
            "arguments": { "server": CAPS, "tool": PERSONAL, "arguments": {} }
        }),
        true,
    )
}

/// MIK-7663.GH2409.3: a failed decision write refuses the answer under the
/// request's own id, recorded where the route parses the request.
#[tokio::test]
async fn failed_decision_write_refuses_under_the_request_id() {
    let row = armed(true, false, AuditFailurePolicy::FailClosed, |meta| meta).await;
    row.log.fail_next_append_of_kind_for_test(DECISION_KIND);
    let answer = post(&row.state, "key-a", personal_invoke(7)).await;
    std::assert_eq!(answer["error"]["code"], json!(-32005), "{answer}");
    std::assert_eq!(answer["id"], json!(7), "{answer}");
}

/// A two-step `gateway_execute` chain calling the personal capability twice.
pub(super) fn personal_chain(id: i64) -> Value {
    let step = json!({ "tool": format!("{CAPS}:{PERSONAL}"), "arguments": {} });
    modern(
        id,
        "tools/call",
        json!({ "name": "gateway_execute", "arguments": { "chain": [step.clone(), step] } }),
        true,
    )
}

pub(super) fn only(records: Vec<Value>, what: &str) -> Value {
    std::assert_eq!(
        records.len(),
        1,
        "expected exactly one {what}: {records:#?}"
    );
    records.into_iter().next().expect("one record")
}

/// Response signing on, nonce required, as `signing_joint.rs` installs it.
pub(super) fn signing(mut meta: MetaMcp) -> MetaMcp {
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            // Generated per run: no cell needs its value, and none is committed.
            format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            )
            .into_bytes(),
            None,
            "d3a-signing-key".to_owned(),
        ),
        Duration::from_secs(300),
        true,
    );
    meta
}

/// Put a signing nonce beside `server` and `tool`, where signing reads it.
pub(super) fn with_nonce(mut body: Value) -> Value {
    // Fresh per call: a signing nonce is single-use, and none is committed.
    body["params"]["arguments"]["nonce"] = json!(uuid::Uuid::new_v4().to_string());
    body
}

/// T9. A signed call is checked once, by signing preparation; dispatch
/// skips its check and stamps its trace on that note: one record, carrying
/// the invocation's trace.
#[tokio::test]
async fn signed_call_writes_one_record_with_invocation_trace() {
    let row = armed(true, false, AuditFailurePolicy::BestEffort, signing).await;
    let answer = post(&row.state, "key-a", with_nonce(personal_invoke(1))).await;
    assert!(answer.get("error").is_none(), "{answer}");
    let invocation = only(invocations(&row.dir), "invocation record");
    let record = only(decisions(&row.dir), "decision record");
    std::assert_eq!(trace_of(&record), trace_of(&invocation), "{record}");
    assert!(trace_of(&record).is_some(), "{record}");
}

/// T10. Sync admission refuses an ungranted call before dispatch: one
/// `denied` record, and no invocation record.
#[tokio::test]
async fn admission_refusal_writes_one_denied_record() {
    let row = armed(false, false, AuditFailurePolicy::BestEffort, |meta| meta).await;
    let answer = post(&row.state, "key-a", personal_invoke(1)).await;
    std::assert_eq!(
        answer.pointer("/error/code").and_then(Value::as_i64),
        Some(-32004),
        "{answer}"
    );
    let record = only(decisions(&row.dir), "decision record");
    std::assert_eq!(record["outcome"], json!("denied"), "{record}");
    assert!(
        invocations(&row.dir).is_empty(),
        "{:#?}",
        invocations(&row.dir)
    );
}

/// T11. One chain, one tool twice, one `meta_mcp_dispatch` slot: two
/// records, each carrying its own invocation's trace.
#[tokio::test]
async fn plan_calling_one_tool_twice_writes_two_records() {
    let row = armed(true, false, AuditFailurePolicy::BestEffort, |meta| meta).await;
    let answer = post(&row.state, "key-a", personal_chain(1)).await;
    assert!(answer.get("error").is_none(), "{answer}");
    std::assert_eq!(
        row.endpoint.arrivals(),
        2,
        "both steps reach the capability"
    );

    let invocation_traces: Vec<String> = invocations(&row.dir)
        .iter()
        .filter_map(|r| trace_of(r).map(str::to_string))
        .collect();
    let records = decisions(&row.dir);
    std::assert_eq!(records.len(), 2, "{records:#?}");
    let traces: Vec<&str> = records.iter().filter_map(|r| trace_of(r)).collect();
    std::assert_eq!(traces.len(), 2, "{records:#?}");
    assert_ne!(
        traces[0], traces[1],
        "one trace per invocation: {records:#?}"
    );
    for trace in traces {
        assert!(
            invocation_traces.iter().any(|t| t == trace),
            "{trace} pairs with no invocation record: {invocation_traces:?}"
        );
    }
}

/// T20. Admission notes untraced, dispatch notes traced, same key: only
/// the traced note becomes a record.
#[tokio::test]
async fn admitted_unsigned_call_writes_only_the_traced_record() {
    let row = armed(true, false, AuditFailurePolicy::BestEffort, |meta| meta).await;
    let answer = post(&row.state, "key-a", personal_invoke(1)).await;
    assert!(answer.get("error").is_none(), "{answer}");
    let invocation = only(invocations(&row.dir), "invocation record");
    let record = only(decisions(&row.dir), "decision record");
    std::assert_eq!(trace_of(&record), trace_of(&invocation), "{record}");
    assert!(trace_of(&record).is_some(), "{record}");
}

/// The personal capability surfaced under its own name.
pub(super) fn surfaced(meta: MetaMcp) -> MetaMcp {
    meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
        server: CAPS.to_string(),
        tool: PERSONAL.to_string(),
    }])
}

/// T27 (H2, synchronous). A direct-name call to a surfaced personal tool,
/// refused by the grant, is answered -32601 as today and recorded once.
#[tokio::test]
async fn surfaced_call_grant_denial_writes_one_record() {
    let row = armed(false, false, AuditFailurePolicy::BestEffort, surfaced).await;
    let body = modern(
        1,
        "tools/call",
        json!({ "name": PERSONAL, "arguments": {} }),
        true,
    );
    let answer = post(&row.state, "key-a", body).await;
    std::assert_eq!(
        answer.pointer("/error/code").and_then(Value::as_i64),
        Some(-32601),
        "{answer}"
    );
    std::assert_eq!(
        row.endpoint.arrivals(),
        0,
        "the refused call reaches nothing"
    );
    let record = only(decisions(&row.dir), "decision record");
    std::assert_eq!(record["outcome"], json!("denied"), "{record}");
}
