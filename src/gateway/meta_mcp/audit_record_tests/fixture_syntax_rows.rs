// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Decision fixture table part 3b-1, the in-process meta route: the `syntax`
//! sites in the invocation policy (`invoke/policy.rs:42` and `:50` at
//! e6df0d013e), the signing nonce (`signing.rs:680`, `:687`) and the web UI
//! call (`ui_call.rs:208`).
//!
//! Each row's decision carries the same values as part 3a's refusal rows: no
//! rule id (every site here notes `(Syntax, None)`), no grant id, findings not run
//! and no effect (nothing writes those on a refusal before admission), and
//! `decided: fresh`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::super::{api_key_caller, context};
use super::{Form, Refusal, refusal, refused_args, table_meta, table_meta_over};
use crate::config::BackendConfig;
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::visible::memo::with_visibility_memo;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::decision_fixture_table::assert_row;
use crate::security::decision_record::DecisionKind;

/// S1 (unit row): the invocation policy given `gateway_invoke` arguments with
/// no `tool` notes `(Syntax, None)` at `policy.rs:42`, refusing with
/// `Error::json_rpc(INVALID_PARAMS, ..)` (`meta_mcp_helpers.rs:625-628`).
///
/// No external call reaches this site first. `invoke_tool`'s intake reads
/// `server` and `tool` before the policy (`intake.rs:115-116`), and so does
/// the meta admission (`admission.rs:483-484`); both refuse a missing one
/// without noting a kind. So this row calls the check directly and pins the
/// pair it returns, as the 2026-11-06 ruling allows for such a site (T3, P4).
#[tokio::test]
async fn s1_policy_missing_tool() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _sent) = table_meta(&dir, BackendConfig::default());
    let who = api_key_caller();
    let caller = context(&AllowAll, &who);
    let unnamed = json!({"server": "alpha", "arguments": {}});
    let Err((error, pair)) = meta.check_invocation_policy_explained(&unnamed, None, &caller) else {
        panic!("premise: arguments naming no tool pass the policy");
    };
    assert_eq!(
        pair,
        (DecisionKind::Syntax, None),
        "the noted pair: {error:?}"
    );
    assert_eq!(error.to_rpc_code(), -32602, "the refusal's code: {error:?}");
    // Control: the same arguments naming `read` are not refused for their shape.
    let named = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let checked = with_visibility_memo(async {
        meta.check_invocation_policy_explained(&named, None, &caller)
    })
    .await;
    if let Err((error, pair)) = checked {
        assert_ne!(
            pair.0,
            DecisionKind::Syntax,
            "control refused as syntax: {error:?}"
        );
    }
}

/// S2: `gateway_invoke` naming `read.v2`, a name `alpha` itself lists. The
/// catalogue keeps listed names as given (no name check on ingestion), so
/// the fill check finds it; an unlisted one would get the fill check's
/// absent-tool answer first (its text at `fill_check.rs:442-445`). `AllowAll` admits every target
/// (`authz.rs:483-485`) and nothing withholds the name, so the name check at
/// `policy.rs:47-51` decides: `.` is outside `[A-Za-z0-9_-]`
/// (`scope_collision.rs:54-66`). The refusal is `Error::Protocol`, answered
/// with -32600 (`error_origin.rs:86`) and recorded `invalid` with that code
/// (`security/audit.rs:80-85`).
#[tokio::test]
async fn s2_meta_invalid_tool_name_at_policy() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let sent = Arc::new(AtomicUsize::new(0));
    let meta = table_meta_over(
        &dir,
        BackendConfig::default(),
        Arc::new(ListsDotted(Arc::clone(&sent))),
    );
    let dotted = json!({"server": "alpha", "tool": "read.v2", "arguments": {}});
    let malformed = Refusal {
        form: Form::RpcError,
        outcome: "invalid",
        code: Some(-32600),
    };
    let decision = refused_args(&meta, &dir, &dotted, malformed).await;
    assert_row(
        &decision,
        &refusal("s2_meta_invalid_tool_name_at_policy", "syntax"),
    );
    assert_eq!(
        sent.load(Ordering::SeqCst),
        0,
        "alpha received a tools/call"
    );
}

/// `alpha` listing the dotted `read.v2` beside `read`; it counts every other
/// request it is sent.
struct ListsDotted(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl crate::transport::Transport for ListsDotted {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let result = if method == "tools/list" {
            let schema = json!({"type": "object"});
            json!({"tools": [
                {"name": "read", "inputSchema": schema},
                {"name": "read.v2", "inputSchema": schema},
            ]})
        } else {
            self.0.fetch_add(1, Ordering::SeqCst);
            json!({"content": [{"type": "text", "text": "sent"}], "isError": false})
        };
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            result,
        ))
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
    async fn notify(&self, _name: &str, _body: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
}

/// A table gateway with message signing armed; `require_nonce` as given.
fn signing_meta(
    dir: &Arc<tempfile::TempDir>,
    require_nonce: bool,
) -> crate::gateway::meta_mcp::MetaMcp {
    let (mut meta, _sent) = table_meta(dir, BackendConfig::default());
    let signer = crate::security::message_signing::MessageSigner::new(
        b"syntax-rows-signing-key-0123456789abcdef".to_vec(),
        None,
        "hardened".into(),
    );
    meta.enable_message_signing(signer, std::time::Duration::from_secs(300), require_nonce);
    meta
}

/// The nonce admission's answer to `nonce`, and the pair it noted.
async fn admitted(
    meta: &crate::gateway::meta_mcp::MetaMcp,
    nonce: Option<&str>,
) -> (
    crate::Result<Option<std::time::Instant>>,
    Option<crate::security::decision_record::Refusal>,
) {
    use crate::gateway::meta_mcp::invoke::audit::{take_refusal, with_route_scope};
    with_route_scope(async {
        let answer = meta.admit_signing_nonce(nonce, "syntax-rows");
        (answer, take_refusal())
    })
    .await
}

/// S15 (unit row): a nonce the store refuses as malformed (257 characters)
/// notes `(Syntax, None)` (`signing.rs:676-684`, from the `INVALID_PARAMS`
/// refusal of `message_signing.rs:246`).
///
/// No wire call reaches this arm with an over-long nonce: the capture turns
/// a nonce longer than 256 characters into an invalid one
/// (`signing.rs:136-139`), which `nonce_value` refuses with the same code
/// before the store is asked (`signing.rs:323`). So this row calls the
/// admission directly and pins the pair its own arm notes; the wire path's
/// kind and record are pinned by the signing refusal rows that follow.
#[tokio::test]
async fn s15_signing_malformed_nonce() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let meta = signing_meta(&dir, true);
    let (answer, noted) = admitted(&meta, Some(&"n".repeat(257))).await;
    let Err(error) = answer else {
        panic!("premise: a 257-character nonce is admitted");
    };
    assert_eq!(
        noted,
        Some((DecisionKind::Syntax, None)),
        "the noted pair: {error:?}"
    );
    assert_eq!(error.to_rpc_code(), -32602, "the refusal's code: {error:?}");
    // Control: a well-formed nonce is admitted and notes nothing.
    let (answer, noted) = admitted(&meta, Some("syntax-rows-nonce-1")).await;
    assert!(
        answer.is_ok(),
        "control: a well-formed nonce refused: {answer:?}"
    );
    assert_eq!(noted, None, "control: a pair noted for an admitted nonce");
}

/// S16a (unit row): no nonce where one is required notes `(Syntax, None)`
/// (`signing.rs:686-691`) and refuses with -32001. Unrecorded on both meta
/// transports for now, as for S15.
#[tokio::test]
async fn s16a_signing_nonce_required() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (answer, noted) = admitted(&signing_meta(&dir, true), None).await;
    let Err(error) = answer else {
        panic!("premise: a missing nonce is admitted where one is required");
    };
    assert_eq!(
        noted,
        Some((DecisionKind::Syntax, None)),
        "the noted pair: {error:?}"
    );
    assert_eq!(error.to_rpc_code(), -32001, "the refusal's code: {error:?}");
    // Control: with no nonce required, the same call is admitted.
    let (answer, noted) = admitted(&signing_meta(&dir, false), None).await;
    assert!(
        answer.is_ok(),
        "control: refused with no nonce required: {answer:?}"
    );
    assert_eq!(noted, None, "control: a pair noted for an admitted call");
}

/// S18 (unit row): a task-augmented call under a web UI call is refused by
/// `task_refused` (`ui_call.rs:207-209`), which notes `(Syntax, None)` and
/// returns `Error::Forbidden { code: -32600, status: 403 }` through
/// `ui_call_refused` (`ui_call.rs:297-305`).
///
/// No external path reaches it. Its one caller refuses a call that carries a
/// task inside a UI call's scope (`call_dispatch.rs:341-343`), and the UI's
/// own request names `gateway_invoke` with no task (`ui/tool_call.rs:442-458`).
/// So this row pins the pair the site notes, as for S1.
#[cfg(feature = "webui")]
#[tokio::test]
async fn s18_ui_call_refuses_a_task() {
    use crate::gateway::meta_mcp::invoke::audit::{take_refusal, with_route_scope};
    use crate::gateway::ui_call::{Confirm, UiCall, refuses_task};
    // Inside a UI call's scope, as its one caller runs: the predicate holds
    // there, so the site is the one a real call would reach.
    let ui = UiCall::new("alpha", "read", "s18-principal", Confirm::Confirmed);
    let (refused, error, noted) = ui
        .scope(with_route_scope(async {
            let refused = refuses_task();
            let error = crate::gateway::ui_call::task_refused();
            (refused, error, take_refusal())
        }))
        .await;
    assert!(refused, "premise: a task is refused inside a UI call");
    assert_eq!(
        noted,
        Some((DecisionKind::Syntax, None)),
        "the noted pair: {error:?}"
    );
    let crate::Error::Forbidden { code, status, .. } = error else {
        panic!("premise: the refusal is a forbidden error: {error:?}");
    };
    assert_eq!(
        (code, status),
        (-32600, 403),
        "the refusal's code and status"
    );
    // Control: outside a UI call nothing refuses a task.
    assert!(
        !crate::gateway::ui_call::refuses_task(),
        "control: a task refused outside a UI call"
    );
}
