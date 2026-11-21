// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Decision fixture table part 3b-1, the in-process meta route: the `syntax`
//! sites in the invocation policy (`invoke/policy.rs:42` and `:50` at
//! e6df0d013e).
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
/// the fill check finds it; an unlisted one would be answered absent there
/// first (`fill_check.rs:442-445`). `AllowAll` admits every target
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
