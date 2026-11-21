// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call the gateway itself refused is recorded as a refusal even when its
//! wire code is one the plain error mapping files under `error`: the record's
//! outcome has to agree with the check its decision names.

use serde_json::json;

use super::{api_key_caller, context, meta, ok_result, records};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::visible::memo::with_visibility_memo;

/// O1: the spend budget refuses the call with -32003; the one record says
/// `denied`, not `error`, beside its `cost_budget` decision.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn o1_a_spend_refusal_is_recorded_as_denied() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let who = api_key_caller();
    let meta = meta(Ok(ok_result()), &dir).with_spend_refusing_for_test("read");
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let answer =
        with_visibility_memo(meta.invoke_tool(&args, None, &context(&AllowAll, &who))).await;
    let all = records(&dir);
    let [record] = all.as_slice() else {
        panic!("premise: one invocation record: {all:?}; answer {answer:?}");
    };
    assert_eq!(
        record["decision"]["kind"],
        json!("cost_budget"),
        "premise: the budget decided; answer {answer:?}; {record}"
    );
    assert_eq!(record["error_code"], json!(-32003), "{record}");
    assert_eq!(record["outcome"], json!("denied"), "{record}");
}
