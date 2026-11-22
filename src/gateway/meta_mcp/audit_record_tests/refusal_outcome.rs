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
/// `denied`, not `error`, beside its `cost_budget` decision, and the
/// counters and D4 count it once as a refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn o1_a_spend_refusal_is_recorded_as_denied() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let who = api_key_caller();
    let meta = meta(Ok(ok_result()), &dir).with_spend_refusing_for_test("read");
    let store = std::sync::Arc::new(crate::counters::CounterStore::new(
        crate::clock::unix_secs().expect("a readable clock"),
    ));
    meta.set_counters(std::sync::Arc::clone(&store));
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let (answer, text) = crate::security::metrics_scrape::scrape_if_enabled(with_visibility_memo(
        meta.invoke_tool(&args, None, &context(&AllowAll, &who)),
    ));
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
    let d4 = crate::security::metrics_scrape::route_denials_as(text.as_deref(), "meta", "other");
    assert_eq!(
        (crate::counters::test_totals::totals(&store), d4),
        (
            [1, 1, 0, 0, 0],
            crate::security::metrics_scrape::ONE_DENIAL_AS
        ),
        "[calls, blocks, errors, firewall, cache hits] and D4"
    );
}
