// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7325.RETRY.1: answers without the gateway's own `requestState` are
//! refused, never forwarded.
//!
//! Every interim this gateway relays carries a `requestState` it minted, so an
//! honest retry always presents one. `inputResponses` without it reach a
//! backend as a fresh call carrying stray answers, and a backend that ignores
//! the field runs the call again: the repeat the retry contract exists to
//! prevent. Refused before dispatch, the idempotency key is released, as for
//! every pre-dispatch refusal.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{Value, json};

use crate::error::Error;
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx, invoke_args};
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::protocol::mrtr::RetryFields;

fn retry(input_responses: Option<Value>, idempotency_key: Option<&str>) -> RetryFields {
    RetryFields {
        input_responses,
        request_state: None,
        idempotency_key: idempotency_key.map(str::to_owned),
        malformed: Vec::new(),
        attestation: None,
    }
}

/// The JSON-RPC code of a refusal, or `None` for anything that is not one.
fn rpc_code(result: &crate::error::Result<Value>) -> Option<i32> {
    match result {
        Err(Error::JsonRpc { code, .. }) => Some(*code),
        _ => None,
    }
}

#[tokio::test]
async fn unsolicited_input_responses_are_refused() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let fields = retry(Some(json!({"q": {"action": "accept"}})), None);
    let caller = MetaMcpCallerContext {
        retry: &fields,
        ..ctx(&AllowAll)
    };

    let result = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &caller)
        .await;

    assert_eq!(
        rpc_code(&result),
        Some(-32602),
        "answers with no gateway requestState must be refused -32602: {result:?}"
    );
    let message = result.expect_err("refused").to_string();
    assert!(
        message.contains("requestState"),
        "the refusal must name what is missing: {message}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a refused retry must never reach the backend, which would run it fresh"
    );
}

#[tokio::test]
async fn unsolicited_refusal_frees_the_idempotency_key() {
    let (registry, calls) = counted_backend("alpha");
    let mut meta = MetaMcp::new(registry);
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    let args = invoke_args("alpha", "read");

    let stray = retry(Some(json!({"q": {"action": "accept"}})), Some("one-key"));
    let first = meta
        .invoke_tool(
            &args,
            None,
            &MetaMcpCallerContext {
                retry: &stray,
                ..ctx(&AllowAll)
            },
        )
        .await;
    assert_eq!(rpc_code(&first), Some(-32602), "{first:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "refused before dispatch");

    let clean = retry(None, Some("one-key"));
    let second = meta
        .invoke_tool(
            &args,
            None,
            &MetaMcpCallerContext {
                retry: &clean,
                ..ctx(&AllowAll)
            },
        )
        .await;
    assert!(second.is_ok(), "the clean call must run: {second:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the refusal must release the key, so the clean call with the same key \
         dispatches instead of replaying a stored result"
    );
}

#[tokio::test]
async fn empty_input_responses_without_state_runs() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let fields = retry(Some(json!({})), None);
    let caller = MetaMcpCallerContext {
        retry: &fields,
        ..ctx(&AllowAll)
    };

    let result = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &caller)
        .await;

    assert!(
        result.is_ok(),
        "`{{}}` answers nothing and must run: {result:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// Both refusals of stray answers (this one and `tasks/update`'s) read one
/// emptiness rule, so the two cannot drift apart. A source pin, because the
/// `tasks/update` site has no test harness under the size ceiling to extend.
#[test]
fn both_refusal_sites_share_the_rule() {
    fn code_lines(source: &str) -> String {
        source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }
    let sites = [
        ("meta_mcp/invoke.rs", code_lines(include_str!("invoke.rs"))),
        (
            "router/handlers/tasks.rs",
            code_lines(include_str!("../router/handlers/tasks.rs")),
        ),
    ];
    for (file, code) in &sites {
        assert!(
            code.contains("mrtr::input_responses_nonempty("),
            "{file} must refuse stray answers through the shared rule"
        );
        assert!(
            !code.contains("fn input_responses_nonempty"),
            "{file} defines its own emptiness rule, which can drift from the shared one"
        );
    }
}
