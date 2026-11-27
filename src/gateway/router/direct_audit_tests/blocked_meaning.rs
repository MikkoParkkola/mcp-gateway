// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One meaning of a blocked call (MEAN.3). A rule that refused a call (a
//! policy denial, a firewall refusal) makes it blocked; a call the caller got
//! wrong fails. Each leg sends one call to a fresh gateway and reads its class
//! twice, from the counters and from the call's one Activity row. Every leg is
//! judged before the row asserts, so a red run names each leg that is wrong.

use super::counting::{attach, meta_invoke, totals};
use super::*;
use crate::counters::CounterStore;

/// The secret of the admin who reads Activity; the caller is alpha's key.
const READER: &str = "reader-of-activity";

/// Alpha's caller key, with `denied` tools, plus an admin reader.
fn keys(denied: Option<Vec<String>>) -> AuthConfig {
    let mut config = key_for_alpha(denied);
    let reader = ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(READER.as_bytes())),
        name: "reader".to_string(),
        admin: true,
        ..Default::default()
    };
    config.api_keys.push(reader);
    config
}

/// What this leg must be on both sides.
#[derive(Clone, Copy)]
enum Class {
    Blocked,
    Failed,
}

/// `None` when both sides agree on `class` for the leg just sent; else a line
/// naming the leg and what each side said.
async fn verdict(fx: &Fixture, store: &CounterStore, leg: &str, class: Class) -> Option<String> {
    let [_, blocks, errors, _, _] = totals(store);
    let (word, counted_ok) = match class {
        Class::Blocked => ("blocked", (blocks, errors) == (1, 0)),
        Class::Failed => ("failed", (blocks, errors) == (0, 1)),
    };
    // Reading the records first lets the log's write land before the list.
    let records = invocations(fx).len();
    let outcomes: Vec<Value> = activity_rows(fx.router.clone(), READER, "")
        .await
        .iter()
        .map(|row| row["outcome"].clone())
        .collect();
    let listed_ok = outcomes == [json!(word)];
    if counted_ok && listed_ok {
        return None;
    }
    Some(format!(
        "{leg}: should be {word}; counters blocks={blocks} errors={errors} [{}]; \
         activity {outcomes:?} [{}]; {records} record(s)",
        if counted_ok { "ok" } else { "WRONG" },
        if listed_ok { "ok" } else { "WRONG" },
    ))
}

#[tokio::test]
async fn p1_a_denial_a_firewall_refusal_and_an_invalid_call_each_take_one_class() {
    let mut wrong = Vec::new();

    // (a) The caller's key denies `t`.
    let fx = fixture(Setup {
        auth: Some(keys(Some(vec!["t".to_string()]))),
        ..Setup::default()
    })
    .await;
    let store = attach(&fx);
    let call = meta_invoke("alpha", "t", &json!({}));
    let _ = post_to(&fx, "/mcp", &call, &Caller::Key).await;
    wrong.extend(verdict(&fx, &store, "(a) policy denial", Class::Blocked).await);

    // (b) The request firewall refuses the arguments.
    let fx = fixture(Setup {
        auth: Some(keys(None)),
        request_firewall: true,
        ..Setup::default()
    })
    .await;
    let store = attach(&fx);
    let call = meta_invoke("alpha", "t", &request_firewall_payload());
    let _ = post_to(&fx, "/mcp", &call, &Caller::Key).await;
    wrong.extend(verdict(&fx, &store, "(b) request firewall", Class::Blocked).await);

    // (d) A direct call that names no tool.
    let fx = fixture(Setup {
        auth: Some(keys(None)),
        ..Setup::default()
    })
    .await;
    let store = attach(&fx);
    let _ = post(&fx, "alpha", &nameless_tools_call(), &Caller::Key).await;
    wrong.extend(verdict(&fx, &store, "(d) invalid call", Class::Failed).await);

    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[tokio::test]
async fn p1c_a_direct_response_firewall_refusal_is_blocked() {
    let fx = fixture(Setup {
        auth: Some(keys(None)),
        tenant_limit: Some(0),
        response_rules: Some(BLOCK_T_RULES),
        reply: Some(takeover_reply()),
        ..Setup::default()
    })
    .await;
    let store = attach(&fx);
    let _ = post(&fx, "alpha", &tools_call("t"), &Caller::Key).await;
    let leg = verdict(&fx, &store, "(c) direct response firewall", Class::Blocked).await;
    assert!(leg.is_none(), "{}", leg.unwrap_or_default());
}
