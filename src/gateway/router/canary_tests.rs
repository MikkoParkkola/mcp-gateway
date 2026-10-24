// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8697 credential canary, router (lead, 2026-10-24): the request paths
//! an API-key caller drives through `/mcp` and the direct route (a served
//! call, an idempotent replay, a key reused with other arguments, a missing
//! tool, a tool refusal and a refused credential), with every log at TRACE
//! captured. The caller's stored principal appears in no log line and no
//! answer. The fixture's keys use their name as the secret, and names are
//! logged by design, so the canary is the stored principal (the digest an
//! offline guess is tested against), not the secret.

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, fixture, post_direct, post_meta_invoke};

const KEY: &str = "k-std";

/// `k-std`'s stored principal: 12 hex of the SHA-256 its config names.
fn stored() -> String {
    crate::hashing::sha256_hex(KEY.as_bytes())[..12].to_owned()
}

#[test]
fn canary_router_paths_never_print_the_stored_principal() {
    let mut answers: Vec<Value> = Vec::new();
    let mut statuses = Vec::new();
    let logs: String = crate::test_log_capture::records(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let fx = fixture(Answer::Ok, |_| {}).await;
            let no_args = json!({});
            let calls = [
                post_meta_invoke(&fx, KEY, "alpha", "read", no_args.clone(), None, None).await,
                post_meta_invoke(&fx, KEY, "alpha", "nope", no_args.clone(), None, None).await,
                post_meta_invoke(&fx, "k-wrong", "alpha", "read", no_args.clone(), None, None)
                    .await,
                post_direct(
                    &fx,
                    "alpha",
                    KEY,
                    "read",
                    no_args.clone(),
                    Some("canary-1"),
                    None,
                )
                .await,
                post_direct(
                    &fx,
                    "alpha",
                    KEY,
                    "read",
                    no_args.clone(),
                    Some("canary-1"),
                    None,
                )
                .await,
                // A key reused with other arguments: `/mcp` refuses it (409).
                post_meta_invoke(
                    &fx,
                    KEY,
                    "alpha",
                    "read",
                    no_args.clone(),
                    Some("canary-2"),
                    None,
                )
                .await,
                post_meta_invoke(
                    &fx,
                    KEY,
                    "alpha",
                    "read",
                    json!({"n": 2}),
                    Some("canary-2"),
                    None,
                )
                .await,
            ];
            for (status, body) in calls {
                statuses.push(status);
                answers.push(body);
            }
            let refusing = fixture(Answer::IsError, |_| {}).await;
            let (_, body) =
                post_meta_invoke(&refusing, KEY, "alpha", "read", no_args, None, None).await;
            answers.push(body);
        });
    })
    .iter()
    .map(Value::to_string)
    .collect();
    let stored = stored();
    assert!(!logs.is_empty(), "premise: the requests logged");
    assert!(
        statuses.contains(&axum::http::StatusCode::CONFLICT),
        "premise, the reused key was refused: {statuses:?} {answers:?}"
    );
    assert!(!logs.contains(&stored), "a log names the principal: {logs}");
    for answer in &answers {
        assert!(
            !answer.to_string().contains(&stored),
            "an answer names it: {answer}"
        );
    }
}
