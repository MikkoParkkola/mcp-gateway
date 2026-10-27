// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The interactive token step runs its refresh in a task of its own
//! (`detach_token_step`), so a destination refusal raised inside the refresh
//! cannot reach the calling delivery's task-local record. The caller records
//! it where it joins the task.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex as TokioMutex;

use crate::gateway::delivery_facts;
use crate::oauth::client::destination::client_with_refused_refresh;
use crate::oauth::login_gate::LoginGate;
use crate::security::ssrf::is_ssrf_refusal;

/// A tool call whose detached token refresh is refused by the destination
/// policy records `refused` on that call's delivery.
#[tokio::test]
async fn a_refused_detached_refresh_records_refused_on_the_call() {
    let dir = tempfile::tempdir().unwrap();
    let gate = Arc::new(LoginGate::default());
    let client = client_with_refused_refresh(dir.path())
        .await
        .with_login_gate(Arc::clone(&gate));
    let set_out = gate.set_out_now();
    let oauth = Arc::new(TokioMutex::new(client));
    let (outcome, facts) = delivery_facts::scope(async {
        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            super::detach_token_step(oauth, gate, set_out, "listed-backend".to_owned()),
        )
        .await
        .expect("answered promptly");
        (outcome, delivery_facts::snapshot())
    })
    .await;
    let error = outcome.expect_err("a refused refresh must surface");
    // The classifier the join point keys on: a change to how this refusal
    // is built fails here. The cleartext refusals are pinned the same way
    // in `oauth/client/cleartext_tests.rs`.
    assert!(is_ssrf_refusal(&error), "{error}");
    // Read as the delivery record renders it.
    let mut fields = serde_json::Map::new();
    delivery_facts::record_fields(facts.as_ref(), false, false, &mut fields);
    assert_eq!(
        fields.get("response_effect"),
        Some(&"refused".into()),
        "{fields:?}"
    );
}
