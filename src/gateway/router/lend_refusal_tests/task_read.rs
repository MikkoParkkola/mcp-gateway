// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! TASKREAD rows: a stored task read whose cold fill the lender
//! refuses answers that refusal, as the live routes do, and not the
//! retryable "temporarily unavailable" a merely cold slot gets.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::{BACKEND, FixedMint, TOOL, gateway_in, peer, post_mcp, task_request};

/// The literal the live routes' refusal carries (`assert_meta_refusal`).
const REFUSAL: &str = "this call carried none";

/// The lent backend behind a gateway whose credential mint returns no
/// header, so the lender refuses every fill of the caller's slot.
struct Refusing {
    router: axum::Router,
    backend: Arc<crate::backend::Backend>,
    /// `tools/call` requests that reached the backend's peer.
    sent: Arc<AtomicUsize>,
    /// The log and store directories, alive for the row.
    _dirs: (Arc<tempfile::TempDir>, Arc<tempfile::TempDir>),
}

async fn refusing() -> Refusing {
    let (peer_url, sent) = peer().await;
    let headerless = FixedMint {
        expires_at: i64::MAX,
        headers: Vec::new(),
    };
    let closed = crate::config::InputSchemaEnforcement::Closed;
    let (router, _dirs, (_, backend)) = gateway_in(peer_url, headerless, closed).await;
    Refusing {
        router,
        backend,
        sent,
        _dirs,
    }
}

impl Refusing {
    /// Every refusal the lender has made so far, over all bindings.
    fn lender_refusals(&self) -> usize {
        self.backend.lend_refusals.lock().values().sum()
    }

    /// Waits until the lender has refused `count` times, failing after 30 s.
    async fn await_refusals(&self, count: usize) {
        let waited = tokio::time::timeout(Duration::from_secs(30), async {
            while self.lender_refusals() < count {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            waited.is_ok(),
            "premise: {count} lender refusals within 30 s; saw {}",
            self.lender_refusals()
        );
    }

    /// Creates a task whose meta-route invoke targets the lent tool, and
    /// returns the task's id.
    async fn create_task(&self) -> String {
        let target = json!({"server": BACKEND, "tool": TOOL, "arguments": {"q": "x"}});
        let params = json!({"task": {}, "name": "gateway_invoke", "arguments": target});
        let (status, answer) = post_mcp(&self.router, &task_request("tools/call", params)).await;
        answer
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("premise: a task handle: {status} {answer}"))
            .to_owned()
    }

    /// One `tasks/get` of `id`; a read carries no idempotency key.
    async fn read_task(&self, id: &str) -> Value {
        let mut body = task_request("tasks/get", json!({"taskId": id}));
        if let Some(meta) = body
            .pointer_mut("/params/_meta")
            .and_then(Value::as_object_mut)
        {
            meta.remove(crate::protocol::mrtr::IDEMPOTENCY_KEY_META);
        }
        post_mcp(&self.router, &body).await.1
    }

    /// Reads `id` until the task is no longer working (a working task has
    /// nothing stored, so its read judges nothing), failing after 30 s. The
    /// first read that is not "working" is the one a row is about.
    async fn settled_read(&self, id: &str) -> SettledRead {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut working_reads = 0;
        loop {
            let refusals_before = self.lender_refusals();
            let answer = self.read_task(id).await;
            if answer.pointer("/result/status") != Some(&json!("working")) {
                return SettledRead {
                    refusals_after: self.lender_refusals(),
                    answer,
                    refusals_before,
                    working_reads,
                };
            }
            working_reads += 1;
            assert!(
                tokio::time::Instant::now() < deadline,
                "premise: the task settles within 30 s; still working: {answer}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// The first read of a task that is no longer working, with the lender's
/// refusal count just before and just after it.
struct SettledRead {
    answer: Value,
    refusals_before: usize,
    refusals_after: usize,
    working_reads: usize,
}

/// The refusal as the live routes give it: -32001, the lender's message,
/// and nothing that says to retry.
fn assert_refusal(answer: &Value, row: &str) {
    assert_eq!(answer["error"]["code"], -32001, "{row}: {answer}");
    assert!(
        answer["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains(REFUSAL)),
        "{row}: the lender's message: {answer}"
    );
    let data = answer["error"].get("data").cloned().unwrap_or(Value::Null);
    assert!(
        data.get("retryable").is_none() && data.get("retry_after_ms").is_none(),
        "{row}: no retry is suggested: {answer}"
    );
}

/// R1 (TASKREAD.1, .2): the worker's dispatch was refused by the lender
/// (F6's premise); the task's read then fills the caller's cold slot, the
/// lender refuses that fill too, and the read answers the refusal. Today it
/// answers -32603 "temporarily unavailable, retry" with `retry_after_ms`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_task_read_whose_fill_the_lender_refuses_answers_the_refusal() {
    let gw = refusing().await;
    let id = gw.create_task().await;
    let at_create = gw.lender_refusals();
    // The creating request's verdict and the worker's dispatch.
    gw.await_refusals(2).await;
    let settled = gw.settled_read(&id).await;
    let answer = settled.answer;
    eprintln!(
        "R1 lender refusals: at create {at_create}, before the settled read {}, after it {}; \
         {} working reads before it; the settled read answered {answer}",
        settled.refusals_before, settled.refusals_after, settled.working_reads
    );
    assert_refusal(&answer, "R1");
    assert_eq!(gw.sent.load(Ordering::SeqCst), 0, "nothing was sent");
}
