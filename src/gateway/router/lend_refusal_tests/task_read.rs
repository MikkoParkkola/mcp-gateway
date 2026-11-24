// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! TASKREAD rows: a stored task read whose cold fill the lender
//! refuses answers that refusal, as the live routes do, and not the
//! retryable "temporarily unavailable" a merely cold slot gets.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::{BACKEND, FixedMint, TOOL, gateway_in, gateway_named, peer, post_mcp, task_request};

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
    /// Set by a row that sets the backend's skip seam for one attempt only:
    /// the first skipped answer [`Refusing::read_task`] sees then clears both.
    clear_skip_after_one: AtomicBool,
}

/// The most skipped-claim answers one read absorbs before it fails: 3, so a
/// read makes at most 4 attempts. A chosen tolerance, not a measured bound.
const SKIPS_ABSORBED: usize = 3;

/// Whether `answer` is a stored read that skipped its claim (an unfilled or
/// busy account outcome, judging.rs:266-281): -32603, retryable, no retry
/// time and nothing of a refusal. No row asserts this shape (F6).
fn skipped(answer: &Value) -> bool {
    answer.pointer("/error/code") == Some(&json!(-32603))
        && answer.pointer("/error/data/retryable") == Some(&json!(true))
        && answer.pointer("/error/data/retry_after_ms").is_none()
        && !answer.to_string().contains(REFUSAL)
}

/// Runs `attempt` until it answers something other than a skipped claim, and
/// returns that answer with the attempts it took. A skipped answer whose
/// attempt moved `refusals` is returned at once: the lender refused a fill,
/// and that is a regression a row must see, not a race. Past
/// [`SKIPS_ABSORBED`] skipped answers in a row it fails, naming the count, the
/// last answer and `unfilled`, the backend's unfilled-outcome reads.
async fn absorb_skips<A, F>(
    mut attempt: A,
    refusals: impl Fn() -> usize,
    unfilled: impl Fn() -> usize,
) -> (Value, usize)
where
    A: FnMut() -> F,
    F: std::future::Future<Output = Value>,
{
    let mut skips = 0;
    loop {
        let before = refusals();
        let answer = attempt().await;
        if !skipped(&answer) || refusals() != before {
            return (answer, skips + 1);
        }
        skips += 1;
        eprintln!("read_task: attempt {skips} skipped its claim; reading again");
        assert!(
            skips <= SKIPS_ABSORBED,
            "read_task: {skips} skipped-claim answers in a row (unfilled outcome reads {}); \
             the account never confirmed live: {answer}",
            unfilled()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn refusing() -> Refusing {
    let (peer_url, sent) = peer().await;
    let headerless = FixedMint {
        expires_at: i64::MAX,
        headers: Vec::new(),
    };
    let closed = crate::config::InputSchemaEnforcement::Closed;
    let (router, dirs, (_, backend)) = gateway_in(peer_url, headerless, closed).await;
    Refusing {
        router,
        backend,
        sent,
        _dirs: dirs,
        clear_skip_after_one: AtomicBool::new(false),
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

    /// A `tasks/get` of `id` as a row sees it: a skipped-claim answer (a race
    /// with the account's custody, never a row's subject) is read again, up to
    /// [`SKIPS_ABSORBED`] times; every other answer is returned as it came.
    async fn read_task(&self, id: &str) -> Value {
        let this = self;
        let attempt = move || async move {
            let answer = this.read_once(id).await;
            if skipped(&answer) && this.clear_skip_after_one.swap(false, Ordering::SeqCst) {
                this.backend
                    .skip_account_prepass
                    .store(false, Ordering::SeqCst);
            }
            answer
        };
        let unfilled = || self.backend.unfilled_outcome_reads.load(Ordering::SeqCst);
        absorb_skips(attempt, || self.lender_refusals(), unfilled)
            .await
            .0
    }

    /// One `tasks/get` of `id`; a read carries no idempotency key.
    async fn read_once(&self, id: &str) -> Value {
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
    assert_eq!(
        data["gateway_http_status"], 403,
        "{row}: the refusal keeps its HTTP status: {answer}"
    );
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

/// R2 (TASKREAD.1, a read after a read): inside the lease the settled read
/// took, a second read answers the same refusal from what was recorded, and
/// the lender is not asked again: its count stays at the first read's.
/// Today the second read answers retryable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_read_inside_the_lease_answers_the_recorded_refusal() {
    let gw = refusing().await;
    let id = gw.create_task().await;
    gw.await_refusals(2).await;
    let first = gw.settled_read(&id).await;
    assert_eq!(
        first.refusals_after,
        first.refusals_before + 1,
        "premise: the settled read's own fill reached the lender: {}",
        first.answer
    );
    let second = gw.read_task(&id).await;
    assert_refusal(&second, "R2");
    assert_eq!(
        gw.lender_refusals(),
        first.refusals_after,
        "R2: the second read did not ask the lender again"
    );
}

/// R3 (TASKREAD.1 after the lease): the settled read takes the lease on
/// the real clock; time is paused only then and moved one tick past the
/// lease. The next read asks the lender again (count + 1) and answers the
/// refusal that new fill met. Today it answers retryable.
#[tokio::test]
async fn a_read_after_the_lease_asks_the_lender_again_and_answers_the_refusal() {
    let gw = refusing().await;
    let id = gw.create_task().await;
    gw.await_refusals(2).await;
    let _first = gw.settled_read(&id).await;
    tokio::time::pause();
    tokio::time::advance(crate::gateway::meta_mcp::COLD_RETRY_BACKOFF + Duration::from_millis(1))
        .await;
    let before = gw.lender_refusals();
    let after_lease = gw.read_task(&id).await;
    assert_eq!(
        gw.lender_refusals(),
        before + 1,
        "R3: the read after the lease asked the lender again: {after_lease}"
    );
    assert_refusal(&after_lease, "R3");
}

/// A mint that answers as `refusing` until `lend` is set and as `lending`
/// after: the lender refuses a credential with no header, and lends one
/// that carries a header, so the fill then reaches the peer.
struct SwitchMint {
    lend: Arc<AtomicBool>,
    refusing: FixedMint,
    lending: FixedMint,
}

#[async_trait::async_trait]
impl super::IdentityPropagation for SwitchMint {
    async fn propagate(
        &self,
        identity: &super::VerifiedIdentity,
        backend: &super::BackendDescriptor,
    ) -> Result<super::PropagatedCredential, super::PropagationError> {
        let chosen = if self.lend.load(Ordering::SeqCst) {
            &self.lending
        } else {
            &self.refusing
        };
        chosen.propagate(identity, backend).await
    }
}

/// What the switchable peer does with a `tools/list`: answer it, fail it
/// with a 503 (`fail`), or hold it while `hold` is set.
#[derive(Clone, Default)]
struct PeerControl {
    fail: Arc<AtomicBool>,
    hold: Arc<AtomicBool>,
    lists: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
}

/// A loopback MCP peer driven by `control`; returns its URL.
async fn switch_peer(control: PeerControl) -> String {
    let route = axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
        let control = control.clone();
        async move { answer_peer(&control, &request).await }
    });
    let app = axum::Router::new().route("/mcp", route);
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let address = socket.local_addr().expect("its address");
    tokio::spawn(async move { axum::serve(socket, app).await });
    format!("http://{address}/mcp")
}

async fn answer_peer(control: &PeerControl, request: &Value) -> axum::response::Response {
    use axum::response::IntoResponse;
    let result = match request["method"].as_str() {
        Some("tools/list") => {
            control.lists.fetch_add(1, Ordering::SeqCst);
            while control.hold.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            if control.fail.load(Ordering::SeqCst) {
                return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            let schema = json!({"properties": {"q": {"type": "string"}}, "type": "object"});
            json!({"tools": [{"inputSchema": schema, "name": TOOL}]})
        }
        Some("tools/call") => {
            control.calls.fetch_add(1, Ordering::SeqCst);
            json!({"content": [{"text": "sent", "type": "text"}]})
        }
        _ => json!({}),
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    axum::Json(json!({"id": id, "jsonrpc": "2.0", "result": result})).into_response()
}

/// A [`Refusing`] gateway whose lender refuses until the returned flag is
/// set; after that the fill reaches the switchable peer, which the
/// returned control can fail or hold.
async fn switchable() -> (Refusing, Arc<AtomicBool>, PeerControl) {
    let control = PeerControl::default();
    let url = switch_peer(control.clone()).await;
    let lend = Arc::new(AtomicBool::new(false));
    let mint = SwitchMint {
        lend: Arc::clone(&lend),
        refusing: FixedMint {
            expires_at: i64::MAX,
            headers: Vec::new(),
        },
        lending: FixedMint {
            expires_at: i64::MAX,
            headers: vec![("authorization".to_owned(), "Bearer lent".to_owned())],
        },
    };
    let closed = crate::config::InputSchemaEnforcement::Closed;
    let (router, dirs, (_, backend)) = gateway_named(BACKEND, url, mint, closed).await;
    let gw = Refusing {
        router,
        backend,
        sent: Arc::clone(&control.calls),
        _dirs: dirs,
        clear_skip_after_one: AtomicBool::new(false),
    };
    (gw, lend, control)
}

/// The retryable answer a merely cold slot gets: -32603 with
/// `retryable` and `retry_after_ms`, and nothing of the lender's refusal.
fn assert_retryable(answer: &Value, row: &str) {
    assert_eq!(answer["error"]["code"], -32603, "{row}: {answer}");
    let data = &answer["error"]["data"];
    assert_eq!(data["retryable"], true, "{row}: {answer}");
    assert!(
        data["retry_after_ms"].is_u64(),
        "{row}: the lease's retry time: {answer}"
    );
    assert!(
        !answer.to_string().contains(REFUSAL),
        "{row}: no refusal shows: {answer}"
    );
}

/// R3b: the settled read's fill is refused (recorded); after the lease the
/// lender lends again and the next fill fails at the peer (a 503, not an
/// authorization refusal). That read answers retryable: a recorded refusal
/// never outlives its own lease.
#[tokio::test]
async fn a_refusal_does_not_outlive_its_lease_when_the_next_fill_fails_otherwise() {
    let (gw, lend, control) = switchable().await;
    let id = gw.create_task().await;
    gw.await_refusals(2).await;
    let first = gw.settled_read(&id).await;
    assert_eq!(
        first.refusals_after,
        first.refusals_before + 1,
        "premise: the settled read's fill was refused: {}",
        first.answer
    );
    lend.store(true, Ordering::SeqCst);
    control.fail.store(true, Ordering::SeqCst);
    tokio::time::pause();
    tokio::time::advance(crate::gateway::meta_mcp::COLD_RETRY_BACKOFF + Duration::from_millis(1))
        .await;
    let after_lease = gw.read_task(&id).await;
    assert_eq!(
        gw.lender_refusals(),
        first.refusals_after,
        "R3b premise: the lender lent this time: {after_lease}"
    );
    assert_retryable(&after_lease, "R3b");
}

/// R4 (TASKREAD.3 control): the task's worker was refused, but the settled
/// read's own fill is lent and fails at the peer (a 503). The read answers
/// retryable with its lease's retry time, as today.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fill_failing_for_another_reason_still_answers_retryable() {
    let (gw, lend, control) = switchable().await;
    let id = gw.create_task().await;
    gw.await_refusals(2).await;
    lend.store(true, Ordering::SeqCst);
    control.fail.store(true, Ordering::SeqCst);
    let settled = gw.settled_read(&id).await;
    assert_eq!(
        settled.refusals_after, settled.refusals_before,
        "R4 premise: the read's fill was lent, not refused: {}",
        settled.answer
    );
    assert!(
        control.lists.load(Ordering::SeqCst) > 0,
        "R4 premise: the fill reached the peer: {}",
        settled.answer
    );
    assert_retryable(&settled.answer, "R4");
}

/// R4, its second half: while one read's fill is held at the peer (its
/// lease running), another read answers retryable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_during_another_readers_running_lease_answers_retryable() {
    let (gw, lend, control) = switchable().await;
    let gw = Arc::new(gw);
    let id = gw.create_task().await;
    gw.await_refusals(2).await;
    lend.store(true, Ordering::SeqCst);
    control.hold.store(true, Ordering::SeqCst);
    let lists_before = control.lists.load(Ordering::SeqCst);
    let holder = {
        let (gw, id) = (Arc::clone(&gw), id.clone());
        tokio::spawn(async move { gw.settled_read(&id).await })
    };
    let reached = tokio::time::timeout(Duration::from_secs(30), async {
        while control.lists.load(Ordering::SeqCst) == lists_before {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        reached.is_ok(),
        "premise: the first read's fill reached the peer"
    );
    let during = gw.read_task(&id).await;
    control.hold.store(false, Ordering::SeqCst);
    let _ = holder.await;
    assert_retryable(&during, "R4 running lease");
}

/// The second per-user backend of R6, which the mint lends nothing for.
const SECOND: &str = "lent-b";

/// A mint that always carries a credential for `lends_to`'s audience, and
/// for every other audience only while `others` is set: once it is cleared,
/// those per-user backends' lenders refuse the caller.
struct AudienceMint {
    lends_to: &'static str,
    others: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl super::IdentityPropagation for AudienceMint {
    async fn propagate(
        &self,
        identity: &super::VerifiedIdentity,
        backend: &super::BackendDescriptor,
    ) -> Result<super::PropagatedCredential, super::PropagationError> {
        let lends = backend.audience == self.lends_to || self.others.load(Ordering::SeqCst);
        let headers = if lends {
            vec![("authorization".to_owned(), "Bearer lent".to_owned())]
        } else {
            Vec::new()
        };
        let mint = FixedMint {
            expires_at: i64::MAX,
            headers,
        };
        mint.propagate(identity, backend).await
    }
}

/// A second required per-user backend at `url`, under its own audience,
/// so its lender judges the caller apart from the first backend's.
fn second_backend(url: String) -> Arc<crate::backend::Backend> {
    let per_user = super::IdentityPropagationConfig {
        session_mode: super::SessionMode::PerUser,
        audience: "https://lent-b.internal".to_owned(),
        required: true,
        strategy: super::PropagationStrategyKind::SignedAssertion,
        token_exchange_scope: None,
        token_exchange_endpoint: None,
    };
    let config = super::BackendConfig {
        input_schema_enforcement: crate::config::InputSchemaEnforcement::Closed,
        identity_propagation: Some(per_user),
        transport: super::TransportConfig::Http {
            protocol_version: None,
            streamable_http: Some(true),
            http_url: url,
        },
        ..super::BackendConfig::r2_off()
    };
    let failsafe = super::FailsafeConfig::default();
    Arc::new(crate::backend::Backend::new(
        SECOND,
        config,
        &failsafe,
        Duration::from_secs(60),
    ))
}

/// R6: a task of two targets on two per-user backends. A stored task
/// records only the targets it sent, so both steps are lent and sent while
/// the task runs; then both caller slots are evicted and the second
/// backend's lender starts refusing. The first target is merely cold
/// (another reader holds its lease, the fill held at the peer); the
/// second target's fill is refused by its lender. The read answers the
/// refusal, not the first target's retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_later_targets_refusal_is_answered_over_an_earlier_targets_lease() {
    let control = PeerControl::default();
    let first_url = switch_peer(control.clone()).await;
    let (second_url, second_sent) = peer().await;
    let others = Arc::new(AtomicBool::new(true));
    let mint = AudienceMint {
        lends_to: "https://lent.internal",
        others: Arc::clone(&others),
    };
    let closed = crate::config::InputSchemaEnforcement::Closed;
    let (router, dirs, (meta, first)) = gateway_named(BACKEND, first_url, mint, closed).await;
    let second = second_backend(second_url);
    assert!(
        meta.backends.for_test().register(Arc::clone(&second)),
        "premise: the second backend registers"
    );
    let gw = Arc::new(Refusing {
        router,
        backend: second,
        sent: second_sent,
        _dirs: dirs,
        clear_skip_after_one: AtomicBool::new(false),
    });
    let steps = json!([
        {"arguments": {"q": "x"}, "tool": format!("{BACKEND}:{TOOL}")},
        {"arguments": {"q": "y"}, "tool": format!("{SECOND}:{TOOL}")},
    ]);
    let params = json!({"arguments": {"chain": steps}, "name": "gateway_execute", "task": {}});
    let (status, created) = post_mcp(&gw.router, &task_request("tools/call", params)).await;
    let id = created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task handle: {status} {created}"))
        .to_owned();
    let done = gw.settled_read(&id).await;
    eprintln!(
        "R6 second lender refusals: before the settled read {}, after it {}; it answered {}",
        done.refusals_before, done.refusals_after, done.answer
    );
    assert_eq!(
        done.answer.pointer("/result/status"),
        Some(&json!("completed")),
        "premise: both steps were sent, so both are recorded targets: {}",
        done.answer
    );
    // Both targets go cold (the caller's slots are evicted), and from now
    // on the second backend's lender refuses the caller.
    for (backend, binding) in [
        (&first, "alpha@https://lent.internal"),
        (&gw.backend, "alpha@https://lent-b.internal"),
    ] {
        backend.age_per_user_slot_for_test(binding, 400);
        backend.evict_idle_per_user_entries(Duration::from_secs(300));
        assert!(
            !backend.holds_per_user_slot_for_test(binding),
            "premise: {binding}'s slot is evicted"
        );
    }
    others.store(false, Ordering::SeqCst);
    // The holder may read only the first target. Unseamed, a skipped claim on
    // the first target (the race read_task absorbs) would let its read claim
    // the second one, whose refusal moves the count and is returned at once,
    // and the holder would never reach the first peer. A seamed target leaves
    // the stored read's whole target list (task_replay.rs:104-114), which the
    // read fixes before its fill reaches the peer, so clearing the seam after
    // "reached" cannot hand the holder's read the second target.
    gw.backend
        .skip_account_prepass
        .store(true, Ordering::SeqCst);
    control.hold.store(true, Ordering::SeqCst);
    let lists_before = control.lists.load(Ordering::SeqCst);
    let holder = {
        let (gw, id) = (Arc::clone(&gw), id.clone());
        tokio::spawn(async move { gw.read_task(&id).await })
    };
    let reached = tokio::time::timeout(Duration::from_secs(30), async {
        while control.lists.load(Ordering::SeqCst) == lists_before {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        reached.is_ok(),
        "premise: the holding reader's fill of the first target reached its peer"
    );
    gw.backend
        .skip_account_prepass
        .store(false, Ordering::SeqCst);
    let before_read = gw.lender_refusals();
    let answer = gw.read_task(&id).await;
    eprintln!(
        "R6 second lender refusals around the read: {before_read} -> {}; created {created}",
        gw.lender_refusals()
    );
    control.hold.store(false, Ordering::SeqCst);
    let held = holder.await;
    eprintln!("R6 the holding reader answered {held:?}");
    assert_eq!(
        gw.lender_refusals(),
        before_read + 1,
        "R6 premise: the read's fill of the second target was refused: {answer}"
    );
    assert_refusal(&answer, "R6");
}

/// The skipped-claim absorb's own rows.
#[path = "task_read_skip_rows.rs"]
mod skipped_claim;
