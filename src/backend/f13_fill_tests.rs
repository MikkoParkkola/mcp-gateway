// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F13 (MIK-7586) backend-level cells: the fill's bound, cooldown, drop guard,
//! completeness and failsafe gate, driven through
//! `Backend::undeclared_key_refusal` against a test transport, mostly on
//! tokio's paused clock. Counter labels are read from a local Prometheus
//! render. Router-level cells live in `gateway/router/f13_fetch_on_miss_tests.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::sync::Notify;

use super::fill_check::{LIST_FILL_COOLDOWN, LIST_FILL_WAIT_GRACE, TEXT_UNAVAILABLE, text_partial};
use super::{Backend, PoolKey};
use crate::config::{BackendConfig, FailsafeConfig, InputSchemaEnforcement};
use crate::protocol::{JsonRpcResponse, RequestId};

/// How the wire answers `tools/list`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Serve,
    /// Yields once, then answers with a JSON-RPC error (reachable, list
    /// unreadable): concurrent callers park as waiters first.
    Fail,
    /// As `Fail`, but a transport failure: the backend is unreachable (A3).
    Down,
    Hang,
    /// Signals `started`, waits for `release`, then serves.
    Barrier,
}

/// A `tools/list` upstream. Pages are chosen by the cursor received (none is
/// page 0, `cK` is page K); `endless` serves `tK` pointing at `c{K+1}`.
struct Lister {
    lists: AtomicUsize,
    mode: Mutex<Mode>,
    pages: Mutex<Vec<(Vec<Value>, Option<&'static str>)>>,
    endless: AtomicBool,
    sleep_per_page: Mutex<Duration>,
    fail_resources: AtomicBool,
    headers: Mutex<Vec<Vec<(String, String)>>>,
    started: Notify,
    release: Notify,
}

fn edit_schema() -> Value {
    json!({"type": "object", "properties": {"edits": {"type": "array"}}})
}

fn edit_tool() -> Value {
    json!({"name": "edit", "inputSchema": edit_schema()})
}

impl Lister {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            lists: AtomicUsize::new(0),
            mode: Mutex::new(mode),
            pages: Mutex::new(vec![(vec![edit_tool()], None)]),
            endless: AtomicBool::new(false),
            sleep_per_page: Mutex::new(Duration::ZERO),
            fail_resources: AtomicBool::new(false),
            headers: Mutex::new(Vec::new()),
            started: Notify::new(),
            release: Notify::new(),
        })
    }

    fn lists(&self) -> usize {
        self.lists.load(Ordering::SeqCst)
    }

    fn set(&self, mode: Mode) {
        *self.mode.lock() = mode;
    }

    fn page(&self, page: usize) -> Value {
        let (items, next) = if self.endless.load(Ordering::SeqCst) {
            let name = format!("t{page}");
            let tool = json!({"name": name, "inputSchema": {"type": "object"}});
            (vec![tool], Some(format!("c{}", page + 1)))
        } else {
            let pages = self.pages.lock();
            let (items, next) = &pages[page];
            (items.clone(), next.map(str::to_owned))
        };
        let mut result = json!({ "tools": items });
        if let Some(next) = next {
            result["nextCursor"] = json!(next);
        }
        result
    }
}

#[async_trait]
impl crate::transport::Transport for Lister {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let permission = crate::transport::ResendPermission::Permitted;
        self.request_with_headers(method, params, &[], None, permission)
            .await
    }

    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "resources/list" && self.fail_resources.load(Ordering::SeqCst) {
            return Err(crate::Error::BackendUnavailable("resources fail".into()));
        }
        if method != "tools/list" {
            return Ok(JsonRpcResponse::success(id, json!({})));
        }
        self.lists.fetch_add(1, Ordering::SeqCst);
        self.headers.lock().push(extra_headers.to_vec());
        let mode = *self.mode.lock();
        match mode {
            Mode::Serve => {}
            Mode::Fail => {
                tokio::task::yield_now().await;
                return Ok(JsonRpcResponse::error(Some(id), -32603, "list fails"));
            }
            Mode::Down => {
                tokio::task::yield_now().await;
                return Err(crate::Error::TransportConnect("list down".into()));
            }
            Mode::Hang => std::future::pending::<()>().await,
            Mode::Barrier => {
                self.started.notify_one();
                self.release.notified().await;
            }
        }
        let sleep = *self.sleep_per_page.lock();
        if !sleep.is_zero() {
            tokio::time::sleep(sleep).await;
        }
        let page: usize = params
            .as_ref()
            .and_then(|p| p.get("cursor")?.as_str()?.strip_prefix('c')?.parse().ok())
            .unwrap_or(0);
        Ok(JsonRpcResponse::success(id, self.page(page)))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A single-tenant backend on the `Shared` slot, wired to `lister`.
fn backend(
    mode: InputSchemaEnforcement,
    failsafe: &FailsafeConfig,
    lister: &Arc<Lister>,
) -> Arc<Backend> {
    let config = BackendConfig {
        input_schema_enforcement: mode,
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "f13",
        config,
        failsafe,
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::clone(lister) as Arc<dyn crate::transport::Transport>);
    backend
}

/// No breaker: a cell that fails fills repeatedly must not trip it.
fn no_breaker() -> FailsafeConfig {
    let mut failsafe = FailsafeConfig::default();
    failsafe.circuit_breaker.enabled = false;
    failsafe
}

/// A breaker that opens on one failure and closes on one success.
fn hair_trigger(reset: Duration) -> FailsafeConfig {
    let mut failsafe = FailsafeConfig::default();
    failsafe.circuit_breaker.enabled = true;
    failsafe.circuit_breaker.failure_threshold = 1;
    failsafe.circuit_breaker.success_threshold = 1;
    failsafe.circuit_breaker.reset_timeout = reset;
    failsafe
}

/// R2's check as an anonymous caller on the shared slot.
async fn check(backend: &Backend, tool: &str, arguments: &Value) -> crate::Result<Option<String>> {
    backend
        .undeclared_key_refusal(None, &[], tool, arguments)
        .await
}

/// An undeclared key on the fixture's `edit` tool.
fn undeclared() -> Value {
    json!({"edits": [], "zzinvented": 1})
}

/// Run `fut` under a local Prometheus recorder, on a paused clock or not.
fn metered<T>(paused: bool, fut: impl std::future::Future<Output = T>) -> (T, String) {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let out = telemetry_metrics::with_local_recorder(&recorder, || {
        let mut rt = tokio::runtime::Builder::new_current_thread();
        rt.enable_all().start_paused(paused);
        rt.build().expect("runtime").block_on(fut)
    });
    (out, handle.render())
}

/// The value of `mcp_input_schema_events_total{kind="<label>"}` (no reason).
fn kind(rendered: &str, label: &str) -> u64 {
    let needle = format!("kind=\"{label}\"");
    rendered
        .lines()
        .filter(|l| l.starts_with("mcp_input_schema_events_total{"))
        .filter(|l| l.contains(&needle) && !l.contains("reason="))
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// F13-T5: a hanging list under a paused clock. The check returns at
/// `timeout` + e with e < `LIST_FILL_WAIT_GRACE`, so the fill's inner bound
/// fired, not the waiter's outer one. `closed` returns the timeout as a failed
/// dispatch would (A3) and `standard` forwards; each counts
/// `input_schema_fetch_failed` once. Red on
/// base: no fetch, so the check returns at once and `closed` forwards.
/// Mutant M4 (drop the inner timeout) makes the outer bound fire at
/// `timeout` + grace, which the upper-bound assertion catches.
#[test]
fn f13_t5_hanging_list_is_bounded_by_the_inner_timeout() {
    for (mode, expected) in [
        (InputSchemaEnforcement::Closed, Err(true)),
        (InputSchemaEnforcement::Standard, Ok(None)),
    ] {
        let ((out, elapsed), rendered) = metered(true, async move {
            let lister = Lister::new(Mode::Hang);
            let backend = backend(mode, &no_breaker(), &lister);
            let started = tokio::time::Instant::now();
            let limit = CALL_TIMEOUT + LIST_FILL_WAIT_GRACE + Duration::from_secs(5);
            let out = tokio::time::timeout(limit, check(&backend, "edit", &undeclared()))
                .await
                .expect("the check was not bounded");
            let timed_out = |e| matches!(e, crate::Error::BackendTimeout(_));
            (out.map_err(timed_out), started.elapsed())
        });
        assert_eq!(out, expected);
        assert!(elapsed >= CALL_TIMEOUT, "{elapsed:?}");
        assert!(elapsed < CALL_TIMEOUT + LIST_FILL_WAIT_GRACE, "{elapsed:?}");
        assert_eq!(
            kind(&rendered, "input_schema_fetch_failed"),
            1,
            "{rendered}"
        );
    }
}

/// F13-T5b: after a timed-out fill, a second cold call within the cooldown
/// sends no `tools/list` and fails at once as the timeout did (A3). Counts one
/// `fetch_failed` (call 1) and one `fill_cooldown` (call 2). Red on base: no
/// fetch at all; without the inner timeout (M4) call 1 never stamps in time.
#[test]
fn f13_t5b_a_timed_out_fill_makes_the_next_call_fail_fast() {
    let ((second, lists, elapsed), rendered) = metered(true, async {
        let lister = Lister::new(Mode::Hang);
        let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
        let first = check(&backend, "edit", &undeclared()).await;
        assert!(
            matches!(first, Err(crate::Error::BackendTimeout(_))),
            "{first:?}"
        );
        let started = tokio::time::Instant::now();
        let second = check(&backend, "edit", &undeclared()).await;
        let second = second.map_err(|e| crate::backend::fill_check::is_transport_failure(&e));
        (second, lister.lists(), started.elapsed())
    });
    assert_eq!(second, Err(true));
    assert_eq!(lists, 1, "call 2 sent a list inside the cooldown");
    assert_eq!(elapsed, Duration::ZERO, "call 2 waited");
    assert_eq!(
        kind(&rendered, "input_schema_fetch_failed"),
        1,
        "{rendered}"
    );
    assert_eq!(
        kind(&rendered, "input_schema_fill_cooldown"),
        1,
        "{rendered}"
    );
}

/// F13-T5c: a caller that disconnects mid-drain (its future dropped at
/// `timeout / 2`) stamps nothing: the next call sends exactly one list and
/// is judged. Counts `fill_cancelled` once and neither `fetch_failed` nor
/// `fill_cooldown`. Red on base: no fetch. Mutant M5d (stamp on `Pending`)
/// makes call 2 hit the cooldown.
#[test]
fn f13_t5c_a_cancelled_fill_does_not_stamp() {
    let ((second, lists), rendered) = metered(true, async {
        let lister = Lister::new(Mode::Hang);
        let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
        let dropped =
            tokio::time::timeout(CALL_TIMEOUT / 2, check(&backend, "edit", &undeclared())).await;
        assert!(dropped.is_err(), "call 1 finished before it was dropped");
        lister.set(Mode::Serve);
        let second = check(&backend, "edit", &undeclared()).await;
        (second.expect("no refusal"), lister.lists())
    });
    assert!(
        second.is_some_and(|t| t.contains("zzinvented")),
        "call 2 was not judged"
    );
    assert_eq!(lists, 2, "call 2 did not lead a fresh drain");
    assert_eq!(
        kind(&rendered, "input_schema_fill_cancelled"),
        1,
        "{rendered}"
    );
    assert_eq!(
        kind(&rendered, "input_schema_fetch_failed"),
        0,
        "{rendered}"
    );
    assert_eq!(
        kind(&rendered, "input_schema_fill_cooldown"),
        0,
        "{rendered}"
    );
}

/// F13-T5d, GUARD row (green on base): a discovery fill (`DrainBudget`) whose
/// list takes `timeout` + 5 s still stores, and it drains even with the
/// slot's breaker open. Proven by mutants M4b (apply the call timeout to
/// every fill) and M11d (admit `DrainBudget` fills too).
#[tokio::test(start_paused = true)]
async fn f13_t5d_a_discovery_fill_is_not_bounded_by_the_call_timeout() {
    let lister = Lister::new(Mode::Serve);
    *lister.sleep_per_page.lock() = CALL_TIMEOUT + Duration::from_secs(5);
    let backend = backend(
        InputSchemaEnforcement::Closed,
        &hair_trigger(Duration::from_secs(3600)),
        &lister,
    );
    backend.trip_circuit_breaker_for_test();
    let tools = backend
        .get_tools_shared()
        .await
        .expect("the discovery fill");
    assert_eq!(tools.len(), 1);
    assert!(
        backend.has_cached_tools(),
        "the discovery fill did not store"
    );
}

/// F13-T6: after a failed fill, a cold call within `LIST_FILL_COOLDOWN` sends
/// no `tools/list`; once the window has passed, one does. Red on base: no
/// fetch at all. Mutant M5 (no stamp) sends the second list early.
#[tokio::test(start_paused = true)]
async fn f13_t6_a_failed_fill_holds_the_slot_for_the_cooldown() {
    let lister = Lister::new(Mode::Fail);
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    let unavailable = Some(TEXT_UNAVAILABLE.to_owned());
    assert_eq!(
        check(&backend, "edit", &undeclared()).await.expect("ok"),
        unavailable
    );
    tokio::time::advance(LIST_FILL_COOLDOWN.saturating_sub(Duration::from_millis(1))).await;
    assert_eq!(
        check(&backend, "edit", &undeclared()).await.expect("ok"),
        unavailable
    );
    assert_eq!(lister.lists(), 1, "a list went out inside the cooldown");
    tokio::time::advance(Duration::from_millis(2)).await;
    let _ = check(&backend, "edit", &undeclared()).await;
    assert_eq!(lister.lists(), 2, "no list after the cooldown");
}

/// F13-T6b: 16 concurrent cold calls against a failing list send exactly one
/// `tools/list`: the waiters wake inside the fill and meet the cooldown
/// there. Red on base: zero lists. Mutant M5 (check outside the closure)
/// lets each woken waiter lead its own drain.
#[tokio::test(start_paused = true)]
async fn f13_t6b_concurrent_cold_calls_on_a_failing_list_send_one() {
    let lister = Lister::new(Mode::Fail);
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    let args = undeclared();
    let calls = (0..16).map(|_| check(&backend, "edit", &args));
    let results = futures::future::join_all(calls).await;
    assert_eq!(lister.lists(), 1);
    let unavailable = Some(TEXT_UNAVAILABLE.to_owned());
    assert!(results.into_iter().all(|r| r.expect("ok") == unavailable));
}

/// F13-T6c: a failed resources fill leaves the tools family alone: a cold
/// tools call right after it still sends one `tools/list`. Red on base: no
/// fetch. Mutant M5 (cooldown for every family) makes the tools fill fail
/// fast.
#[tokio::test(start_paused = true)]
async fn f13_t6c_a_resources_failure_does_not_cool_the_tools_slot() {
    let lister = Lister::new(Mode::Serve);
    lister.fail_resources.store(true, Ordering::SeqCst);
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    assert!(backend.get_resources_shared().await.is_err());
    let judged = check(&backend, "edit", &undeclared()).await.expect("ok");
    assert!(judged.is_some_and(|t| t.contains("zzinvented")));
    assert_eq!(lister.lists(), 1);
}

/// F13-T8: a `Shared` slot and a caller credential: no fetch (A3), text U
/// under `closed`, `input_schema_fetch_skipped_a3` counted. Red on base: the
/// call is forwarded (`None`) and the label does not exist. Mutant M7 (drop
/// the A3 guard) sends a list.
#[test]
fn f13_t8_shared_slot_with_a_credential_never_fetches() {
    let ((out, lists), rendered) = metered(true, async {
        let lister = Lister::new(Mode::Serve);
        let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
        let headers = [("Authorization".to_owned(), "Bearer caller".to_owned())];
        let out = backend
            .undeclared_key_refusal(None, &headers, "edit", &undeclared())
            .await;
        (out.expect("ok"), lister.lists())
    });
    assert_eq!(out, Some(TEXT_UNAVAILABLE.to_owned()));
    assert_eq!(
        lists, 0,
        "a Shared slot was listed for a credentialed caller"
    );
    assert_eq!(
        kind(&rendered, "input_schema_fetch_skipped_a3"),
        1,
        "{rendered}"
    );
    assert_eq!(
        kind(&rendered, "input_schema_refused_unavailable"),
        1,
        "{rendered}"
    );
}

/// What lands on the slot while a check-site drain is on the wire.
#[derive(Clone, Copy, Debug)]
enum Voider {
    /// `invalidate_if` on the cold slot: the generation moves, slot stays cold.
    Invalidate,
    /// A direct-route list lands through `CachedMetadata::replace`.
    Replace,
    /// Nothing: the control arm.
    Nothing,
}

/// Run the check on `tool` while a barrier holds the drain on the wire, and
/// apply `voider` before releasing it.
async fn voided_check(
    backend: &Backend,
    lister: &Lister,
    tool: &str,
    voider: Voider,
) -> Option<String> {
    let arguments = undeclared();
    let (out, ()) = tokio::join!(check(backend, tool, &arguments), async {
        lister.started.notified().await;
        match voider {
            Voider::Invalidate => backend.invalidate_tools_cache(),
            Voider::Replace => {
                backend
                    .remember_listed_tools(None, false, &[edit_tool()])
                    .await;
            }
            Voider::Nothing => {}
        }
        lister.release.notify_one();
    });
    out.expect("no failsafe refusal")
}

/// F13-T7c: an invalidation lands while the drain is on the wire. The call is
/// judged from the list the fill returned (the key refusal, not text U); the
/// slot stays cold; `fetched` +1, `fetch_failed` +0; and the voided store
/// stamps the cooldown: a second cold call within the window sends no list
/// and gets text U, and after the window one list goes out. Red on base: no
/// fetch. Mutants M6b (re-read the slot) and M5b/M5c (no stamp on a void).
#[test]
fn f13_t7c_a_voided_store_is_judged_from_the_returned_list_and_stamps() {
    let ((first, cold, second, lists_in_window, lists_after), rendered) = metered(true, async {
        let lister = Lister::new(Mode::Barrier);
        let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
        let first = voided_check(&backend, &lister, "edit", Voider::Invalidate).await;
        let cold = backend.cached_tools_count() == 0;
        lister.set(Mode::Serve);
        let second = check(&backend, "edit", &undeclared()).await.expect("ok");
        let lists_in_window = lister.lists();
        tokio::time::advance(LIST_FILL_COOLDOWN).await;
        let _ = check(&backend, "edit", &undeclared()).await;
        (first, cold, second, lists_in_window, lister.lists())
    });
    assert!(
        first.as_deref().is_some_and(|t| t.contains("zzinvented")),
        "not judged from the returned list: {first:?}"
    );
    assert!(cold, "the voided store landed");
    assert_eq!(second, Some(TEXT_UNAVAILABLE.to_owned()));
    assert_eq!(lists_in_window, 1, "the void did not stamp the cooldown");
    assert_eq!(lists_after, 2, "no list after the cooldown");
    // One for the voided drain, one for the stored drain after the window.
    assert_eq!(kind(&rendered, "input_schema_fetched"), 2, "{rendered}");
    assert_eq!(
        kind(&rendered, "input_schema_fetch_failed"),
        0,
        "{rendered}"
    );
}

/// F13-T7d: an invented tool name, with the store voided mid-drain by an
/// invalidation or by a direct-route `replace`: `closed` refuses with text U,
/// never text A, because absence from a list the slot does not hold proves
/// nothing (`Completeness::Unknown`). The no-voider control gets text A.
/// New-API row: `Completeness` has no base counterpart. Proven by mutants
/// M6c (completeness without `ptr_eq`) and M6d (judge a void from the side
/// bit), which turn the voided arms into text A.
#[test]
fn f13_t7d_absence_from_a_voided_list_is_unavailable_not_absent() {
    for voider in [Voider::Invalidate, Voider::Replace, Voider::Nothing] {
        let (out, rendered) = metered(true, async move {
            let lister = Lister::new(Mode::Barrier);
            let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
            voided_check(&backend, &lister, "nosuch", voider).await
        });
        let (text, refused, other) = match voider {
            Voider::Nothing => (
                super::fill_check::text_absent("nosuch"),
                "input_schema_refused_absent",
                "input_schema_refused_unavailable",
            ),
            _ => (
                TEXT_UNAVAILABLE.to_owned(),
                "input_schema_refused_unavailable",
                "input_schema_refused_absent",
            ),
        };
        assert_eq!(out, Some(text), "{voider:?}");
        assert_eq!(kind(&rendered, refused), 1, "{voider:?}: {rendered}");
        assert_eq!(kind(&rendered, other), 0, "{voider:?}: {rendered}");
    }
}

/// Why a drain stopped early (the three `tools_truncated` causes).
#[derive(Clone, Copy, Debug)]
enum Stop {
    /// 33+ pages: the `LIST_MAX_PAGES` cap.
    PageCap,
    /// Page 2 repeats page 1's `nextCursor`.
    CursorRepeat,
    /// 10 s pages, past the 120 s `CACHE_LIST_DRAIN_BUDGET`.
    FillBudget,
}

/// A backend whose `tools/list` stops at `stop`; `edit` is never served.
/// `per_user` puts the caller on its own `PerUser` slot. The call timeout is
/// raised above the drain budget, so the budget, not the timeout, stops it.
fn truncating(
    stop: Stop,
    mode: InputSchemaEnforcement,
    per_user: bool,
) -> (Arc<Backend>, Option<&'static str>) {
    let lister = Lister::new(Mode::Serve);
    match stop {
        Stop::PageCap => lister.endless.store(true, Ordering::SeqCst),
        Stop::CursorRepeat => {
            let tool = |n: &str| json!({"name": n, "inputSchema": {"type": "object"}});
            *lister.pages.lock() = vec![
                (vec![tool("t0")], Some("c1")),
                (vec![tool("t1")], Some("c1")),
            ];
        }
        Stop::FillBudget => {
            lister.endless.store(true, Ordering::SeqCst);
            *lister.sleep_per_page.lock() = Duration::from_secs(10);
        }
    }
    let identity_propagation =
        per_user.then(|| crate::identity_propagation::IdentityPropagationConfig {
            strategy: crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
            audience: "f13".to_string(),
            required: true,
            session_mode: crate::identity_propagation::SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        });
    let config = BackendConfig {
        input_schema_enforcement: mode,
        timeout: Duration::from_secs(600),
        identity_propagation,
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "f13",
        config,
        &no_breaker(),
        Duration::from_secs(300),
    ));
    let wire = lister as Arc<dyn crate::transport::Transport>;
    if per_user {
        let binding = "alpha@f13".to_owned();
        backend.set_pooled_transport_for_test(&PoolKey::PerUser { binding }, wire);
        (backend, Some("alpha@f13"))
    } else {
        backend.set_transport_for_test(wire);
        (backend, None)
    }
}

/// F13-T10: a drain that stops structurally leaves a truncated slot, and a
/// tool not in the pages kept cannot be checked. One row per stop cause, on
/// a `Shared` slot (no credential) and on a `PerUser` slot. `closed`: text P
/// exactly as rendered from `LIST_MAX_PAGES` (no config key),
/// `input_schema_refused_truncated` +1. `standard`: forwarded,
/// `input_schema_truncated_forward` +1, `input_schema_unknown` +0. Red on
/// base: no fetch, the call is forwarded. Mutants M6 (forward truncated under
/// `closed`), M6e (hard-coded page count) and M10 (count it `unknown`).
#[test]
fn f13_t10_absence_from_a_truncated_list_is_its_own_outcome() {
    let modes = [
        InputSchemaEnforcement::Closed,
        InputSchemaEnforcement::Standard,
    ];
    for stop in [Stop::PageCap, Stop::CursorRepeat, Stop::FillBudget] {
        for per_user in [false, true] {
            for mode in modes {
                let (out, rendered) = metered(true, async move {
                    let (backend, binding) = truncating(stop, mode, per_user);
                    let headers = if per_user {
                        vec![("Authorization".to_owned(), "Bearer alpha".to_owned())]
                    } else {
                        Vec::new()
                    };
                    backend
                        .undeclared_key_refusal(binding, &headers, "edit", &undeclared())
                        .await
                        .expect("no failsafe refusal")
                });
                let row = format!("{stop:?} per_user={per_user} {mode:?}");
                if mode == InputSchemaEnforcement::Closed {
                    assert_eq!(out, Some(text_partial()), "{row}");
                    assert!(!text_partial().contains("input_schema_enforcement"));
                    let refused = kind(&rendered, "input_schema_refused_truncated");
                    assert_eq!(refused, 1, "{row}: {rendered}");
                } else {
                    assert_eq!(out, None, "{row}");
                    let forwarded = kind(&rendered, "input_schema_truncated_forward");
                    assert_eq!(forwarded, 1, "{row}: {rendered}");
                    assert_eq!(kind(&rendered, "input_schema_unknown"), 0, "{row}");
                }
            }
        }
    }
}

/// A half-open breaker on the shared slot: tripped, then past its reset.
async fn half_open(lister: &Arc<Lister>) -> Arc<Backend> {
    let reset = Duration::from_millis(200);
    let backend = backend(InputSchemaEnforcement::Closed, &hair_trigger(reset), lister);
    backend.trip_circuit_breaker_for_test();
    // The breaker reads the wall clock, so this sleep is real.
    tokio::time::sleep(Duration::from_millis(300)).await;
    backend
}

/// F13-T12d: a half-open breaker (`success_threshold` = 1), cold, `closed`,
/// an undeclared key: one successful fill closes it. One `tools/list` and no
/// dispatch, so only the fill could have closed it. Red on base: no fill,
/// the breaker stays half-open. Mutant M11c (no outcome recording).
#[tokio::test]
async fn f13_t12d_a_successful_fill_closes_a_half_open_breaker() {
    let lister = Lister::new(Mode::Serve);
    let backend = half_open(&lister).await;
    let judged = check(&backend, "edit", &undeclared())
        .await
        .expect("admitted");
    assert!(judged.is_some_and(|t| t.contains("zzinvented")));
    assert_eq!(lister.lists(), 1);
    let state = backend.circuit_breaker_stats().state;
    assert_eq!(state, crate::failsafe::CircuitState::Closed);
}

/// F13-T12f: a drain that succeeds but whose store an invalidation voids
/// still records success: the half-open breaker closes. New-API row (needs
/// the barrier fill): proven by mutant M11c, not red on base.
#[tokio::test]
async fn f13_t12f_a_voided_drain_still_records_success() {
    let lister = Lister::new(Mode::Barrier);
    let backend = half_open(&lister).await;
    let judged = voided_check(&backend, &lister, "edit", Voider::Invalidate).await;
    assert!(judged.is_some_and(|t| t.contains("zzinvented")));
    assert_eq!(backend.cached_tools_count(), 0, "the voided store landed");
    let state = backend.circuit_breaker_stats().state;
    assert_eq!(state, crate::failsafe::CircuitState::Closed);
}

/// F13-T12h, GUARD row (green on base: the dispatch returns `CircuitOpen`):
/// with a fill cooldown active and the breaker open, the check surfaces
/// `CircuitOpen`, not text U. Proven by mutant M11f (cooldown before the
/// breaker), which answers with text U.
#[tokio::test(start_paused = true)]
async fn f13_t12h_an_open_breaker_outranks_the_cooldown() {
    let lister = Lister::new(Mode::Fail);
    let mut failsafe = hair_trigger(Duration::from_secs(3600));
    failsafe.circuit_breaker.failure_threshold = 5;
    let backend = backend(InputSchemaEnforcement::Closed, &failsafe, &lister);
    let first = check(&backend, "edit", &undeclared())
        .await
        .expect("admitted");
    assert_eq!(
        first,
        Some(TEXT_UNAVAILABLE.to_owned()),
        "the cooldown is stamped"
    );
    backend.trip_circuit_breaker_for_test();
    let second = check(&backend, "edit", &undeclared()).await;
    assert!(
        matches!(second, Err(crate::Error::CircuitOpen { .. })),
        "{second:?}"
    );
    assert_eq!(lister.lists(), 1);
}

/// F13-T12i: a cooldown hit spends no limiter token. Two tokens: the failed
/// fill spends one and stamps; a second cold call inside the window sends no
/// list and spends none; after the window a declared-key call fills with the
/// token left over. Red on base: no fill and no cooldown (0 lists). Mutant
/// M11h (token before the cooldown) spends the second token on the cooldown
/// hit, so the third call is refused `RateLimited`.
#[tokio::test(start_paused = true)]
async fn f13_t12i_a_cooldown_hit_spends_no_token() {
    let lister = Lister::new(Mode::Fail);
    let mut failsafe = no_breaker();
    failsafe.rate_limit.enabled = true;
    failsafe.rate_limit.requests_per_second = 1;
    failsafe.rate_limit.burst_size = 2;
    let backend = backend(InputSchemaEnforcement::Closed, &failsafe, &lister);
    let unavailable = Some(TEXT_UNAVAILABLE.to_owned());
    assert_eq!(
        check(&backend, "edit", &undeclared()).await.expect("ok"),
        unavailable
    );
    assert_eq!(
        check(&backend, "edit", &undeclared()).await.expect("ok"),
        unavailable
    );
    assert_eq!(lister.lists(), 1, "the cooldown hit sent a list");
    tokio::time::advance(LIST_FILL_COOLDOWN).await;
    lister.set(Mode::Serve);
    let declared = check(&backend, "edit", &json!({"edits": []})).await;
    assert!(matches!(declared, Ok(None)), "{declared:?}");
    assert_eq!(lister.lists(), 2);
}

#[path = "f13_a3_tests.rs"]
mod a3;
