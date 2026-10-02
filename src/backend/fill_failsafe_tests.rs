// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1300: every list fill obeys the slot's failsafe.
//!
//! A request-triggered fill (discovery, search and list, resources, resource
//! templates, prompts) passes the breaker, takes a limiter token and records
//! its outcome, as the R2 check-site fill already does. A startup warm-up fill
//! is recorded but not admitted. Its success resets an Open breaker only when
//! every failure since the breaker last closed came from warm-up.
//!
//! A child of the F13 fill tests, so it shares their `Lister` fixture.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};

use super::{LIST_FILL_COOLDOWN, Lister, Mode, backend, hair_trigger, half_open, metered};
use crate::config::{BackendConfig, FailsafeConfig, InputSchemaEnforcement};
use crate::failsafe::CircuitState;
use crate::protocol::{JsonRpcResponse, RequestId};

fn state(backend: &crate::backend::Backend) -> CircuitState {
    backend.circuit_breaker_stats().state
}

fn is_circuit_open(error: &crate::Error) -> bool {
    matches!(error, crate::Error::CircuitOpen { .. })
}

/// One token, refilled once a second: the second admitted fill in a burst is
/// refused.
fn one_token() -> FailsafeConfig {
    let mut failsafe = hair_trigger(Duration::from_secs(3600));
    failsafe.rate_limit.enabled = true;
    failsafe.rate_limit.requests_per_second = 1;
    failsafe.rate_limit.burst_size = 1;
    failsafe
}

/// The value of `mcp_backend_requests_total{backend="f13",status="<status>"}`.
fn requests(rendered: &str, status: &str) -> u64 {
    let needle = format!("status=\"{status}\"");
    rendered
        .lines()
        .filter(|l| l.starts_with("mcp_backend_requests_total{"))
        .filter(|l| l.contains("backend=\"f13\"") && l.contains(&needle))
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

/// T1 (AC1): an open breaker refuses a discovery fill before any list is sent,
/// and the refusal is `CircuitOpen`. Red on base: `DrainBudget` skips the
/// breaker. Mutant M1.
#[tokio::test]
async fn open_breaker_refuses_a_discovery_fill_without_a_probe() {
    let lister = Lister::new(Mode::Serve);
    let backend = backend(
        InputSchemaEnforcement::Closed,
        &hair_trigger(Duration::from_secs(3600)),
        &lister,
    );
    backend.trip_circuit_breaker_for_test();
    let error = backend.get_tools_shared().await.expect_err("refused");
    assert!(is_circuit_open(&error), "got {error}");
    assert_eq!(lister.lists(), 0, "a list reached an open breaker");
}

/// T9 (issue fail-fast): the search and list path's fill sends no list to an
/// open breaker. Mutant M1.
#[tokio::test]
async fn the_search_fill_on_an_open_breaker_sends_no_list() {
    let lister = Lister::new(Mode::Serve);
    let backend = backend(
        InputSchemaEnforcement::Closed,
        &hair_trigger(Duration::from_secs(3600)),
        &lister,
    );
    backend.trip_circuit_breaker_for_test();
    let error = backend
        .get_tools_for_binding(None, &[])
        .await
        .expect_err("refused");
    assert!(is_circuit_open(&error), "got {error}");
    assert_eq!(lister.lists(), 0);
}

/// T2 (AC1): with one token, a second cold discovery fill is `RateLimited`
/// and sends nothing; the refusal stamps no F13 cooldown, so once a token is
/// back the next fill lists. Red on base: no token is taken. Mutant M2.
#[tokio::test]
async fn one_token_admits_one_cold_discovery_fill() {
    let lister = Lister::new(Mode::Serve);
    let backend = backend(InputSchemaEnforcement::Closed, &one_token(), &lister);
    // A prompts fill spends the one token (its answer is unusable here, which
    // counts as reachable and stamps no tools cooldown).
    drop(backend.get_prompts_shared().await);
    let error = backend.get_tools_shared().await.expect_err("no token");
    assert!(matches!(error, crate::Error::RateLimited(_)), "got {error}");
    assert_eq!(lister.lists(), 0, "a refused fill sent a list");
    // The limiter reads the wall clock: this sleep is real.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    backend.get_tools_shared().await.expect("a token is back");
    assert_eq!(lister.lists(), 1, "the refusal stamped a cooldown");
}

/// T3 (AC2): a discovery fill that cannot reach the backend opens a
/// hair-trigger breaker. Red on base: nothing is recorded. Mutant M3.
#[tokio::test]
async fn a_failing_discovery_fill_opens_the_breaker() {
    let lister = Lister::new(Mode::Down);
    let backend = backend(
        InputSchemaEnforcement::Closed,
        &hair_trigger(Duration::from_secs(3600)),
        &lister,
    );
    backend.get_tools_shared().await.expect_err("down");
    assert_eq!(state(&backend), CircuitState::Open);
}

/// T4 (AC2): a successful discovery fill closes a half-open breaker. Red on
/// base: nothing is recorded. Mutant M3.
#[tokio::test]
async fn a_successful_discovery_fill_closes_a_half_open_breaker() {
    let lister = Lister::new(Mode::Serve);
    let backend = half_open(&lister).await;
    backend.get_tools_shared().await.expect("fill");
    assert_eq!(state(&backend), CircuitState::Closed);
}

/// T8 (AC1): the resources, resource-template and prompts fills obey the
/// breaker too. Red on base. Mutant M1.
#[tokio::test]
async fn resources_prompts_and_templates_fills_obey_the_breaker() {
    let lister = Lister::new(Mode::Serve);
    let backend = backend(
        InputSchemaEnforcement::Closed,
        &hair_trigger(Duration::from_secs(3600)),
        &lister,
    );
    backend.trip_circuit_breaker_for_test();
    let resources = backend.get_resources_shared().await.map(|_| ());
    let templates = backend.get_resource_templates_shared().await.map(|_| ());
    let prompts = backend.get_prompts_shared().await.map(|_| ());
    for (family, outcome) in [
        ("resources", resources),
        ("resource templates", templates),
        ("prompts", prompts),
    ] {
        let error = outcome.expect_err(family);
        assert!(is_circuit_open(&error), "{family}: got {error}");
    }
}

/// A backend whose `tools/list` answers a JSON-RPC throttle: reachable, told
/// to slow down.
struct Throttler;

#[async_trait]
impl crate::transport::Transport for Throttler {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let permission = crate::transport::ResendPermission::Permitted;
        self.request_with_headers(method, params, &[], None, permission)
            .await
    }

    async fn request_with_headers(
        &self,
        method: &str,
        _params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            return Ok(JsonRpcResponse::error(
                Some(id),
                -32000,
                "rate limit exceeded",
            ));
        }
        if method == "throttled/call" {
            let text = json!([{"type": "text", "text": "rate limit exceeded"}]);
            return Ok(JsonRpcResponse::success(
                id,
                json!({"isError": true, "content": text}),
            ));
        }
        Ok(JsonRpcResponse::success(id, json!({})))
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

/// A half-open breaker on a throttling backend.
async fn half_open_throttled() -> Arc<crate::backend::Backend> {
    let config = BackendConfig {
        input_schema_enforcement: InputSchemaEnforcement::Closed,
        ..BackendConfig::default()
    };
    let backend = Arc::new(crate::backend::Backend::new(
        "f13",
        config,
        &hair_trigger(Duration::from_millis(200)),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Throttler) as Arc<dyn crate::transport::Transport>);
    backend.trip_circuit_breaker_for_test();
    // The breaker reads the wall clock, so this sleep is real.
    tokio::time::sleep(Duration::from_millis(300)).await;
    backend
}

/// NFR.WORKLOAD.1: with its keys built once per slot, a dispatched request
/// still lands in the series the macros wrote: one answered call counts as
/// `ok`, one throttled answer as `rate_limited`, and both record a duration,
/// each labelled with the backend.
#[test]
fn a_dispatched_request_lands_in_the_backend_request_series() {
    let ((), rendered) = metered(false, async {
        let backend = crate::backend::Backend::new(
            "f13",
            BackendConfig::default(),
            &hair_trigger(Duration::from_secs(3600)),
            Duration::from_secs(300),
        );
        backend.set_transport_for_test(Arc::new(Throttler) as Arc<dyn crate::transport::Transport>);
        backend.request("ping", None).await.expect("answered");
        backend
            .request("throttled/call", None)
            .await
            .expect("answered");
    });
    assert_eq!(requests(&rendered, "ok"), 1, "{rendered}");
    assert_eq!(requests(&rendered, "rate_limited"), 1, "{rendered}");
    let durations = rendered
        .lines()
        .find(|l| l.starts_with("mcp_backend_request_duration_seconds_count{backend=\"f13\"}"));
    assert_eq!(
        durations.and_then(|l| l.rsplit(' ').next()),
        Some("2"),
        "{rendered}"
    );
}

/// T5 (amended AC2): a throttle answered to the R2 check-site fill is neither
/// a success nor a failure, so a half-open breaker stays half-open. Red on
/// base: the check site records it as a success and closes the breaker.
/// Mutant M4.
#[tokio::test]
async fn a_throttled_check_site_list_is_neither_success_nor_failure() {
    let backend = half_open_throttled().await;
    drop(super::check(&backend, "edit", &super::undeclared()).await);
    assert_eq!(state(&backend), CircuitState::HalfOpen);
}

/// T5b (amended AC2): the same throttle on a discovery fill leaves the breaker
/// half-open and is counted as rate limited. Red on base: nothing is recorded
/// or counted. Mutant M4.
#[test]
fn a_throttled_discovery_list_is_neither_success_nor_failure() {
    let (state_after, rendered) = metered(false, async {
        let backend = half_open_throttled().await;
        drop(backend.get_tools_shared().await);
        state(&backend)
    });
    assert_eq!(state_after, CircuitState::HalfOpen);
    assert_eq!(requests(&rendered, "rate_limited"), 1, "{rendered}");
}

/// T6 (amended AC2): an answer the gateway cannot use is reachability: a
/// half-open breaker closes, and the answer is counted as unusable. Red on
/// base: nothing is recorded or counted. Mutant M5.
#[test]
fn an_unusable_list_records_reachability_and_is_counted() {
    let (state_after, rendered) = metered(false, async {
        let lister = Lister::new(Mode::Serve);
        let backend = half_open(&lister).await;
        lister.set(Mode::Fail);
        backend.get_tools_shared().await.expect_err("unusable");
        state(&backend)
    });
    assert_eq!(state_after, CircuitState::Closed);
    assert_eq!(requests(&rendered, "list_unusable"), 1, "{rendered}");
}

/// T7 (AC1 as amended): a warm-up fill spends no token. Red on base: the
/// stub lists nothing. Mutant M6 (warm-up through `DrainBudget`).
#[tokio::test]
async fn warm_up_spends_no_token() {
    let lister = Lister::new(Mode::Serve);
    let backend = backend(InputSchemaEnforcement::Closed, &one_token(), &lister);
    drop(backend.get_prompts_shared().await); // spends the one token
    let tools = backend.warm_tools().await.expect("warm-up needs no token");
    assert_eq!(tools.len(), 1);
    assert_eq!(lister.lists(), 1);
}

/// T10 (AC2), GUARD row: a warm-up that cannot reach the backend opens a
/// hair-trigger breaker. The warm-up fill is new, so on base this fails only
/// at the stub's setup (it cannot fail); proven by mutant M7 (no recording).
#[tokio::test]
async fn a_failing_warm_up_opens_the_breaker() {
    let lister = Lister::new(Mode::Down);
    let backend = backend(
        InputSchemaEnforcement::Closed,
        &hair_trigger(Duration::from_secs(3600)),
        &lister,
    );
    backend.warm_tools().await.expect_err("down");
    assert_eq!(state(&backend), CircuitState::Open);
}

/// T12, GUARD row for a behaviour this design introduces: a warm-up success
/// resets a breaker that only warm-up failures opened, so a slow start is not
/// refused after its catalogue is cached. On base it fails only at the stub's
/// setup; proven by mutant M8 (no reset on a warm-up success).
#[tokio::test(start_paused = true)]
async fn a_warm_up_success_clears_a_breaker_its_own_failures_tripped() {
    let lister = Lister::new(Mode::Down);
    let backend = backend(
        InputSchemaEnforcement::Closed,
        &hair_trigger(Duration::from_secs(3600)),
        &lister,
    );
    backend.warm_tools().await.expect_err("down");
    // Past the F13 fill cooldown the failure stamped (a tokio clock).
    tokio::time::advance(LIST_FILL_COOLDOWN + Duration::from_secs(1)).await;
    lister.set(Mode::Serve);
    backend.warm_tools().await.expect("up");
    assert_eq!(state(&backend), CircuitState::Closed);
}

/// T11, GUARD row for a behaviour this design introduces: a warm-up success
/// does not clear a breaker a request failure tripped; the normal half-open
/// probe decides. The warm-up still lists (it is not admitted). Not red-first
/// on the defect: on base it fails only at the stub's "warm-up listed"
/// precondition. Proven by mutant M9 (reset without the provenance check).
#[tokio::test]
async fn a_warm_up_success_does_not_clear_a_breaker_tripped_by_requests() {
    let lister = Lister::new(Mode::Down);
    let backend = backend(
        InputSchemaEnforcement::Closed,
        &hair_trigger(Duration::from_secs(3600)),
        &lister,
    );
    backend
        .request("tools/list", None)
        .await
        .expect_err("a request failure");
    assert_eq!(state(&backend), CircuitState::Open);
    lister.set(Mode::Serve);
    let before = lister.lists();
    backend.warm_tools().await.expect("warm-up lists");
    assert_eq!(lister.lists(), before + 1, "the warm-up did not list");
    assert_eq!(state(&backend), CircuitState::Open);
}

/// T13, GUARD row: a request that fails the half-open probe reopens the
/// breaker and marks it as request-tripped, so a later warm-up success still
/// cannot clear it. Proven by mutant M10 (set the flag only from Closed).
#[tokio::test(start_paused = true)]
async fn a_request_failing_the_half_open_probe_keeps_warm_up_from_clearing_it() {
    let lister = Lister::new(Mode::Down);
    let backend = backend(
        InputSchemaEnforcement::Closed,
        &hair_trigger(Duration::from_millis(1)),
        &lister,
    );
    backend.warm_tools().await.expect_err("warm-up trips it");
    assert_eq!(state(&backend), CircuitState::Open);
    // The breaker reads the wall clock and has no test clock seam, while the
    // F13 cooldown below needs the paused tokio clock. A 1 ms reset needs only
    // this short blocking wait to reach half-open.
    std::thread::sleep(Duration::from_millis(5));
    backend
        .request("tools/list", None)
        .await
        .expect_err("the half-open probe fails");
    assert_eq!(state(&backend), CircuitState::Open);
    tokio::time::advance(LIST_FILL_COOLDOWN + Duration::from_secs(1)).await;
    lister.set(Mode::Serve);
    backend.warm_tools().await.expect("warm-up lists");
    assert_eq!(state(&backend), CircuitState::Open);
}

/// T14, GUARD row: a breaker tripped by a request-triggered FILL (not only a
/// dispatch) is also kept from a warm-up reset. Proven by mutant M11 (fills
/// record their failures without the provenance flag).
#[tokio::test(start_paused = true)]
async fn a_warm_up_success_does_not_clear_a_breaker_tripped_by_a_discovery_fill() {
    let lister = Lister::new(Mode::Down);
    let backend = backend(
        InputSchemaEnforcement::Closed,
        &hair_trigger(Duration::from_secs(3600)),
        &lister,
    );
    backend
        .get_tools_shared()
        .await
        .expect_err("a fill failure");
    assert_eq!(state(&backend), CircuitState::Open);
    tokio::time::advance(LIST_FILL_COOLDOWN + Duration::from_secs(1)).await;
    lister.set(Mode::Serve);
    backend.warm_tools().await.expect("warm-up lists");
    assert_eq!(state(&backend), CircuitState::Open);
}

/// #2219: a breaker the health probe tripped (`trip_circuit_breaker`, the
/// unserved escalation) is not warm-up's own trip, so a warm-up success must
/// leave it Open. Red on base: the probe's trip set no provenance flag.
#[tokio::test]
async fn a_warm_up_success_does_not_clear_a_breaker_the_health_probe_tripped() {
    let lister = Lister::new(Mode::Serve);
    let backend = backend(
        InputSchemaEnforcement::Closed,
        &hair_trigger(Duration::from_secs(3600)),
        &lister,
    );
    backend.trip_circuit_breaker_for_test();
    assert_eq!(state(&backend), CircuitState::Open);
    let before = lister.lists();
    backend.warm_tools().await.expect("warm-up lists");
    assert_eq!(lister.lists(), before + 1, "the warm-up did not list");
    assert_eq!(state(&backend), CircuitState::Open);
}
