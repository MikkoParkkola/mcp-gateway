// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend with per-user sessions only, listed by a cold caller over
//! `/mcp`: the caller's own view is warmed under its own grant, within one
//! capped deadline, and the shared slot's schema is never shown. Uses the
//! parent's fixture.
use super::*;

/// The listing's warm of a caller's cold view is scoped by the caller's own
/// grant: a backend the key does not grant is never reached for that caller,
/// even when one of its tools is surfaced and the caller's view of it is cold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tools_list_never_warms_a_backend_the_grant_excludes_http() {
    let fx = fixture_for(
        operator_granted(&["elsewhere"]),
        &Binding::Connected,
        |_| {},
    )
    .await;
    let before = fx.gateway.requests().len();
    let answer = rpc(&fx, 1, "tools/list", json!({})).await;
    assert!(
        answer.get("result").is_some(),
        "premise: tools/list answered: {answer}"
    );
    let reached: Vec<_> = fx.gateway.requests().into_iter().skip(before).collect();
    assert!(
        reached.is_empty(),
        "tools/list reached a backend the caller's grant excludes: {reached:?}"
    );
}

/// The surfaced entries in a `tools/list` answer whose trust card names
/// `server`.
fn surfaced_on<'a>(answer: &'a Value, server: &str) -> Vec<&'a Value> {
    answer
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|t| t.pointer("/trustCard/serverId") == Some(&json!(format!("backend:{server}"))))
        .collect()
}

/// Whether an entry carries the shared slot's schema B (a `folder` property).
fn is_shared_schema(entry: &Value) -> bool {
    entry.pointer("/inputSchema/properties/folder").is_some()
}

/// SHARED.5 (`tools/list` only): a cold caller's first listing of a backend
/// with per-user sessions only shows the caller's own schema, from one fill of
/// its own slot, and never the shared slot's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cold_callers_first_tools_list_shows_its_own_schema_http() {
    let fx = fixture().await;
    assert!(
        !listed_schema_has_folder(&fx, 1).await,
        "a cold caller was shown the shared schema"
    );
    assert_eq!(
        fx.gateway.lists_to(BACKEND),
        1,
        "one fill of the caller's own slot"
    );
}

/// SHARED.5 (overlap): two overlapping listings of one cold caller never show
/// the shared schema, and the caller's slot is filled once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlapping_listings_of_a_cold_caller_fill_once_http() {
    let fx = fixture().await;
    let (a, b) = tokio::join!(
        rpc(&fx, 1, "tools/list", json!({})),
        rpc(&fx, 2, "tools/list", json!({}))
    );
    for answer in [&a, &b] {
        assert!(
            !surfaced_on(answer, BACKEND)
                .into_iter()
                .any(is_shared_schema),
            "a listing showed the shared schema: {answer}"
        );
    }
    assert_eq!(
        fx.gateway.lists_to(BACKEND),
        1,
        "the overlapping listings filled twice"
    );
}

/// The router over both managed backends, [`TOOL`] surfaced on each.
async fn fixture_two() -> Fx {
    let auth = sole_operator();
    let gateway = DirectAccountGateway::with_second(
        auth.clone(),
        &Binding::Connected,
        Second::PersonalAccount,
    );
    two_surfaced(gateway, &auth).await
}

/// The second backend lists [`PERSONAL_TOOL`]: a second surfaced `read`
/// would collide with the first and be skipped.
const PERSONAL_TOOL: &str = "note";

/// The router over [`BACKEND`] and [`PERSONAL_BACKEND`], each with its own
/// surfaced tool.
async fn two_surfaced(gateway: DirectAccountGateway, auth: &AuthConfig) -> Fx {
    gateway.name_list_tool_on(PERSONAL_BACKEND, PERSONAL_TOOL);
    fixture_on(
        gateway,
        auth,
        &[(BACKEND, TOOL), (PERSONAL_BACKEND, PERSONAL_TOOL)],
        |_| {},
    )
    .await
}

/// The fill bound of `server`.
fn fill_bound(fx: &Fx, server: &str) -> std::time::Duration {
    fx.gateway
        .backends()
        .get(server)
        .expect("the backend")
        .tools_fill_bound()
}

/// SHARED.5 (deadline, inside the bound): two cold backends, one slow but
/// inside its own fill bound. The listing waits for it: both backends' own
/// tools are in the same response, each from one fill.
#[tokio::test(start_paused = true)]
async fn a_slow_backend_inside_its_bound_is_in_the_same_response_http() {
    let fx = fixture_two().await;
    let bound = fill_bound(&fx, PERSONAL_BACKEND);
    fx.gateway.delay_lists_on(PERSONAL_BACKEND, bound / 2);
    let first = rpc(&fx, 1, "tools/list", json!({})).await;
    for server in [BACKEND, PERSONAL_BACKEND] {
        assert!(
            surfaced_on(&first, server)
                .iter()
                .any(|t| !is_shared_schema(t)),
            "{server}'s own tool was not in the first response: {first}"
        );
        assert_eq!(fx.gateway.lists_to(server), 1, "{server}: one fill");
    }
}

/// Whether `rx` holds a change nudge for `server`, draining it.
fn nudged(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::backend::tools_nudge::ToolsNudge>,
    server: &str,
) -> bool {
    let mut seen = false;
    while let Ok(nudge) = rx.try_recv() {
        if let crate::backend::tools_nudge::ToolsNudge::Backend { name, .. } = nudge {
            seen |= name == server;
        }
    }
    seen
}

/// SHARED.5 (deadline, past the cap): both backends' fill bound is past the
/// listing's 30 s cap, and the slow one answers at 40 s. The first listing
/// returns at the cap with the fast backend's own tool and without the slow
/// one's. The slow fill finishes on its own lease and stores into the
/// caller's slot, which sends the change nudge the drain announces as
/// `tools/list_changed`; the next listing shows it with no
/// further fill.
#[tokio::test(start_paused = true)]
async fn a_backend_past_the_cap_is_listed_after_its_late_fill_http() {
    let auth = sole_operator();
    let gateway = DirectAccountGateway::with_second_configured(
        auth.clone(),
        &Binding::Connected,
        Second::PersonalAccount,
        |config| config.timeout = std::time::Duration::from_secs(60),
    );
    let fx = two_surfaced(gateway, &auth).await;
    let cap = crate::gateway::meta_mcp::LISTING_DEADLINE_CAP;
    assert!(
        fill_bound(&fx, PERSONAL_BACKEND) > cap,
        "premise: the fill bound is past the cap"
    );
    let (feed, mut rx) = tokio::sync::mpsc::unbounded_channel();
    fx.gateway.backends().set_change_feed(feed);
    fx.gateway
        .delay_lists_on(PERSONAL_BACKEND, std::time::Duration::from_secs(40));
    let started = tokio::time::Instant::now();
    let first = rpc(&fx, 1, "tools/list", json!({})).await;
    assert!(
        started.elapsed() <= cap + std::time::Duration::from_secs(1),
        "the listing waited past the cap: {:?}",
        started.elapsed()
    );
    assert!(
        surfaced_on(&first, BACKEND)
            .iter()
            .any(|t| !is_shared_schema(t)),
        "the fast backend's own tool was not listed: {first}"
    );
    assert!(
        surfaced_on(&first, PERSONAL_BACKEND).is_empty(),
        "the slow backend was listed before its own fill finished: {first}"
    );
    assert!(
        !nudged(&mut rx, PERSONAL_BACKEND),
        "premise: no store of the slow backend before its answer"
    );
    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    assert!(
        nudged(&mut rx, PERSONAL_BACKEND),
        "the late fill's store sent no change nudge"
    );
    let fills = fx.gateway.lists_to(PERSONAL_BACKEND);
    let second = rpc(&fx, 2, "tools/list", json!({})).await;
    assert!(
        surfaced_on(&second, PERSONAL_BACKEND)
            .iter()
            .any(|t| !is_shared_schema(t)),
        "the late fill was not listed: {second}"
    );
    assert_eq!(
        fx.gateway.lists_to(PERSONAL_BACKEND),
        fills,
        "listed from a new fill, not the one the first listing started"
    );
}

/// SHARED.5 (busy custody): a second listing that starts while the first
/// one's lease is mid-fill, with custody busy, waits on that lease and serves
/// its result, with no second fill.
#[tokio::test(start_paused = true)]
async fn a_listing_waits_on_a_running_lease_through_a_busy_custody_http() {
    let fx = Arc::new(fixture().await);
    let bound = fill_bound(&fx, BACKEND);
    fx.gateway.delay_lists_on(BACKEND, bound / 2);
    let first = tokio::spawn({
        let fx = Arc::clone(&fx);
        async move { rpc(&fx, 1, "tools/list", json!({})).await }
    });
    tokio::time::sleep(bound / 4).await;
    assert_eq!(
        fx.gateway.lists_to(BACKEND),
        1,
        "premise: the first listing's fill is running"
    );
    fx.gateway.fail_custody_for_test(true);
    let second = rpc(&fx, 2, "tools/list", json!({})).await;
    fx.gateway.fail_custody_for_test(false);
    assert!(
        surfaced_on(&second, BACKEND)
            .iter()
            .any(|t| !is_shared_schema(t)),
        "the second listing did not serve the running lease's fill: {second}"
    );
    assert_eq!(fx.gateway.lists_to(BACKEND), 1, "a second fill ran");
    let first = first.await.expect("the first listing");
    assert!(
        surfaced_on(&first, BACKEND)
            .iter()
            .any(|t| !is_shared_schema(t)),
        "the first listing lost its own fill: {first}"
    );
}

/// The lease covers the fill: a backend whose fill bound is past
/// the 60 s cold backoff fills for 90 s. The first listing returns at the
/// 30 s cap without it. A second listing at 70 s does not claim the view
/// again: it waits on the running lease and lists the 90 s fill, and the
/// backend saw one fill. A regression pin, not a red proof: with a lease of
/// the backoff alone the 70 s listing does claim again, but its fill joins
/// the one already running and nothing a user or operator sees changes.
#[tokio::test(start_paused = true)]
async fn a_fill_past_the_cold_backoff_still_publishes_http() {
    let auth = sole_operator();
    let gateway = DirectAccountGateway::new_configured(
        crate::gateway::server::account_bindings::ServeMode::Http,
        auth.clone(),
        &Binding::Connected,
        |config| config.timeout = std::time::Duration::from_secs(120),
    );
    let fx = Arc::new(fixture_on(gateway, &auth, &[(BACKEND, TOOL)], |_| {}).await);
    fx.gateway
        .delay_lists_on(BACKEND, std::time::Duration::from_secs(90));
    let first = tokio::spawn({
        let fx = Arc::clone(&fx);
        async move { rpc(&fx, 1, "tools/list", json!({})).await }
    });
    tokio::time::sleep(std::time::Duration::from_secs(70)).await;
    let second = rpc(&fx, 2, "tools/list", json!({})).await;
    first.await.expect("the first listing");
    assert!(
        surfaced_on(&second, BACKEND)
            .iter()
            .any(|t| !is_shared_schema(t)),
        "the second listing did not show the 90 s fill: {second}"
    );
    assert_eq!(fx.gateway.lists_to(BACKEND), 1, "one fill");
}
