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
    // A backend the grant excludes is skipped, not refused: no shared start
    // is attempted for it, so the listing records no refusal.
    let raw = std::fs::read_to_string(fx.dirs.0.path().join("audit.jsonl")).unwrap_or_default();
    let delivered: Vec<Value> = raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .collect();
    let [listing] = delivered.as_slice() else {
        panic!("premise: one delivery record for the listing: {delivered:?}");
    };
    assert_ne!(listing["response_effect"], "refused", "{listing}");
}

/// The surfaced entries in a `tools/list` answer whose trust card names
/// `server`.
pub(super) fn surfaced_on<'a>(answer: &'a Value, server: &str) -> Vec<&'a Value> {
    answer
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|t| t.pointer("/trustCard/serverId") == Some(&json!(format!("backend:{server}"))))
        .collect()
}

/// Whether an entry carries the shared slot's schema B (a `folder` property).
pub(super) fn is_shared_schema(entry: &Value) -> bool {
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
    // The fill is held open, so both listings are in flight together.
    let bound = fill_bound(&fx, BACKEND);
    fx.gateway.delay_lists_on(BACKEND, bound / 2);
    let (a, b) = tokio::join!(
        rpc(&fx, 1, "tools/list", json!({})),
        rpc(&fx, 2, "tools/list", json!({}))
    );
    for answer in [&a, &b] {
        let entries = surfaced_on(answer, BACKEND);
        assert!(
            entries.iter().any(|t| !is_shared_schema(t)),
            "a listing did not show the caller's own schema: {answer}"
        );
        assert!(
            !entries.into_iter().any(is_shared_schema),
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
pub(super) fn fill_bound(fx: &Fx, server: &str) -> std::time::Duration {
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

/// `server`'s `tools_known` in a `gateway_list_servers` answer, wherever the
/// entry sits in the (text-carried) JSON.
fn servers_know_tools(answer: &Value, server: &str) -> bool {
    fn find(value: &Value, server: &str) -> Option<bool> {
        match value {
            Value::String(text) => find(&serde_json::from_str(text).ok()?, server),
            Value::Array(items) => items.iter().find_map(|item| find(item, server)),
            Value::Object(map) => {
                if map.get("name") == Some(&json!(server))
                    && let Some(known) = map.get("tools_known")
                {
                    return Some(known == &json!(true));
                }
                map.values().find_map(|item| find(item, server))
            }
            _ => None,
        }
    }
    find(answer, server)
        .unwrap_or_else(|| panic!("premise: gateway_list_servers lists {server}: {answer}"))
}

/// SHARED.5 (busy custody), superseded by D3: busy custody fails closed for
/// per-user tools, and a fill that finishes under an unreadable gate does not
/// publish. A second listing that starts while the first one's lease is
/// mid-fill, with custody busy, withholds the per-user backend's tools and
/// still lists a shared backend's; no second fill runs. The per-user tools
/// stay hidden for up to the retry backoff after a busy read: once custody
/// is back and the backoff has passed, the next listing claims afresh, reads
/// custody, and shows the current grant's tools.
#[tokio::test(start_paused = true)]
async fn a_busy_custody_listing_withholds_per_user_tools_then_recovers_http() {
    let fx = Arc::new(fixture().await);
    shared_backend(&fx);
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
    let servers = rpc(
        &fx,
        3,
        "tools/call",
        json!({"name": "gateway_list_servers", "arguments": {}}),
    )
    .await;
    fx.gateway.fail_custody_for_test(false);
    first.await.expect("the first listing");
    assert!(
        !surfaced_on(&second, BACKEND)
            .iter()
            .any(|t| !is_shared_schema(t)),
        "a busy custody listed the per-user backend's own tools: {second}"
    );
    assert!(
        servers_know_tools(&servers, "shared-ledger"),
        "a busy custody hid a shared backend's tools: {servers}"
    );
    assert!(
        !servers_know_tools(&servers, BACKEND),
        "a busy custody let the per-user backend's tools list: {servers}"
    );
    assert_eq!(
        fx.gateway.lists_to(BACKEND),
        1,
        "a second fill ran while custody was busy"
    );
    let within = rpc(&fx, 4, "tools/list", json!({})).await;
    assert!(
        !surfaced_on(&within, BACKEND)
            .iter()
            .any(|t| !is_shared_schema(t)),
        "the retry backoff did not hold after the refused publish: {within}"
    );
    tokio::time::sleep(crate::gateway::meta_mcp::COLD_RETRY_BACKOFF + bound).await;
    let third = rpc(&fx, 5, "tools/list", json!({})).await;
    assert!(
        surfaced_on(&third, BACKEND)
            .iter()
            .any(|t| !is_shared_schema(t)),
        "the current grant's tools did not list after custody recovered: {third}"
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

/// A grant that rotates while another listing's lease is filling: the
/// second listing, begun after the rotation, waits on that lease, but the
/// view it published belongs to the old grant, so it reads as cold and the
/// listing withholds the tool rather than serve the old grant's schema. The
/// next listing shows the current grant's own schema after one fresh fill.
#[tokio::test(start_paused = true)]
async fn a_lease_filled_under_a_rotated_grant_is_not_served_http() {
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
        "premise: the old grant's fill is running"
    );
    fx.gateway.rotate_operator_grant().await;
    let rotated = fx
        .state
        .meta_mcp
        .account_strategies()
        .managed_vault(Some("work-gmail"))
        .expect("the managed vault")
        .view_binding(crate::personal_accounts::identity::Principal::SoleOperator)
        .await
        .expect("premise: the rotated grant has a view");
    assert_ne!(
        rotated,
        DirectAccountGateway::operator_binding(),
        "premise: rotation selects a new slot"
    );
    let second = rpc(&fx, 2, "tools/list", json!({})).await;
    assert!(
        surfaced_on(&second, BACKEND).is_empty(),
        "the old grant's schema was served after the rotation: {second}"
    );
    first.await.expect("the first listing");
    // The current grant's own view comes from one fresh fill of its slot.
    fx.gateway.rearm_operator_slot_at_for_test(&rotated);
    let fills = fx.gateway.lists_to(BACKEND);
    let third = rpc(&fx, 3, "tools/list", json!({})).await;
    assert!(
        surfaced_on(&third, BACKEND)
            .iter()
            .any(|t| !is_shared_schema(t)),
        "the current grant's own schema was not listed: {third}"
    );
    assert_eq!(
        fx.gateway.lists_to(BACKEND),
        fills + 1,
        "the current grant's view took other than one fill"
    );
}

/// The race, laid out step by step: a listing begun after a rotation finds
/// the old grant's lease running, so its claim returns nothing; before it
/// looks for that lease, the old fill publishes. The listing then finds no
/// lease to wait on and builds its list at once. The view it would read is
/// the old grant's, and it must read as cold.
#[tokio::test(start_paused = true)]
async fn a_rotated_grant_publishing_inside_the_claim_window_is_not_served_http() {
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
        "premise: the old grant's fill is running"
    );
    fx.gateway.rotate_operator_grant().await;
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    let (reached, release) = backend.before_lease_lookup.arm();
    let second = tokio::spawn({
        let fx = Arc::clone(&fx);
        async move { rpc(&fx, 2, "tools/list", json!({})).await }
    });
    // The second listing's claim found the old lease and returned nothing.
    reached.notified().await;
    // The old fill publishes inside that window.
    first.await.expect("the first listing");
    release.notify_one();
    let second = second.await.expect("the second listing");
    assert!(
        surfaced_on(&second, BACKEND).is_empty(),
        "the old grant's schema was served through the claim window: {second}"
    );
}

/// The deadline cuts the account pre-pass short while the old grant's fill
/// publishes: the listing never read the current grant, so it fails closed
/// and withholds the tool rather than serve the old grant's schema.
#[tokio::test(start_paused = true)]
async fn a_listing_whose_account_check_is_cut_short_withholds_http() {
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
        "premise: the old grant's fill is running"
    );
    fx.gateway.rotate_operator_grant().await;
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    // Armed and never released: the second listing's pre-pass never runs,
    // and its deadline ends the step.
    let (reached, _held) = backend.before_listing_prepass.arm();
    let second = tokio::spawn({
        let fx = Arc::clone(&fx);
        async move { rpc(&fx, 2, "tools/list", json!({})).await }
    });
    reached.notified().await;
    first.await.expect("the first listing");
    let second = second.await.expect("the second listing");
    assert!(
        surfaced_on(&second, BACKEND).is_empty(),
        "an unchecked listing served the old grant's schema: {second}"
    );
}

/// A cold caller's claim whose credential release fails leaves only the
/// retry backoff behind, and no fill runs under it: neither that listing nor
/// the next one inside the backoff waits out the backend's fill bound, and
/// nothing is fetched meanwhile.
#[tokio::test(start_paused = true)]
async fn a_listing_after_a_failed_credential_lookup_answers_at_once_http() {
    let fx = fixture().await;
    let bound = fill_bound(&fx, BACKEND);
    let floor = std::time::Duration::from_secs(1);
    assert!(bound > floor * 2, "premise: a fill bound worth waiting on");
    fx.gateway.fail_release_for_test();
    let started = tokio::time::Instant::now();
    let first = rpc(&fx, 1, "tools/list", json!({})).await;
    let first_took = started.elapsed();
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    let id = crate::personal_accounts::identity::Principal::SoleOperator.stable_actor_id();
    assert!(
        backend.cold_lease_remaining(&id).is_some(),
        "premise: the claim was made and its lease stands as the backoff"
    );
    assert_eq!(fx.gateway.releases(), 0, "premise: the lookup failed");
    let started = tokio::time::Instant::now();
    let second = rpc(&fx, 2, "tools/list", json!({})).await;
    let second_took = started.elapsed();
    assert!(
        first_took < floor && second_took < floor,
        "a listing waited on a failed lookup's backoff: {first_took:?} then \
         {second_took:?}, against a {bound:?} fill bound"
    );
    for answer in [&first, &second] {
        assert!(
            surfaced_on(answer, BACKEND).is_empty(),
            "no view of the caller's own was filled: {answer}"
        );
    }
    assert_eq!(
        fx.gateway.lists_to(BACKEND),
        0,
        "nothing fetched in the backoff"
    );
}

/// A listing waiting on another listing's running claim is woken as that
/// claim's credential lookup fails: it answers within the floor of the
/// failure, not at the backend's fill bound.
#[tokio::test(start_paused = true)]
async fn a_listing_waiting_on_a_lookup_that_fails_is_woken_at_once_http() {
    let fx = Arc::new(fixture().await);
    let bound = fill_bound(&fx, BACKEND);
    let floor = std::time::Duration::from_secs(1);
    assert!(bound > floor * 2, "premise: a fill bound worth waiting on");
    fx.gateway.fail_release_for_test();
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    // The first listing wins the claim and is held before its lookup.
    let (reached, release) = backend.cold_winner.arm();
    let first = tokio::spawn({
        let fx = Arc::clone(&fx);
        async move { rpc(&fx, 1, "tools/list", json!({})).await }
    });
    reached.notified().await;
    let second = tokio::spawn({
        let fx = Arc::clone(&fx);
        async move { rpc(&fx, 2, "tools/list", json!({})).await }
    });
    // The clock only moves once every task is idle: the second listing is
    // parked on the first one's running lease by then.
    tokio::time::sleep(floor / 10).await;
    assert!(!second.is_finished(), "premise: the second listing waits");
    let failed_at = tokio::time::Instant::now();
    release.notify_one();
    let second = second.await.expect("the second listing");
    let woke_after = failed_at.elapsed();
    first.await.expect("the first listing");
    assert!(
        woke_after < floor,
        "a waiter slept {woke_after:?} past a failed lookup, against a {bound:?} fill bound"
    );
    assert!(
        surfaced_on(&second, BACKEND).is_empty(),
        "no view was filled: {second}"
    );
    assert_eq!(fx.gateway.releases(), 0, "premise: the lookup failed");
}

/// A listing waiting on another listing's running claim is woken when that
/// claim's request is cancelled mid-lookup (its attempt dropped, not
/// failed), and the claim's lease still stands as the retry backoff.
#[tokio::test(start_paused = true)]
async fn a_listing_waiting_on_a_cancelled_claim_is_woken_at_once_http() {
    let fx = Arc::new(fixture().await);
    let bound = fill_bound(&fx, BACKEND);
    let floor = std::time::Duration::from_secs(1);
    assert!(bound > floor * 2, "premise: a fill bound worth waiting on");
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    let (reached, _held) = backend.cold_winner.arm();
    let first = tokio::spawn({
        let fx = Arc::clone(&fx);
        async move { rpc(&fx, 1, "tools/list", json!({})).await }
    });
    reached.notified().await;
    let second = tokio::spawn({
        let fx = Arc::clone(&fx);
        async move { rpc(&fx, 2, "tools/list", json!({})).await }
    });
    tokio::time::sleep(floor / 10).await;
    assert!(!second.is_finished(), "premise: the second listing waits");
    let cancelled_at = tokio::time::Instant::now();
    first.abort();
    let _ = first.await;
    let second = second.await.expect("the second listing");
    let woke_after = cancelled_at.elapsed();
    assert!(
        woke_after < floor,
        "a waiter slept {woke_after:?} past a cancelled claim, against a {bound:?} fill bound"
    );
    assert!(
        surfaced_on(&second, BACKEND).is_empty(),
        "no view was filled: {second}"
    );
    let id = crate::personal_accounts::identity::Principal::SoleOperator.stable_actor_id();
    assert!(
        backend.cold_lease_remaining(&id).is_some(),
        "the cancelled claim's lease still stands as the backoff"
    );
    assert_eq!(
        fx.gateway.lists_to(BACKEND),
        0,
        "nothing fetched in the backoff"
    );
}
