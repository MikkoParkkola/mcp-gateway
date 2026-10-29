// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A surfaced task runs on the server its name resolved to at
//! creation, or not at all. A reload that moves or removes the name between
//! the create and the worker's dispatch makes the worker refuse, with no
//! backend called. Each row registers two separate counted mocks, so "no
//! backend was called" cannot be confused with "the other one was".
use super::super::*;
use super::support::*;

const ALPHA: &str = "alpha";
const BETA: &str = "beta";

/// Authenticated state surfacing [`TOOL`] from `alpha`, with separate mocks
/// registered as `alpha` and `beta`.
async fn surfaced_state(
    alpha: &Arc<MockBackend>,
    beta: &Arc<MockBackend>,
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    // The suite's keys reach only `mock`; these rows need both servers
    // visible, so the move is the only thing that can refuse.
    let mut auth = two_principal_auth();
    for key in &mut auth.api_keys {
        key.backends = vec![ALPHA.to_owned(), BETA.to_owned()];
    }
    let (mut state, store) =
        crate::gateway::router::tests::test_router_app_state_with_auth_and_config(
            &auth,
            crate::config::Config::default(),
        )
        .await;
    let inner = Arc::get_mut(&mut state).expect("fixture is not shared yet");
    inner.meta_mcp = Arc::new(
        MetaMcp::new(Arc::clone(&inner.backends)).with_surfaced_tools(vec![
            crate::config::SurfacedToolConfig {
                server: ALPHA.into(),
                tool: TOOL.into(),
            },
        ]),
    );
    register(&state, ALPHA, alpha);
    register(&state, BETA, beta);
    // A surfaced name resolves from the backend's cached list, so both are
    // loaded before any row lists or calls it.
    for name in [ALPHA, BETA] {
        state
            .backends
            .get(name)
            .expect("registered above")
            .get_tools()
            .await
            .expect("premise: the mock's tool list loads");
    }
    (state, store)
}

fn surfaced_task(key: &str) -> Value {
    keyed(
        modern(
            2,
            "tools/call",
            json!({"name": TOOL, "arguments": {}, "task": {}}),
            true,
        ),
        key,
    )
}

/// The worker's refusal: a completed tool error whose outcome says the
/// backend never ran, carrying the plain sentence.
fn assert_refused(fetched: &Value) {
    std::assert_eq!(status_of(fetched), "completed", "{fetched}");
    std::assert_eq!(
        fetched.pointer("/result/result/isError"),
        Some(&json!(true)),
        "{fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/result/_meta/io.mcp-gateway~1executionOutcome"),
        Some(&json!("not_executed")),
        "{fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/result/_meta/io.mcp-gateway~1reason"),
        Some(&json!("surfaced_target_changed")),
        "{fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/result/content/0/text"),
        Some(&json!("surfaced target changed since the task was created")),
        "{fetched}"
    );
}

/// Run a surfaced task whose name `reload` changes as the worker starts, and
/// return its terminal state.
async fn run_with(
    alpha: &Arc<MockBackend>,
    beta: &Arc<MockBackend>,
    key: &str,
    reload: impl FnOnce(&MetaMcp) + 'static,
) -> Value {
    let (state, _store) = surfaced_state(alpha, beta).await;
    let meta = Arc::clone(&state.meta_mcp);
    crate::gateway::meta_mcp::visible::seams::at_task_start(move || reload(&meta));
    let created = post(&state, "key-a", surfaced_task(key)).await;
    let id = task_id(&created);
    poll_until_terminal(&state, "key-a", &id).await
}

/// L10 (N8): the name moves from alpha to beta before the worker dispatches.
/// The worker refuses: neither backend is called.
#[tokio::test]
async fn l10_a_surfaced_task_moved_before_dispatch_is_refused() {
    let alpha = MockBackend::answering(Answer::ok());
    let beta = MockBackend::answering(Answer::ok());
    let fetched = run_with(&alpha, &beta, "l10", |meta| {
        meta.resurface_for_test(TOOL, BETA);
    })
    .await;
    assert_refused(&fetched);
    std::assert_eq!((alpha.calls(), beta.calls()), (0, 0), "{fetched}");
}

/// L10b (N8): the name is removed before the worker dispatches: the same
/// refusal, and no backend is called.
#[tokio::test]
async fn l10b_a_surfaced_task_removed_before_dispatch_is_refused() {
    let alpha = MockBackend::answering(Answer::ok());
    let beta = MockBackend::answering(Answer::ok());
    let fetched = run_with(&alpha, &beta, "l10b", MetaMcp::clear_surfaced_for_test).await;
    assert_refused(&fetched);
    std::assert_eq!((alpha.calls(), beta.calls()), (0, 0), "{fetched}");
}

/// L11 (N8b, control): a reload that leaves the name on alpha does not refuse;
/// the worker dispatches alpha as normal.
#[tokio::test]
async fn l11_a_surfaced_task_left_in_place_runs_on_its_server() {
    let alpha = MockBackend::answering(Answer::ok());
    let beta = MockBackend::answering(Answer::ok());
    let fetched = run_with(&alpha, &beta, "l11", |meta| {
        meta.resurface_for_test(TOOL, ALPHA);
    })
    .await;
    assert_carries_the_backend_result(&fetched);
    std::assert_eq!((alpha.calls(), beta.calls()), (1, 0), "{fetched}");
}

/// L10d (N14): the name moves after the worker's check and before its
/// dispatch. The pin holds the recorded server: alpha is called, beta never.
/// Firewall builds only: the `before_task_dispatch` seam exists only there.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn l10d_a_move_between_the_check_and_the_dispatch_still_runs_on_alpha() {
    let alpha = MockBackend::answering(Answer::ok());
    let beta = MockBackend::answering(Answer::ok());
    let (state, _store) = surfaced_state(&alpha, &beta).await;
    let meta = Arc::clone(&state.meta_mcp);
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
        meta.resurface_for_test(TOOL, BETA);
    });
    let created = post(&state, "key-a", surfaced_task("l10d")).await;
    let fetched = poll_until_terminal(&state, "key-a", &task_id(&created)).await;
    assert_carries_the_backend_result(&fetched);
    std::assert_eq!((alpha.calls(), beta.calls()), (1, 0), "{fetched}");
}

/// Park a surfaced task on alpha, whose first answer asks for input, then
/// apply `reload` and answer. Returns the gateway, its store and the terminal
/// state.
async fn resumed_after(
    alpha: &Arc<MockBackend>,
    beta: &Arc<MockBackend>,
    key: &str,
    before_answer: impl FnOnce(&Arc<AppState>, &str),
) -> (
    Arc<AppState>,
    crate::gateway::router::tests::FixtureDir,
    Value,
) {
    let (state, store) = surfaced_state(alpha, beta).await;
    let created = post(&state, "key-a", declaring_elicitation(surfaced_task(key))).await;
    let id = task_id(&created);
    super::input_round::wait_input_required(&state, &id).await;
    before_answer(&state, &id);
    let answer =
        super::input_round::update(2, &id, json!({ "confirm": super::input_round::answer() }));
    let _ = post(&state, "key-a", answer).await;
    let fetched = poll_until_terminal(&state, "key-a", &id).await;
    (state, store, fetched)
}

fn asking() -> Answer {
    Answer::Sequence(vec![
        super::input_round::ask("confirm", super::input_round::STATE_1),
        super::input_round::done(),
    ])
}

/// L10c (N12): a task parked on alpha whose name moves to beta before the
/// answer arrives: the resume settles as the worker's refusal does (completed,
/// not executed, surfaced target changed), alpha is not called again and beta
/// never.
#[tokio::test]
async fn l10c_a_parked_surfaced_task_moved_before_resume_is_refused() {
    let alpha = MockBackend::answering(asking());
    let beta = MockBackend::answering(Answer::ok());
    let (_state, _store, fetched) = resumed_after(&alpha, &beta, "l10c", |state, _| {
        state.meta_mcp.resurface_for_test(TOOL, BETA);
    })
    .await;
    assert_refused(&fetched);
    std::assert_eq!((alpha.calls(), beta.calls()), (1, 0), "{fetched}");
}

/// L10d: a refused resume hands back what it held. Once it settles, a drain
/// joins every handoff and takes the whole worker pool within the bound; a
/// slot or handoff the refusal kept would hold the drain until it timed out.
#[tokio::test]
async fn l10d_a_refused_resume_releases_its_worker_capacity() {
    let alpha = MockBackend::answering(asking());
    let beta = MockBackend::answering(Answer::ok());
    let (state, _store, fetched) = resumed_after(&alpha, &beta, "l10d", |state, _| {
        state.meta_mcp.resurface_for_test(TOOL, BETA);
    })
    .await;
    assert_refused(&fetched);
    let drained = state
        .task_executor
        .drain(std::time::Duration::from_secs(5))
        .await;
    std::assert!(
        drained.is_clean(),
        "a refused resume kept capacity: {drained:?}"
    );
    std::assert!(drained.acquired > 0, "the drain took the pool: {drained:?}");
}

/// L13 (N13b, pin): a round written before it recorded its surfaced server
/// resumes on the live map, as it did before the field. The name moved to
/// beta, so the resume resolves beta, and the round's continuation, bound to
/// alpha, refuses there: neither backend is called again. A resume pinned to
/// alpha from some other record (N13b) would call alpha a second time.
#[tokio::test]
async fn l13_a_round_without_a_recorded_server_resumes_on_the_live_map() {
    let alpha = MockBackend::answering(asking());
    let beta = MockBackend::answering(Answer::ok());
    let (_state, _store, fetched) = resumed_after(&alpha, &beta, "l13", |state, id| {
        state
            .task_executor
            .service
            .store
            .unrecord_surfaced_for_test(id);
        state.meta_mcp.resurface_for_test(TOOL, BETA);
    })
    .await;
    std::assert_eq!(status_of(&fetched), "failed", "{fetched}");
    std::assert!(
        fetched.to_string().contains("continuation rejected"),
        "L13: the live resolve must meet alpha's continuation: {fetched}"
    );
    std::assert_eq!((alpha.calls(), beta.calls()), (1, 0), "{fetched}");
}

/// L14 (N15): a reload landing while `tools/list` is being built does not
/// split the list. The surfaced set is withdrawn right after the list took
/// its snapshot; the list still holds the set it started with.
#[tokio::test]
async fn l14_one_tools_list_holds_the_surfaced_set_it_started_with() {
    let alpha = MockBackend::answering(Answer::ok());
    let beta = MockBackend::answering(Answer::ok());
    let (state, _store) = surfaced_state(&alpha, &beta).await;
    let names = |listed: &Value| -> Vec<String> {
        listed
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .expect("a tool list")
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
            .collect()
    };
    let list = || modern(1, "tools/list", json!({}), true);
    let before = post(&state, "key-a", list()).await;
    std::assert!(
        names(&before).iter().any(|name| name == TOOL),
        "premise: the surfaced tool is listed: {before}"
    );
    let meta = Arc::clone(&state.meta_mcp);
    crate::gateway::meta_mcp::visible::seams::after_list_snapshot(move || {
        meta.clear_surfaced_for_test();
    });
    let during = post(&state, "key-a", list()).await;
    std::assert_eq!(names(&during), names(&before), "L14: {during}");
    let after = post(&state, "key-a", list()).await;
    std::assert!(
        !names(&after).iter().any(|name| name == TOOL),
        "premise: the withdrawal applies to the next list: {after}"
    );
}

/// L10e: the name moves to beta while alpha is answering. The settled result
/// is inspected as alpha's answer, under alpha's targets, not beta's.
#[tokio::test]
async fn l10e_a_move_during_the_call_keeps_the_result_inspected_as_alpha() {
    let (alpha, mut gate) = MockBackend::holding(Answer::ok());
    let beta = MockBackend::answering(Answer::ok());
    let (state, _store) = surfaced_state(&alpha, &beta).await;
    let _ = crate::gateway::meta_mcp::visible::seams::take_inspected();
    let created = post(&state, "key-a", surfaced_task("l10e")).await;
    gate.wait_for_dispatch().await;
    state.meta_mcp.resurface_for_test(TOOL, BETA);
    gate.release();
    let fetched = poll_until_terminal(&state, "key-a", &task_id(&created)).await;
    assert_carries_the_backend_result(&fetched);
    std::assert_eq!(
        crate::gateway::meta_mcp::visible::seams::take_inspected(),
        vec![ALPHA.to_owned()],
        "L10e: the settled result was inspected under the moved name's server"
    );
    std::assert_eq!((alpha.calls(), beta.calls()), (1, 0), "{fetched}");
}

/// A capability set named `name` holding [`TOOL`].
fn capabilities_named(name: &str) -> Arc<crate::capability::CapabilityBackend> {
    let caps = crate::capability::CapabilityBackend::new(
        name,
        Arc::new(crate::capability::CapabilityExecutor::new()),
    );
    let yaml = format!(
        "name: {TOOL}\ndescription: Test capability\nproviders:\n  primary:\n    \
         service: rest\n    config:\n      base_url: https://example.invalid\n      path: /echo\n"
    );
    caps.register_capability(crate::capability::parse_capability(&yaml).expect("capability"))
        .expect("registered");
    Arc::new(caps)
}

/// L10f (Nk, Nc): a target that keeps its server name but changes kind does
/// not hold. A backend swapped for a capability set of the same name, and the
/// reverse, are both changed targets; a capability set under another name
/// never holds a target recorded for this one.
#[tokio::test]
async fn l10f_a_target_that_changes_kind_does_not_hold() {
    use crate::gateway::task_service::SurfacedKind;
    let alpha = MockBackend::answering(Answer::ok());
    let beta = MockBackend::answering(Answer::ok());
    let (state, _store) = surfaced_state(&alpha, &beta).await;
    let meta = &state.meta_mcp;
    let backend = meta.surfaced_target_at_intake(TOOL).expect("surfaced");
    std::assert_eq!(backend.kind, SurfacedKind::Backend);
    assert!(meta.surfaced_target_holds(TOOL, Some(&backend)), "premise");

    assert!(
        state.backends.remove(ALPHA),
        "premise: alpha was registered"
    );
    meta.set_capabilities(capabilities_named("other"));
    assert!(
        !meta.surfaced_target_holds(TOOL, Some(&backend)),
        "a removed backend held through a capability of the tool's name"
    );
    let capability = meta.surfaced_target_at_intake(TOOL).expect("surfaced");
    assert!(
        !meta.surfaced_target_holds(TOOL, Some(&capability)),
        "a capability set named other held a target recorded for alpha"
    );

    meta.set_capabilities(capabilities_named(ALPHA));
    assert!(
        !meta.surfaced_target_holds(TOOL, Some(&backend)),
        "a backend swapped for a same-named capability held"
    );
    assert!(
        meta.surfaced_target_holds(TOOL, Some(&capability)),
        "premise"
    );
    register(&state, ALPHA, &alpha);
    assert!(
        !meta.surfaced_target_holds(TOOL, Some(&capability)),
        "a capability swapped for a same-named backend held"
    );
}
