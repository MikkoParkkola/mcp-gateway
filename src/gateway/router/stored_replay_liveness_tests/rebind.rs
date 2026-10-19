// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8407: a stored result is judged against the account that produced it,
//! not the account its backend is bound to now. Each row runs a call on
//! [`BACKEND`] while it is bound to `work-gmail`, revokes that grant, then
//! re-binds [`BACKEND`] to `personal-gmail`, whose grant is live, as an
//! operator's reload does. The stored output was produced under the revoked
//! account and must not be served (REC.3); the control row keeps the binding
//! and serves (REC.3 control).

use super::*;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::Second;

/// Both managed accounts live for the sole operator; [`BACKEND`] bound to
/// `work-gmail`.
async fn two_accounts() -> Fx {
    let auth = sole_operator();
    let mut gateway = DirectAccountGateway::with_second(
        auth.clone(),
        &Binding::Connected,
        Second::PersonalAccount,
    );
    let (mut state, store) = super::super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    // The direct route mints only with a propagation audit log (G1).
    let audit = tempfile::tempdir().expect("an audit dir");
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: audit
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                key_id: "8407".to_string(),
                ..crate::security::transparency_log::TransparencyLogConfig::default()
            },
        ))
        .expect("open log"),
    );
    let mut meta = gateway.take_meta();
    meta.enable_transparency_log(Arc::clone(&log));
    state_mut.transparency_log = Some(log);
    state_mut.meta_mcp = Arc::new(meta);
    store_tool(&gateway);
    let tasks = Arc::clone(&state.task_executor);
    let served = Arc::clone(&state.meta_mcp);
    Fx {
        router: super::super::create_router(state),
        gateway,
        tasks,
        meta: served,
        _store: store,
        audit: Some(audit),
    }
}

/// [`TOOL`] in [`BACKEND`]'s catalogue (again after a re-bind: a reload's
/// replacement starts with none).
fn store_tool(gateway: &DirectAccountGateway) {
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .store_shared_tools_for_test(vec![tool]);
}

/// Revoke `work-gmail`, then re-bind [`BACKEND`] to the live `personal-gmail`.
async fn revoke_and_rebind(fx: &Fx) {
    fx.gateway.revoke_operator_grant_on(BACKEND).await;
    fx.gateway.rebind_backend_to_personal_for_test();
    store_tool(&fx.gateway);
}

/// A keyed task-augmented `gateway_invoke` that completed with [`MARKER`]:
/// its task id.
async fn completed_task(fx: &Fx, key: &str) -> String {
    answer_marker(fx);
    let made = send(
        fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some(key), true),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let done = wait_terminal(fx, &id).await;
    assert_eq!(
        done.pointer("/result/status").and_then(Value::as_str),
        Some("completed"),
        "premise: {done}"
    );
    id
}

/// `tasks/get` for `id`: the stored output, or the read's refusal.
async fn task_result(fx: &Fx, id: &str) -> Value {
    send(
        fx,
        "tasks/get",
        id,
        json!({"taskId": id, "_meta": meta(None, true)}),
    )
    .await
}

/// RB-read (REC.3, STORED.1 surface; mutant M-rec-read): a task read after
/// the re-bind is refused; nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rb_read_task_output_of_a_revoked_account_is_refused_after_a_rebind() {
    let fx = two_accounts().await;
    let id = completed_task(&fx, "rb-read").await;
    let before = task_result(&fx, &id).await;
    assert!(
        before.to_string().contains(MARKER),
        "premise: read serves: {before}"
    );
    let sent = fx.gateway.tool_calls().len();
    revoke_and_rebind(&fx).await;
    let read = task_result(&fx, &id).await;
    eprintln!("RB-read: {read}");
    assert_refused_unsent(&fx, "RB-read", &read, sent);
}

/// RB-repeat (REC.3, STORED.2 site 5; mutant M-rec-repeat): the same keyed
/// task call repeated after the re-bind is not answered with the stored
/// task, makes no new task, and sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rb_repeat_task_call_of_a_revoked_account_is_refused_after_a_rebind() {
    let fx = two_accounts().await;
    let id = completed_task(&fx, "rb-repeat").await;
    let sent = fx.gateway.tool_calls().len();
    revoke_and_rebind(&fx).await;
    let again = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("rb-repeat"), true),
    )
    .await;
    eprintln!("RB-repeat: {again}");
    assert_ne!(
        again.pointer("/result/taskId").and_then(Value::as_str),
        Some(id.as_str()),
        "RB-repeat: the stored task was answered back: {again}"
    );
    assert!(
        again.pointer("/result/taskId").is_none(),
        "RB-repeat: a new task was made: {again}"
    );
    assert_refused_unsent(&fx, "RB-repeat", &again, sent);
}

/// RB-control (REC.3 control): no re-bind and `work-gmail` live: the task
/// read, the repeat and the sync retry are all served their stored output,
/// with nothing sent again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rb_control_without_a_rebind_the_stored_output_is_served() {
    let fx = two_accounts().await;
    let id = completed_task(&fx, "rb-control").await;
    answer_marker(&fx);
    let first = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("rb-c-sync"), false),
    )
    .await;
    assert!(first.to_string().contains(MARKER), "premise: {first}");
    let sent = fx.gateway.tool_calls().len();
    let read = task_result(&fx, &id).await;
    assert!(read.to_string().contains(MARKER), "RB-control read: {read}");
    let again = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("rb-control"), true),
    )
    .await;
    assert_eq!(
        again.pointer("/result/taskId").and_then(Value::as_str),
        Some(id.as_str()),
        "RB-control repeat: {again}"
    );
    let sync = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("rb-c-sync"), false),
    )
    .await;
    assert!(sync.to_string().contains(MARKER), "RB-control sync: {sync}");
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "RB-control: sent again"
    );
}

/// RB-legacy (design r4 E4; mutant M-legacy): a row written before bindings
/// were recorded is refused on a read and on a repeat, with the legacy text.
/// Its key stays held (the repeat makes no new task) and the row stays
/// readable by the store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rb_legacy_a_pre_binding_row_is_refused_and_kept() {
    let fx = two_accounts().await;
    let id = completed_task(&fx, "rb-legacy").await;
    let sent = fx.gateway.tool_calls().len();
    fx.tasks.service.store.unrecord_bindings_for_test(&id);
    let read = task_result(&fx, &id).await;
    eprintln!("RB-legacy read: {read}");
    assert_refused_unsent(&fx, "RB-legacy read", &read, sent);
    assert!(
        read.to_string().contains("predates credential binding"),
        "RB-legacy: not the legacy refusal: {read}"
    );
    let again = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("rb-legacy"), true),
    )
    .await;
    assert!(
        again.pointer("/result/taskId").is_none(),
        "RB-legacy: a new task: {again}"
    );
    assert_refused_unsent(&fx, "RB-legacy repeat", &again, sent);
    let owner = fx
        .tasks
        .service
        .store
        .owner_digest_for_test(&id)
        .expect("RB-legacy: the row was deleted");
    assert!(
        fx.tasks.service.store.get(&owner, &id).is_ok(),
        "RB-legacy: unreadable"
    );
}
