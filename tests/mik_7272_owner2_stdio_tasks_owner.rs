// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7272.OWNER.2 (I4), owner and lifecycle rows: invariant I-OWN against
//! HTTP owners on the stdio store, interrupted tasks settled and never rerun,
//! cancel and input rounds over stdio, one admission index, and creation
//! rules matching HTTP. Rows T6, T9–T11 and T14–T17 of
//! `docs/design/2026-09-30-sub4-stdio-owner-test-plan.md`; design D6 rev 5.

#[path = "mik_7272_owner2_stdio_tasks/helper.rs"]
mod helper;

use std::path::{Path, PathBuf};

use helper::{
    ANSWERED, API_KEY, ASK, Auth, Backend, ECHO, HELD, HttpGateway, StdioGateway, error_code,
    initialize, modern, status, sync_call, task_call, task_id, tasks_cancel, tasks_get,
    tasks_update, write_config,
};
use serde_json::{Value, json};

struct World {
    root: tempfile::TempDir,
    backend: Backend,
    config: PathBuf,
}

impl World {
    async fn new(auth: Auth) -> Self {
        let root = tempfile::tempdir().expect("temp root");
        let backend = Backend::start().await;
        let config = write_config(
            root.path(),
            "gateway.yaml",
            &root.path().join("tasks"),
            &backend.url,
            auth,
        );
        Self {
            root,
            backend,
            config,
        }
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    /// A config whose `tasks.store_dir` is stdio's own directory: HTTP pointed
    /// explicitly at the stdio store (I-OWN rows).
    fn http_on_stdio_store(&self, name: &str, auth: Auth) -> PathBuf {
        write_config(
            self.path(),
            name,
            &self.path().join("tasks").join("stdio"),
            &self.backend.url,
            auth,
        )
    }

    async fn stdio(&self, log: &str) -> StdioGateway {
        let mut gateway = StdioGateway::spawn(self.path(), &self.config, log);
        gateway.request(&initialize(json!(0))).await;
        gateway
    }
}

fn no_such_task(answer: &Value) {
    assert_eq!(error_code(answer), Some(-32602), "{answer}");
    assert_eq!(
        answer.pointer("/error/message").and_then(Value::as_str),
        Some("no such task"),
        "{answer}"
    );
}

/// T6, invariant I-OWN.
#[tokio::test]
async fn i_own_a_same_store_http_owner_cannot_reach_it() {
    let world = World::new(Auth::Off).await;
    let mut stdio = world.stdio("t6-a.log").await;
    let created = stdio
        .request(&task_call(json!(1), ECHO, Some("k-t6")))
        .await;
    let id = task_id(&created);
    stdio.terminal(&id).await;
    stdio.close().await;

    for (auth, bearer, name) in [
        (Auth::Off, None, "t6-off.yaml"),
        (Auth::Key, Some(API_KEY), "t6-key.yaml"),
    ] {
        let config = world.http_on_stdio_store(name, auth);
        let http = HttpGateway::start(world.path(), &config, &format!("{name}.log")).await;
        no_such_task(&http.post(&tasks_get(json!(2), &id), bearer).await);
        no_such_task(&http.post(&tasks_cancel(json!(3), &id), bearer).await);
        no_such_task(&http.post(&tasks_update(json!(4), &id), bearer).await);
        http.stop().await;
    }

    let mut again = world.stdio("t6-b.log").await;
    let task = again.request(&tasks_get(json!(5), &id)).await;
    assert_eq!(
        status(&task),
        Some("completed"),
        "no HTTP cancel landed: {task}"
    );
    again.close().await;
}

/// The restart result a killed, dispatched task settles as
/// (`task_service/execution/recovery.rs`: `gateway_restart_after_dispatch`).
fn settled_after_dispatch(task: &Value) {
    assert!(
        matches!(status(task), Some("completed" | "failed")),
        "terminal after restart: {task}"
    );
    assert!(
        task.to_string().contains("gateway_restart_after_dispatch"),
        "settled as interrupted after dispatch: {task}"
    );
}

/// Create a `held` task and kill stdio once the backend has the call.
async fn killed_mid_call(world: &mut World, log: &str) -> String {
    let mut stdio = world.stdio(log).await;
    let request = task_call(json!(1), HELD, Some("k-held"));
    stdio.send(&request).await;
    let created = stdio.try_answer(&request["id"]).await;
    let created = created.expect(
        "a task handle comes back while the held call is still running \
         (a synchronous dispatch would answer only after the barrier opens)",
    );
    let id = task_id(&created);
    world.backend.wait_arrivals(1).await;
    stdio.kill().await;
    id
}

/// T9.
#[tokio::test]
async fn an_interrupted_stdio_task_is_settled_not_rerun() {
    let mut world = World::new(Auth::Off).await;
    let id = killed_mid_call(&mut world, "t9-a.log").await;
    let mut again = world.stdio("t9-b.log").await;
    let task = again.request(&tasks_get(json!(2), &id)).await;
    settled_after_dispatch(&task);
    world.backend.open_barrier();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(world.backend.rounds(), 1, "never rerun");
    again.close().await;
}

/// T10.
#[tokio::test]
async fn an_http_restart_settles_a_stdio_task_but_cannot_read_it() {
    let mut world = World::new(Auth::Off).await;
    let id = killed_mid_call(&mut world, "t10-a.log").await;
    let config = world.http_on_stdio_store("t10-http.yaml", Auth::Off);
    let http = HttpGateway::start(world.path(), &config, "t10-http.log").await;
    no_such_task(&http.post(&tasks_get(json!(2), &id), None).await);
    http.stop().await;
    let mut again = world.stdio("t10-b.log").await;
    settled_after_dispatch(&again.request(&tasks_get(json!(3), &id)).await);
    world.backend.open_barrier();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(world.backend.rounds(), 1, "never rerun");
    again.close().await;
}

/// T11.
#[tokio::test]
async fn stdio_task_creation_ignores_the_http_auth_gate() {
    let world = World::new(Auth::Key).await;
    let mut stdio = world.stdio("t11.log").await;
    let created = stdio
        .request(&task_call(json!(1), ECHO, Some("k-t11")))
        .await;
    let id = task_id(&created);
    let task = stdio.terminal(&id).await;
    assert_eq!(status(&task), Some("completed"), "{task}");
    stdio.close().await;
}

/// T14.
#[tokio::test]
async fn the_local_operator_cancels_a_working_task() {
    let mut world = World::new(Auth::Off).await;
    let mut stdio = world.stdio("t14.log").await;
    let request = task_call(json!(1), HELD, Some("k-t14"));
    stdio.send(&request).await;
    let created = stdio
        .try_answer(&request["id"])
        .await
        .expect("a task handle comes back while the held call runs");
    let id = task_id(&created);
    world.backend.wait_arrivals(1).await;
    let cancelled = stdio.request(&tasks_cancel(json!(2), &id)).await;
    assert!(cancelled.get("error").is_none(), "{cancelled}");
    world.backend.open_barrier();
    let task = stdio.terminal(&id).await;
    assert_eq!(status(&task), Some("cancelled"), "{task}");
    assert!(
        task.pointer("/result/result").is_none(),
        "no result delivered: {task}"
    );
    stdio.close().await;
}

/// T15.
#[tokio::test]
async fn the_local_operator_answers_an_input_round() {
    let world = World::new(Auth::Off).await;
    let mut stdio = world.stdio("t15.log").await;
    let created = stdio
        .request(&task_call(json!(1), ASK, Some("k-t15")))
        .await;
    let id = task_id(&created);
    let deadline = tokio::time::Instant::now() + helper::BOUND;
    let mut n = 0;
    loop {
        n += 1;
        let task = stdio.request(&tasks_get(json!(format!("p{n}")), &id)).await;
        if status(&task) == Some("input_required") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no input round: {task}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let updated = stdio.request(&tasks_update(json!(2), &id)).await;
    assert!(updated.get("error").is_none(), "{updated}");
    let task = stdio.terminal(&id).await;
    assert_eq!(status(&task), Some("completed"), "{task}");
    assert!(
        task.to_string().contains(ANSWERED),
        "the backend saw the answer: {task}"
    );
    stdio.close().await;
}

/// What the creation rules decided about a task-augmented call: a task, a
/// creation refusal (code and text), or not a task. Anything a call does once
/// it is not a task is the synchronous path, which HTTP and stdio authorize
/// differently by design and which these rows do not compare.
fn shape(answer: &Value) -> String {
    if answer.pointer("/result/resultType").and_then(Value::as_str) == Some("task") {
        return "task".to_owned();
    }
    if let Some(error) = answer.get("error")
        && let Some(message) = error["message"].as_str()
        && (message.contains("task creation requires")
            || message.contains("extension to be declared"))
    {
        return format!("refused {} {message}", error["code"]);
    }
    "not a task".to_owned()
}

/// HTTP on its own store and backend, for parity rows.
async fn http_twin(world: &World) -> (HttpGateway, Backend) {
    let backend = Backend::start().await;
    let config = write_config(
        world.path(),
        "twin.yaml",
        &world.path().join("twin-tasks"),
        &backend.url,
        Auth::Off,
    );
    (
        HttpGateway::start(world.path(), &config, "twin.log").await,
        backend,
    )
}

/// T16. A synchronous call carrying a task's key meets the task at the one
/// admission index: it is refused as another execution, never run again. HTTP
/// is not the reference here: an auth-off HTTP gateway refuses a keyed
/// synchronous call for want of a principal (-32003) before admission, and one
/// with credentials cannot create a task without a verified identity.
#[tokio::test]
async fn a_task_and_a_sync_call_share_one_admission() {
    let world = World::new(Auth::Off).await;
    let mut stdio = world.stdio("t16.log").await;
    let id = task_id(
        &stdio
            .request(&task_call(json!(1), ECHO, Some("k-t16")))
            .await,
    );
    stdio.terminal(&id).await;
    let sync = stdio.request(&sync_call(json!(2), ECHO, "k-t16")).await;
    assert_eq!(
        world.backend.rounds(),
        1,
        "one admission, one round: {sync}"
    );
    assert_eq!(
        error_code(&sync),
        Some(409),
        "the admission refuses it: {sync}"
    );
    assert!(
        sync.to_string()
            .contains("belongs to another execution or representation"),
        "the key is held by the task: {sync}"
    );
    stdio.close().await;
}

/// T17: each creation rule answers on stdio as it does on HTTP. The legacy
/// case is not compared here: HTTP's modern route refuses a legacy body as
/// malformed, so the two answers would differ for a transport reason.
#[tokio::test]
async fn stdio_creation_rules_match_http() {
    let world = World::new(Auth::Off).await;
    let (http, _http_backend) = http_twin(&world).await;
    let mut stdio = world.stdio("t17.log").await;

    let no_key = task_call(json!(2), ECHO, None);
    let undeclared = modern(
        json!(3),
        "tools/call",
        json!({"name": "gateway_invoke",
            "arguments": {"server": helper::BACKEND, "tool": ECHO, "arguments": {}},
            "task": {}, "_meta": {helper::IDEMPOTENCY_KEY_META: "k-undeclared"}}),
        false,
    );
    let mut not_dispatchable = modern(
        json!(4),
        "tools/call",
        json!({"name": "gateway_list_servers", "arguments": {}, "task": {}}),
        true,
    );
    not_dispatchable["params"]["_meta"][helper::IDEMPOTENCY_KEY_META] = json!("k-list");
    let mut continuation = task_call(json!(5), ECHO, Some("k-cont"));
    continuation["params"]["requestState"] = json!("owner2-state");

    for (case, request, expected) in [
        ("no key", no_key, "refused -32602"),
        ("undeclared", undeclared, "refused -32021"),
        ("not dispatchable", not_dispatchable, "not a task"),
        ("continuation", continuation, "not a task"),
    ] {
        let on_http = http.post(&request, None).await;
        let on_stdio = stdio.request(&request).await;
        assert!(
            shape(&on_stdio).starts_with(expected),
            "{case}: expected {expected}, stdio answered {on_stdio}"
        );
        assert_eq!(
            shape(&on_stdio),
            shape(&on_http),
            "{case}: stdio {on_stdio} vs HTTP {on_http}"
        );
    }
    http.stop().await;
    stdio.close().await;
}
