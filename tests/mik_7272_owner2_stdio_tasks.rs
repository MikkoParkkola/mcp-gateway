// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7272.OWNER.2 (I4), store rows: the stdio local operator's task store
//! reopens, relocates, stays separate from another store, and degrades
//! honestly when its lease is held. Rows T1–T5, T7, T8, T12 and T13 of
//! `docs/design/2026-09-30-sub4-stdio-owner-test-plan.md`; design D6 rev 5.

#[path = "mik_7272_owner2_stdio_tasks/helper.rs"]
mod helper;

use std::path::{Path, PathBuf};

use helper::{
    Auth, Backend, ECHO, HttpGateway, MARKER, StdioGateway, declares_tasks, discover, error_code,
    initialize, record_names, task_call, task_id, tasks_get, write_config,
};
use serde_json::{Value, json};

/// One test's temp root, fixture backend and stdio config. HTTP shares the
/// config, so `tasks.store_dir` is `<root>/tasks` for both and stdio derives
/// `<root>/tasks/stdio` (D6 rev 5 item 7).
struct World {
    root: tempfile::TempDir,
    backend: Backend,
    config: PathBuf,
}

impl World {
    async fn new() -> Self {
        let root = tempfile::tempdir().expect("temp root");
        let backend = Backend::start().await;
        let config = write_config(
            root.path(),
            "gateway.yaml",
            &root.path().join("tasks"),
            &backend.url,
            Auth::Off,
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

    fn stdio_store(&self) -> PathBuf {
        self.path().join("tasks").join("stdio")
    }

    async fn stdio(&self, log: &str) -> StdioGateway {
        let mut gateway = StdioGateway::spawn(self.path(), &self.config, log);
        let answer = gateway.request(&initialize(json!(0))).await;
        assert!(
            answer.get("result").is_some(),
            "handshake answered: {answer}"
        );
        gateway
    }

    /// T2's steps: create a keyed `echo` task and read it to completion.
    async fn completed_task(&self, gateway: &mut StdioGateway) -> (String, Value) {
        let created = gateway
            .request(&task_call(json!(1), ECHO, Some("k-owner2")))
            .await;
        let id = task_id(&created);
        let terminal = gateway.terminal(&id).await;
        (id, terminal)
    }
}

fn marker(task: &Value) -> Option<&str> {
    task.pointer("/result/result/structuredContent/marker")
        .and_then(Value::as_str)
}

fn no_such_task(answer: &Value) {
    assert_eq!(error_code(answer), Some(-32602), "{answer}");
    assert_eq!(
        answer.pointer("/error/message").and_then(Value::as_str),
        Some("no such task"),
        "{answer}"
    );
}

/// T1.
#[tokio::test]
async fn stdio_serves_tasks_get_and_says_no_such_task() {
    let world = World::new().await;
    let mut gateway = world.stdio("t1.log").await;
    let answer = gateway.request(&tasks_get(json!(2), "task-absent")).await;
    no_such_task(&answer);
    gateway.close().await;
}

/// T2.
#[tokio::test]
async fn the_local_operator_creates_and_retrieves_a_task() {
    let world = World::new().await;
    let mut gateway = world.stdio("t2.log").await;
    let (_, terminal) = world.completed_task(&mut gateway).await;
    assert_eq!(helper::status(&terminal), Some("completed"), "{terminal}");
    assert_eq!(marker(&terminal), Some(MARKER), "{terminal}");
    assert_eq!(world.backend.rounds(), 1);
    gateway.close().await;
}

/// T3.
#[tokio::test]
async fn the_task_survives_a_reopen() {
    let world = World::new().await;
    let mut first = world.stdio("t3-a.log").await;
    let (id, terminal) = world.completed_task(&mut first).await;
    first.close().await;

    let mut second = StdioGateway::spawn(world.path(), &world.config, "t3-b.log");
    let handshake = second.request(&initialize(json!(0))).await;
    assert!(
        declares_tasks(&handshake),
        "the reopened store is served at once, so Tasks is declared: {handshake}"
    );
    let again = second.request(&tasks_get(json!(2), &id)).await;
    assert_eq!(helper::status(&again), Some("completed"), "{again}");
    assert_eq!(marker(&again), marker(&terminal), "{again}");
    assert_eq!(world.backend.rounds(), 1);
    second.close().await;
}

/// T4.
#[tokio::test]
async fn the_task_survives_a_relocation() {
    let world = World::new().await;
    let mut first = world.stdio("t4-a.log").await;
    let (id, _) = world.completed_task(&mut first).await;
    first.close().await;
    let before = record_names(&world.stdio_store());

    let moved = world.path().join("moved");
    std::fs::rename(world.path().join("tasks"), &moved).expect("relocate the base directory");
    let config = write_config(
        world.path(),
        "moved.yaml",
        &moved,
        &world.backend.url,
        Auth::Off,
    );
    let after = record_names(&moved.join("stdio"));
    assert!(
        !before.is_empty(),
        "stdio wrote its record under <base>/stdio"
    );
    assert_eq!(before, after, "a relocation renames nothing in the store");

    let mut second = StdioGateway::spawn(world.path(), &config, "t4-b.log");
    second.request(&initialize(json!(0))).await;
    let again = second.request(&tasks_get(json!(2), &id)).await;
    assert_eq!(helper::status(&again), Some("completed"), "{again}");
    assert_eq!(marker(&again), Some(MARKER), "{again}");
    second.close().await;

    // HTTP on the relocated base ignores the `stdio` subdirectory.
    let http = HttpGateway::start(world.path(), &config, "t4-http.log").await;
    no_such_task(&http.post(&tasks_get(json!(3), &id), None).await);
    http.stop().await;
}

/// T5.
#[tokio::test]
async fn another_store_does_not_have_it() {
    let world = World::new().await;
    let mut first = world.stdio("t5-a.log").await;
    let (id, _) = world.completed_task(&mut first).await;
    first.close().await;

    let other = world.path().join("other");
    let config = write_config(
        world.path(),
        "other.yaml",
        &other,
        &world.backend.url,
        Auth::Off,
    );
    let mut second = StdioGateway::spawn(world.path(), &config, "t5-b.log");
    second.request(&initialize(json!(0))).await;
    no_such_task(&second.request(&tasks_get(json!(2), &id)).await);
    second.close().await;
}

/// T8.
#[tokio::test]
async fn discover_declares_tasks_when_stdio_serves_them() {
    let world = World::new().await;
    let mut gateway = world.stdio("t8.log").await;
    let answer = gateway.request(&discover(json!(2))).await;
    assert!(declares_tasks(&answer), "{answer}");
    no_such_task(&gateway.request(&tasks_get(json!(3), "task-absent")).await);
    gateway.close().await;
}

/// T7.
#[tokio::test]
async fn a_held_store_degrades_stdio_and_stops_advertising_tasks() {
    let world = World::new().await;
    let mut a = world.stdio("t7-a.log").await;
    // A holds the store: one task proves it opened it.
    world.completed_task(&mut a).await;

    let mut b = StdioGateway::spawn(world.path(), &world.config, "t7-b.log");
    let handshake = b.request(&initialize(json!(0))).await;
    assert!(
        !declares_tasks(&handshake),
        "B advertises no Tasks: {handshake}"
    );
    let found = b.request(&discover(json!(1))).await;
    assert!(
        !declares_tasks(&found),
        "B's discover carries no Tasks: {found}"
    );
    let listed = b
        .request(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "gateway_list_servers", "arguments": {}}}))
        .await;
    assert!(
        listed.get("result").is_some(),
        "B still serves tools: {listed}"
    );
    assert_eq!(
        error_code(&b.request(&tasks_get(json!(3), "task-x")).await),
        Some(-32601)
    );
    let sync = b.request(&task_call(json!(4), ECHO, Some("k-b"))).await;
    assert!(
        sync.pointer("/result/taskId").is_none(),
        "answered synchronously: {sync}"
    );
    assert_eq!(marker_of_sync(&sync), Some(MARKER), "{sync}");
    b.close().await;
    a.close().await;
}

fn marker_of_sync(answer: &Value) -> Option<&str> {
    answer
        .pointer("/result/structuredContent/marker")
        .and_then(Value::as_str)
        .or_else(|| {
            answer
                .pointer("/result/content/0/text")
                .and_then(Value::as_str)
                .filter(|text| text.contains(MARKER))
                .map(|_| MARKER)
        })
}

/// T12.
#[tokio::test]
async fn http_and_stdio_share_a_config_without_contention() {
    let world = World::new().await;
    let mut stdio = world.stdio("t12-stdio.log").await;
    let (stdio_task, _) = world.completed_task(&mut stdio).await;

    let http = HttpGateway::start(world.path(), &world.config, "t12-http.log").await;
    let created = http
        .post(&task_call(json!(10), ECHO, Some("k-http")), None)
        .await;
    let http_task = task_id(&created);

    assert_eq!(
        record_names(&world.stdio_store()),
        vec![format!("{stdio_task}.json")],
        "the stdio subdirectory holds only stdio's record"
    );
    assert!(
        record_names(&world.path().join("tasks")).contains(&format!("{http_task}.json")),
        "HTTP's record is in the base directory"
    );
    no_such_task(&http.post(&tasks_get(json!(11), &stdio_task), None).await);
    no_such_task(&stdio.request(&tasks_get(json!(12), &http_task)).await);
    http.stop().await;
    stdio.close().await;
}

/// T13.
#[tokio::test]
async fn an_explicitly_shared_store_names_the_holder() {
    let world = World::new().await;
    let mut stdio = world.stdio("t13-stdio.log").await;
    let (id, _) = world.completed_task(&mut stdio).await;

    let shared = write_config(
        world.path(),
        "shared.yaml",
        &world.stdio_store(),
        &world.backend.url,
        Auth::Off,
    );
    let (status, log) = HttpGateway::spawn(world.path(), &shared, "t13-http.log")
        .exits_instead_of_serving()
        .await;
    assert!(
        status.is_some_and(|status| !status.success()),
        "HTTP on a held store exits non-zero ({status:?})\n{log}"
    );
    assert!(
        log.contains("possibly a stdio gateway"),
        "the error names the holder\n{log}"
    );
    let again = stdio.request(&tasks_get(json!(2), &id)).await;
    assert_eq!(
        helper::status(&again),
        Some("completed"),
        "the holder is undisturbed: {again}"
    );
    stdio.close().await;
}
