// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A store holding a share of its temporary directory keeps it until its last
//! write: a worker's write landing while a test removed the directory left the
//! folder behind in the shared temp directory.

use super::support::*;
use super::*;

#[tokio::test]
async fn a_planted_late_write_after_test_end_leaves_no_folder() {
    let root = Arc::new(tempfile::tempdir().unwrap());
    let root_path = root.path().to_owned();
    let store = open(&root_path.join("tasks")).await;
    store.keep_test_dir(Arc::clone(&root));
    // The test body ends: its own share of the directory goes first.
    drop(root);
    // A worker's handle outlives the test body and writes after it ends.
    let worker = store.clone();
    drop(store);
    let task = task();
    worker
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .expect("the late write lands in the still-owned directory");
    assert!(
        root_path
            .join("tasks")
            .join(format!("{}.json", task.id()))
            .is_file()
    );

    drop(worker);

    assert!(
        !root_path.exists(),
        "the store's directory outlived its last handle"
    );
}

/// The openers that start task workers, recovery, an expiry sweep or the
/// events runtime: a test that calls one owns a writer that can outlive it.
const WORKER_OPENERS: [&str; 9] = [
    "open_runtime(",
    "open_runtime_with_admission(",
    "open_runtime_with_recovery(",
    "stdio_tasks::open(",
    "TaskExecutor::new(",
    // The server tests' reopen of a stdio store, as the next process would.
    "reopen_stdio_store(",
    // The events hub's runtime: fan-out, delivery and the startup replay
    // that rewrites subscription rows.
    "hub.start(",
    // Events delivery driven directly: an attempt settles its record and
    // rewrites its subscription's status on the blocking pool.
    "deliver_forever(",
    ".attempt(&",
];

/// Test files that name an opener but start no unkept store, with why.
const NO_STORE: &[(&str, &str)] = &[
    (
        "src/events/worker_settle_dir_tests.rs",
        "opens its hub through worker_fixtures_tests::delivery_hub, which keeps the folder",
    ),
    (
        "src/gateway/task_service/runtime_tests/admission_clock.rs",
        "names open_runtime in a source string it checks; opens no store",
    ),
];

/// Whether `text` starts a worker-bearing store and never keeps its folder.
fn unkept(text: &str) -> bool {
    WORKER_OPENERS.iter().any(|opener| text.contains(opener)) && !text.contains("keep_test_dir")
}

fn test_sources(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            test_sources(&path, root, out);
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/");
        let is_test =
            rel.contains("/tests/") || rel.contains("_tests") || rel.ends_with("tests.rs");
        if is_test && rel.ends_with(".rs") {
            out.push((rel, std::fs::read_to_string(&path).expect("read source")));
        }
    }
}

/// Every test file that starts a task worker hands its store the folder it
/// lives in, so no worker's write outlives the folder.
#[test]
fn every_test_that_starts_task_workers_keeps_its_store_folder() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    test_sources(&root.join("src"), root, &mut sources);
    let exempt: std::collections::BTreeSet<&str> = NO_STORE.iter().map(|(path, _)| *path).collect();
    let unkept_files: Vec<&str> = sources
        .iter()
        .filter(|(rel, text)| !exempt.contains(rel.as_str()) && unkept(text))
        .map(|(rel, _)| rel.as_str())
        .collect();
    assert!(
        unkept_files.is_empty(),
        "test files start task workers without keep_test_dir (hand the store its folder, \
         or list the file in NO_STORE with why): {unkept_files:?}"
    );
    let stale: Vec<&&str> = exempt
        .iter()
        .filter(|path| {
            !sources
                .iter()
                .any(|(rel, text)| rel == *path && unkept(text))
        })
        .collect();
    assert!(
        stale.is_empty(),
        "NO_STORE rows with nothing left to exempt: {stale:?}"
    );
}

#[test]
fn the_scan_sees_an_unkept_opener_and_passes_a_kept_one() {
    assert!(unkept(
        "let (s, e) = open_runtime(&dir, 1, limits, subs).await?;"
    ));
    assert!(unkept("let x = TaskExecutor::new(service, subs, 1);"));
    assert!(!unkept(
        "let (s, e) = open_runtime(&d, 1, l, s).await?;\ns.keep_test_dir(root);"
    ));
    assert!(!unkept("let store = open(&dir).await;"));
}
