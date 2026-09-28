// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1808: a reload's file load runs off the async workers.
//!
//! A real stall needs an NFS or FUSE mount (env files open non-blocking, so a
//! FIFO is refused rather than stalled), so each test injects the load. Every
//! injected load that returns does so with `Err`, so no test reaches
//! `apply_patch`. Each test owns its statics; tests run in parallel.
//!
//! A pinned runtime cannot be timed out from inside itself, so the stall tests
//! run their runtime on a thread of their own and wait on a channel with a
//! deadline: today's code fails them in 5 s instead of hanging the suite.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;

const DEADLINE: Duration = Duration::from_secs(5);

/// A context with no backends, no env files and no grants file.
fn context() -> ReloadContext {
    ReloadContext::new(
        PathBuf::from("unused-the-load-is-injected.yaml"),
        Arc::new(LiveConfig::new(Config::default())),
        Arc::new(BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
}

/// Block this thread for good; a stalled NFS read, as far as the caller can tell.
fn stall_forever() -> ! {
    loop {
        std::thread::park();
    }
}

static S1_ENTERED: AtomicBool = AtomicBool::new(false);

fn s1_load(
    _: &std::path::Path,
    _: &Arc<LiveConfig>,
    _: &LiveEnv,
) -> std::result::Result<EvaluatedReload, String> {
    S1_ENTERED.store(true, Ordering::SeqCst);
    stall_forever()
}

#[test]
fn s1_a_stalled_load_leaves_the_worker_free() {
    let (reported, report) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async move {
            let ctx = Arc::new(context().with_load(s1_load));
            tokio::spawn(async move { drop(ctx.reload_outcome().await) });
            // Runs only while the single worker is free: on today's code the
            // load holds it, so this loop never resumes after its first sleep.
            while !S1_ENTERED.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            reported.send(()).expect("report");
        });
    });
    assert!(
        report.recv_timeout(DEADLINE).is_ok(),
        "a stalled reload load held the runtime's only worker"
    );
}

static S2_ENTERED: AtomicBool = AtomicBool::new(false);

fn s2_load(
    _: &std::path::Path,
    _: &Arc<LiveConfig>,
    _: &LiveEnv,
) -> std::result::Result<EvaluatedReload, String> {
    S2_ENTERED.store(true, Ordering::SeqCst);
    stall_forever()
}

#[test]
fn s2_shutdown_completes_with_a_load_stalled() {
    let (reported, report) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        rt.spawn(async move {
            let ctx = context().with_load(s2_load);
            drop(ctx.reload_outcome().await);
        });
        while !S2_ENTERED.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }
        // The gateway's own shutdown: the runtime in `main` is dropped.
        drop(rt);
        reported.send(()).expect("report");
    });
    assert!(
        report.recv_timeout(DEADLINE).is_ok(),
        "runtime shutdown waited on a stalled reload load"
    );
}

/// The load's thread name, and whether it ran with a Tokio runtime in context.
static S3_SEEN: Mutex<Option<(Option<String>, bool)>> = Mutex::new(None);

fn s3_load(
    _: &std::path::Path,
    _: &Arc<LiveConfig>,
    _: &LiveEnv,
) -> std::result::Result<EvaluatedReload, String> {
    let name = std::thread::current().name().map(str::to_owned);
    let in_runtime = tokio::runtime::Handle::try_current().is_ok();
    *S3_SEEN.lock().expect("s3 lock") = Some((name, in_runtime));
    Err("s3 recorded".to_owned())
}

#[tokio::test]
async fn s3_the_load_runs_on_a_named_thread_off_the_runtime() {
    let refused = context()
        .with_load(s3_load)
        .reload_outcome()
        .await
        .expect_err("the injected load refuses");
    assert!(refused.contains("s3 recorded"), "{refused}");
    let seen = S3_SEEN.lock().expect("s3 lock").clone();
    let (name, in_runtime) = seen.expect("the injected load ran");
    assert_eq!(name.as_deref(), Some("config-reload"), "load thread name");
    assert!(!in_runtime, "the load ran with a Tokio runtime in context");
}

fn s4_load(
    _: &std::path::Path,
    _: &Arc<LiveConfig>,
    _: &LiveEnv,
) -> std::result::Result<EvaluatedReload, String> {
    panic!("s4: the load panicked");
}

#[tokio::test]
async fn s4_a_load_that_panics_is_a_refusal() {
    let ctx = Arc::new(context().with_load(s4_load));
    let (config, overlay) = (ctx.live_config.get(), ctx.env.get());
    let task = tokio::spawn({
        let ctx = Arc::clone(&ctx);
        async move { ctx.reload_outcome().await }
    });
    let refused = match task.await {
        Ok(Err(refused)) => refused,
        Ok(Ok(outcome)) => panic!("a panicking load reloaded: {}", outcome.changes),
        Err(join) => panic!("the load's panic unwound the reload task: {join}"),
    };
    assert!(refused.contains("ended without a result"), "{refused}");
    assert!(
        Arc::ptr_eq(&config, &ctx.live_config.get()),
        "config published"
    );
    assert!(Arc::ptr_eq(&overlay, &ctx.env.get()), "overlay published");
}

static S5_ENTRIES: AtomicUsize = AtomicUsize::new(0);
static S5_OPEN: AtomicBool = AtomicBool::new(false);

fn s5_load(
    _: &std::path::Path,
    _: &Arc<LiveConfig>,
    _: &LiveEnv,
) -> std::result::Result<EvaluatedReload, String> {
    S5_ENTRIES.fetch_add(1, Ordering::SeqCst);
    while !S5_OPEN.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(5));
    }
    Err("s5 released".to_owned())
}

/// A cancelled reload whose read is still stalled must not let the next
/// reload start a second read thread: a client retrying a reload during an
/// NFS stall would otherwise add one stuck thread per attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s5_a_cancelled_stalled_reload_starts_no_second_read() {
    let ctx = Arc::new(context().with_load(s5_load));
    let first = tokio::spawn({
        let ctx = Arc::clone(&ctx);
        async move { ctx.reload_outcome().await }
    });
    tokio::time::timeout(DEADLINE, async {
        while S5_ENTRIES.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the first load started");
    // Awaited only briefly: on a pinned worker the abort lands only once the
    // load returns, so today this wait simply runs out and the reload lock is
    // what holds the second reload back.
    first.abort();
    drop(tokio::time::timeout(Duration::from_secs(1), first).await);
    let second = tokio::spawn({
        let ctx = Arc::clone(&ctx);
        async move { ctx.reload_outcome().await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        S5_ENTRIES.load(Ordering::SeqCst),
        1,
        "a second load started while the first was still stalled"
    );
    S5_OPEN.store(true, Ordering::SeqCst);
    let refused = tokio::time::timeout(DEADLINE, second)
        .await
        .expect("the second reload finished")
        .expect("the second reload task")
        .expect_err("the injected load refuses");
    assert!(refused.contains("s5 released"), "{refused}");
    assert_eq!(S5_ENTRIES.load(Ordering::SeqCst), 2);
}

fn s6_load(
    _: &std::path::Path,
    _: &Arc<LiveConfig>,
    _: &LiveEnv,
) -> std::result::Result<EvaluatedReload, String> {
    Err("s6 refused".to_owned())
}

#[tokio::test]
async fn s6_a_failed_load_publishes_nothing() {
    let ctx = context().with_load(s6_load);
    let (config, overlay) = (ctx.live_config.get(), ctx.env.get());
    let refused = ctx.reload_outcome().await.expect_err("the load refuses");
    assert!(refused.contains("s6 refused"), "{refused}");
    assert!(
        Arc::ptr_eq(&config, &ctx.live_config.get()),
        "config published"
    );
    assert!(Arc::ptr_eq(&overlay, &ctx.env.get()), "overlay published");
}

fn s7_load(
    _: &std::path::Path,
    _: &Arc<LiveConfig>,
    _: &LiveEnv,
) -> std::result::Result<EvaluatedReload, String> {
    Err("s7: the load ran although its thread never started".to_owned())
}

fn s7_refuse_spawn(_load: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
    Err(std::io::Error::other("s7: no threads left"))
}

#[tokio::test]
async fn s7_a_read_that_cannot_start_is_a_refusal() {
    let ctx = context().with_load(s7_load).with_spawn(s7_refuse_spawn);
    let (config, overlay) = (ctx.live_config.get(), ctx.env.get());
    for attempt in 1..=2 {
        // The second attempt proves the first released the lock and the slot.
        let refused = tokio::time::timeout(DEADLINE, ctx.reload_outcome())
            .await
            .unwrap_or_else(|_| panic!("reload {attempt} did not finish"))
            .expect_err("a load that cannot start refuses");
        assert!(refused.contains("could not start"), "{refused}");
    }
    assert!(
        Arc::ptr_eq(&config, &ctx.live_config.get()),
        "config published"
    );
    assert!(Arc::ptr_eq(&overlay, &ctx.env.get()), "overlay published");
}
