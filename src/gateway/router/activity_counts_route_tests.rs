// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The counts route's bounds, permits, drop flag and cap (rows c12,
//! c13, c14 and c19), through `create_router` on a state of the row's own.
//!
//! Every wait is on the wall clock. A counts read sits in `spawn_blocking`,
//! which holds a paused tokio clock still, so a paused timeout would hang
//! instead of failing. Each leg runs on its own thread under a watchdog, and
//! its requests on a multi-thread runtime that thread is never inside.

use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::process_facts::{COUNT_READS, CountsHook, MAX_CONCURRENT_READS};
use super::tests::{FixtureDir, test_router_app_state_with_auth_and_key_server};
use super::{AppState, ProcessFacts, create_router};
use crate::config::AuthConfig;
use crate::gateway::routes;
use crate::security::TransparencyLogger;
use crate::security::audit::{AuditEnvelope, AuditOutcome, AuditWho, InvocationTarget};
use crate::security::transparency_log::temp::TempLog;
use crate::security::transparency_log::{CorrelationKey, CorrelationSource, TransparencyLogConfig};

const TOKEN: &str = "counts-route-bearer-7e41";
const MIB: u64 = 1 << 20;
/// How long a row waits for something it expects to happen.
const PATIENCE: Duration = Duration::from_secs(20);
/// How long a hook holds a read before it gives up and says so.
const HOLD: Duration = Duration::from_secs(20);

/// What the hook does after recording a pass.
#[derive(Clone, Copy)]
enum Hold {
    Never,
    /// Until the request's drop flag is set.
    UntilDropped,
    /// Until the row releases every held read.
    UntilReleased,
}

/// What the hook saw, shared with the row.
#[derive(Default)]
struct Seen {
    /// `(cap, bytes)` of every pass, in order.
    passes: Mutex<Vec<(u64, u64)>>,
    /// Hook calls so far.
    arrivals: AtomicUsize,
    release: AtomicBool,
    /// A hold ran out before what it waited for happened.
    timed_out: AtomicBool,
}

/// In a hook: wait until `ready`, or note the timeout and let the read go.
fn hold_until(seen: &Seen, ready: impl Fn() -> bool) {
    let deadline = Instant::now() + HOLD;
    while !ready() {
        if Instant::now() >= deadline {
            seen.timed_out.store(true, Ordering::SeqCst);
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn hook(seen: Arc<Seen>, hold: Hold) -> CountsHook {
    CountsHook(Arc::new(
        move |cap: u64, bytes: u64, dropped: &AtomicBool| {
            seen.passes.lock().expect("the passes").push((cap, bytes));
            seen.arrivals.fetch_add(1, Ordering::SeqCst);
            match hold {
                Hold::Never => {}
                Hold::UntilDropped => hold_until(&seen, || dropped.load(Ordering::SeqCst)),
                Hold::UntilReleased => hold_until(&seen, || seen.release.load(Ordering::SeqCst)),
            }
        },
    ))
}

/// Run `leg` on its own thread and fail if it has not finished in 60 s, so
/// a wait the leg forgot to bound fails instead of hanging the run.
fn watched(leg: impl FnOnce() + Send + 'static) {
    let (done_tx, done_rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        leg();
        let _ = done_tx.send(());
    });
    if let Err(mpsc::RecvTimeoutError::Timeout) = done_rx.recv_timeout(Duration::from_secs(60)) {
        panic!("the leg did not finish within 60 s");
    }
    if let Err(panic) = thread.join() {
        std::panic::resume_unwind(panic);
    }
}

/// Wait on the wall clock until `ready`, or fail naming `what` after
/// [`PATIENCE`].
fn wait_until(what: &str, ready: impl Fn() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !ready() {
        assert!(Instant::now() < deadline, "{what}: not within {PATIENCE:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A state of the leg's own: a log, facts carrying the leg's hook and
/// `permits` counts permits, and the router over them.
struct Fx {
    rt: tokio::runtime::Runtime,
    router: axum::Router,
    state: Arc<AppState>,
    seen: Arc<Seen>,
    log: Arc<TransparencyLogger>,
    _keep: (FixtureDir, TempLog),
}

fn fixture(hold: Hold, permits: usize) -> Fx {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime");
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(TOKEN.to_owned()),
        ..AuthConfig::default()
    };
    let (mut state, dir) = rt.block_on(test_router_app_state_with_auth_and_key_server(&auth, None));
    let temp = TempLog::new();
    let config = TransparencyLogConfig {
        enabled: true,
        path: temp.path().display().to_string(),
        key_id: "counts".to_owned(),
        ..TransparencyLogConfig::default()
    };
    let log = Arc::new(TransparencyLogger::open(Arc::new(config)).expect("a logger"));
    let seen = Arc::new(Seen::default());
    let facts = ProcessFacts::default().with_counts(hook(Arc::clone(&seen), hold), permits);
    let unique = Arc::get_mut(&mut state).expect("one owner");
    unique.transparency_log = Some(Arc::clone(&log));
    unique.process = Arc::new(facts);
    let router = create_router(Arc::clone(&state));
    Fx {
        rt,
        router,
        state,
        seen,
        log,
        _keep: (dir, temp),
    }
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))))
        .body(Body::empty())
        .expect("a request")
}

/// What one request answered: its status and its JSON body.
type Answered = mpsc::Receiver<(StatusCode, Value)>;

impl Fx {
    /// `calls` plain calls through the logger, stamped now.
    fn write(&self, calls: usize) {
        for i in 0..calls {
            let tool = format!("call_{i}");
            self.log
                .log_invocation("route", "admin", "srv", &tool, "sha256:aa", "sha256:bb")
                .expect("written");
        }
    }

    /// `calls` calls the gateway refused, through the logger, stamped now.
    fn refuse(&self, calls: usize) {
        let refusal = AuditEnvelope {
            outcome: AuditOutcome::Denied(-32001),
            ..AuditEnvelope::ok(AuditWho::from_actor_id("admin"))
        };
        for i in 0..calls {
            let key = CorrelationKey {
                id: "route",
                source: CorrelationSource::SessionId,
            };
            let tool = format!("refused_{i}");
            let target = InvocationTarget::meta("srv", &tool);
            self.log
                .log_invocation_correlated(key, &refusal, target, "sha256:aa", None)
                .expect("written");
        }
    }

    /// Calls until the log holds more than `bytes`.
    fn fill(&self, bytes: u64) {
        let size = || std::fs::metadata(self.log.path()).map_or(0, |m| m.len());
        while size() <= bytes {
            self.write(500);
        }
    }

    /// Send `uri` as the bearer caller. Its answer arrives on the channel;
    /// aborting the task drops the request.
    fn send(&self, uri: &str) -> (Answered, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel();
        let (router, request) = (self.router.clone(), get(uri));
        let task = self.rt.spawn(async move {
            let response = router.oneshot(request).await.expect("the router answers");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("a body");
            let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            let _ = tx.send((status, body));
        });
        (rx, task)
    }

    fn counts_permits(&self) -> usize {
        self.state.process.counts_reads().available_permits()
    }

    fn read_slots(&self) -> usize {
        self.state.process.activity_reads().available_permits()
    }

    fn arrivals(&self) -> usize {
        self.seen.arrivals.load(Ordering::SeqCst)
    }

    fn passes(&self) -> Vec<(u64, u64)> {
        self.seen.passes.lock().expect("the passes").clone()
    }

    fn timed_out(&self) -> bool {
        self.seen.timed_out.load(Ordering::SeqCst)
    }

    fn release(&self) {
        self.seen.release.store(true, Ordering::SeqCst);
    }
}

fn now() -> DateTime<Utc> {
    crate::clock::utc_now().expect("a clock")
}

fn hours(h: i64) -> TimeDelta {
    TimeDelta::try_hours(h).expect("hours in range")
}

/// The counts route with `from` and `to` as given.
fn uri(from: Option<DateTime<Utc>>, to: Option<DateTime<Utc>>) -> String {
    let stamp = |t: DateTime<Utc>| t.to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut params = Vec::new();
    if let Some(from) = from {
        params.push(format!("from={}", stamp(from)));
    }
    if let Some(to) = to {
        params.push(format!("to={}", stamp(to)));
    }
    format!("{}?{}", routes::UI_ACTIVITY_COUNTS, params.join("&"))
}

/// The counts route over the two hours around now.
fn counts_uri() -> String {
    uri(Some(now() - hours(1)), Some(now() + hours(1)))
}

#[test]
fn c12_bounds_are_checked_before_a_slot_or_a_byte() {
    watched(|| {
        let fx = fixture(Hold::Never, COUNT_READS);
        // Both counts permits and every read slot of this state are held.
        let process = &fx.state.process;
        let counts = Arc::clone(process.counts_reads()).try_acquire_many_owned(2);
        let slots = Arc::clone(process.activity_reads()).try_acquire_many_owned(4);
        let held = (counts.expect("both permits"), slots.expect("every slot"));
        let t = now();
        let both = "`from` and `to` are both required";
        let after = "`to` must be after `from`";
        let legs = [
            ("no from", uri(None, Some(t)), both),
            ("no to", uri(Some(t), None), both),
            ("to equals from", uri(Some(t), Some(t)), after),
            ("to before from", uri(Some(t), Some(t - hours(1))), after),
        ];
        for (leg, uri, error) in legs {
            let (answered, _task) = fx.send(&uri);
            let Ok((status, body)) = answered.recv_timeout(Duration::from_secs(2)) else {
                panic!("{leg}: no answer in 2 s, so it waited for a slot first");
            };
            assert_eq!(status, StatusCode::BAD_REQUEST, "{leg}");
            assert_eq!(body, json!({ "error": error }), "{leg}");
        }
        assert!(fx.passes().is_empty(), "a refused read read nothing");
        drop(held);
        let second = TimeDelta::try_seconds(1).expect("a second");
        let (answered, _task) = fx.send(&uri(Some(t), Some(t + second)));
        let (status, _) = answered.recv_timeout(PATIENCE).expect("an answer");
        assert_eq!(status, StatusCode::OK);
    });
}

/// A read stopped by its caller: the hook saw the drop, the read took
/// exactly one pass of under 3 MiB, and both of its permits came back.
fn assert_stopped_after_one_pass(fx: &Fx, leg: &str) {
    let back = || fx.counts_permits() == COUNT_READS && fx.read_slots() == MAX_CONCURRENT_READS;
    let what = format!("{leg}: both permits back");
    wait_until(&what, back);
    assert!(!fx.timed_out(), "{leg}: the hook never saw the drop");
    let passes = fx.passes();
    assert_eq!(passes.len(), 1, "{leg}: {passes:?}");
    assert!(passes[0].1 < 3 * MIB, "{leg}: {passes:?}");
}

#[test]
fn c13_an_aborted_request_stops_reading() {
    // (a) The request's future is dropped after the first pass.
    watched(|| {
        let fx = fixture(Hold::UntilDropped, COUNT_READS);
        fx.fill(12 * MIB);
        let (_answered, task) = fx.send(&counts_uri());
        wait_until("the read's first pass", || fx.arrivals() >= 1);
        task.abort();
        assert_stopped_after_one_pass(&fx, "dropped future");
    });
    // (b) A real client sends one bodiless GET, then closes its connection.
    watched(|| {
        let fx = fixture(Hold::UntilDropped, COUNT_READS);
        fx.fill(12 * MIB);
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("an address");
        let app = fx
            .router
            .clone()
            .into_make_service_with_connect_info::<SocketAddr>();
        let _server = fx.rt.spawn(async move {
            axum_server::from_tcp(listener)
                .expect("a server")
                .serve(app)
                .await
        });
        let mut client = TcpStream::connect(addr).expect("connected");
        let head = format!(
            "GET {} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {TOKEN}\r\n\r\n",
            counts_uri()
        );
        client.write_all(head.as_bytes()).expect("sent");
        wait_until("the read's first pass", || fx.arrivals() >= 1);
        drop(client);
        assert_stopped_after_one_pass(&fx, "closed connection");
    });
    // A1: the same read, not dropped, goes on past its first pass.
    watched(|| {
        let fx = fixture(Hold::Never, COUNT_READS);
        fx.fill(12 * MIB);
        let (answered, _task) = fx.send(&counts_uri());
        let (status, _) = answered.recv_timeout(PATIENCE).expect("an answer");
        assert_eq!(status, StatusCode::OK);
        let passes = fx.passes();
        let read: u64 = passes.iter().map(|p| p.1).sum();
        assert!(passes.len() > 1 && read > 10 * MIB, "{passes:?}");
    });
}

/// Every held counts read answers once released.
fn answer_all(held: Vec<(Answered, tokio::task::JoinHandle<()>)>) {
    for (answered, _task) in held {
        let answer = answered.recv_timeout(PATIENCE);
        assert!(answer.is_ok(), "a counts read answers");
    }
}

#[test]
fn c14_counts_leave_the_list_two_slots() {
    assert_eq!(COUNT_READS, 2);
    // (a) Two counts reads are held; a third waits; a list read is served.
    watched(|| {
        let fx = fixture(Hold::UntilReleased, COUNT_READS);
        let held: Vec<_> = (0..3).map(|_| fx.send(&counts_uri())).collect();
        let two_held = || fx.arrivals() == 2;
        wait_until("two counts reads at the hook", two_held);
        let settle = Instant::now() + Duration::from_millis(500);
        while Instant::now() < settle {
            assert_eq!(fx.arrivals(), 2, "a third counts read got past its permit");
            std::thread::sleep(Duration::from_millis(10));
        }
        let list = format!("{}?server=srv", routes::UI_ACTIVITY);
        let (answered, _task) = fx.send(&list);
        let served = answered.recv_timeout(Duration::from_secs(2));
        assert_eq!(served.map(|(status, _)| status), Ok(StatusCode::OK));
        fx.release();
        // Premise: the third was waiting, not lost.
        wait_until("the third counts read", || fx.arrivals() == 3);
        answer_all(held);
        assert!(!fx.timed_out());
    });
    // (b) Six at once: the shared pool keeps two free slots throughout.
    watched(|| {
        let fx = fixture(Hold::UntilReleased, COUNT_READS);
        let held: Vec<_> = (0..6).map(|_| fx.send(&counts_uri())).collect();
        let two_held = || fx.arrivals() == 2;
        wait_until("two counts reads at the hook", two_held);
        for sample in 0..20 {
            // Free shared slots, and counts reads at the hook.
            let seen = (fx.read_slots(), fx.arrivals());
            assert_eq!(seen, (2, 2), "sample {sample}");
            // timing: absence
            std::thread::sleep(Duration::from_millis(10));
        }
        fx.release();
        answer_all(held);
        assert!(!fx.timed_out());
    });
    // A7: with three counts permits the third read reaches the hook.
    watched(|| {
        let fx = fixture(Hold::UntilReleased, 3);
        let held: Vec<_> = (0..3).map(|_| fx.send(&counts_uri())).collect();
        let three_held = || fx.arrivals() == 3;
        wait_until("three counts reads at the hook", three_held);
        fx.release();
        answer_all(held);
    });
}

#[test]
fn c19_one_scan_per_request_with_the_64_mib_cap() {
    watched(|| {
        let fx = fixture(Hold::Never, COUNT_READS);
        fx.refuse(5);
        let (answered, _task) = fx.send(&counts_uri());
        let (status, body) = answered.recv_timeout(PATIENCE).expect("an answer");
        assert_eq!(status, StatusCode::OK);
        // One scan of one pass, under the 64 MiB cap.
        let caps: Vec<u64> = fx.passes().iter().map(|p| p.0).collect();
        assert_eq!(caps, [67_108_864]);
        assert_eq!(body["counts"]["blocked"], 5);
    });
}
