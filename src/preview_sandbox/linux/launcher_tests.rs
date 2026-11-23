// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the launch half that need no namespaces: the teardown's cap and
//! wait (R34s, R21b), the control socket's bind (R44), the isolation record's
//! fetch value at its one call site (R15b), and the launch's handling of
//! each status ending with a stand-in helper (R41, launch half).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::*;
use crate::preview_sandbox::control::ControlBounds;
use crate::preview_sandbox::linux::plan::NpmFetch;

/// A real child that outlives every row unless killed.
fn sleeper() -> Child {
    tokio::process::Command::new("sleep")
        .arg("300")
        .kill_on_drop(true)
        .spawn()
        .expect("sleep")
}

fn never(_: &mut Child) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
    Box::pin(std::future::pending())
}

fn after_4900_ms(_: &mut Child) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
    Box::pin(tokio::time::sleep(Duration::from_millis(4900)))
}

static WAITED: AtomicBool = AtomicBool::new(false);

fn after_1_s(child: &mut Child) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
    Box::pin(async move {
        let _ = child.wait().await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        WAITED.store(true, Ordering::SeqCst);
    })
}

/// R34s, kills m-block-on-reap and m-cap-other: a reap that never ends gives
/// the killed process back at exactly the cap; one that ends at 4.9 s gives
/// nothing back.
#[tokio::test(start_paused = true)]
async fn r34s_the_teardown_returns_at_its_cap_with_the_process_unreaped() {
    let begun = tokio::time::Instant::now();
    let refusal = Refusal::Step("x".into());
    let guard = Duration::from_secs(6);
    let failed = tokio::time::timeout(guard, tear_down(sleeper(), refusal.clone(), never))
        .await
        .expect("the teardown ended within its own guard");
    assert_eq!(begun.elapsed(), TEARDOWN_CAP);
    assert_eq!(failed.refusal, refusal);
    assert!(failed.unreaped.is_some(), "the unreaped process rides back");

    let begun = tokio::time::Instant::now();
    let failed = tear_down(sleeper(), refusal, after_4900_ms).await;
    assert_eq!(begun.elapsed(), Duration::from_millis(4900));
    assert!(
        failed.unreaped.is_none(),
        "reaped in time: nothing rides back"
    );
}

/// R21b, kills m-return-before-reap: the teardown returns only once its wait
/// for the killed process ended.
#[tokio::test]
async fn r21b_the_teardown_returns_only_after_the_reap() {
    WAITED.store(false, Ordering::SeqCst);
    let failed = tear_down(sleeper(), Refusal::Step("x".into()), after_1_s).await;
    assert!(
        WAITED.load(Ordering::SeqCst),
        "returned before the wait ended"
    );
    assert!(failed.unreaped.is_none());
}

fn sh() -> Target {
    Target {
        program: PathBuf::from("/bin/sh"),
        args: Vec::new(),
    }
}

fn ambient(runtime_dir: &Path) -> Ambient {
    Ambient {
        ca_bundle: None,
        runtime_dir: Some(OsString::from(runtime_dir)),
        path: std::env::var_os("PATH"),
    }
}

/// R44, kills m-no-listener and m-leak-dir: a runtime directory so long that
/// the control socket's path cannot be a Unix socket address refuses at the
/// bind, naming it, and leaves no directory behind.
#[tokio::test]
async fn r44_a_control_path_too_long_refuses_at_the_bind_and_leaves_nothing() {
    let base = tempfile::tempdir().expect("base");
    let long = base.path().join("d".repeat(120));
    std::fs::create_dir(&long).expect("long dir");
    let refused = prepare(&sh(), &[], ambient(&long), Phase::Run).err();
    assert!(
        matches!(&refused, Some(Refusal::Step(s)) if s.starts_with("binding the control socket (")),
        "{refused:?}"
    );
    let left = std::fs::read_dir(&long).expect("long dir").count();
    assert_eq!(
        left, 0,
        "the control socket's directory outlived the refusal"
    );
}

/// A `Prepared` around `proxy` with `fetch` as the plan's fetch.
fn prepared_with(proxy: AllowlistProxy, npm: Option<NpmFetch>) -> Prepared {
    let mut plan = build_plan(&sh(), &[], std::env::var_os("PATH").as_deref()).expect("plan");
    plan.fetch = Some(FetchPaths {
        ca: "/run/x/ca.pem".into(),
        npm,
        uv: None,
    });
    Prepared {
        unshare: Path::new("/usr/bin/unshare"),
        plan,
        listener: None,
        proxy: Some(proxy),
        _control_dir: None,
    }
}

fn npm() -> NpmFetch {
    NpmFetch {
        spec: "a".into(),
        run_args: Vec::new(),
        npm: "/usr/bin/npm".into(),
        node_dir: "/usr/bin".into(),
        ip: "/usr/sbin/ip".into(),
        proxy: "/run/x/proxy.sock".into(),
    }
}

fn proxy(runtime: &Path) -> AllowlistProxy {
    AllowlistProxy::bind(
        Some(OsString::from(runtime)),
        Arc::new(System),
        Arc::new(System),
        Arc::new(System),
    )
    .expect("proxy")
}

/// R15b, kills m-fetch-left-none, m-separate-label and m-join: the record a
/// started preview gets names the proxy's own allowlist, as the proxy
/// enforces it, only when the plan fetches a package.
#[tokio::test]
async fn r15b_the_record_names_the_proxys_own_allowlist() {
    let runtime = tempfile::tempdir().expect("runtime");
    let swapped = proxy(runtime.path());
    swapped.set_allowlist_for_test(&["a.test:443", "b.test:443"]);
    let prepared = prepared_with(swapped, Some(npm()));
    assert_eq!(
        prepared.isolation().network.fetch.as_deref(),
        Some("a.test:443, b.test:443")
    );
    let handshake_only = prepared_with(proxy(runtime.path()), None);
    assert_eq!(handshake_only.isolation().network.fetch, None);
    let plain = prepared_with(proxy(runtime.path()), Some(npm()));
    assert_eq!(
        plain.isolation().network.fetch.as_deref(),
        Some("registry.npmjs.org:443, pypi.org:443, files.pythonhosted.org:443")
    );
}

/// The bounds the R41 rows run under: short, so a held connection ends fast.
/// The frame bound is a whole second: the rows that must start also run under
/// it, and a loaded host must not turn their prompt status line into a refusal.
const SHORT: ControlBounds = ControlBounds {
    accept: Duration::from_secs(5),
    frame: Duration::from_secs(1),
    setup: Duration::from_secs(5),
};

/// A stand-in helper: Python connects to the control socket, writes `lines`
/// (each ended by a newline) and either closes or holds the connection
/// until the gateway closes it.
/// Its parent is the spawned process, which then becomes `sleep 300`, so
/// the launch's peer check passes as for the real helper.
fn stand_in(lines: &[&str], hold: bool) -> impl FnOnce(&Plan) -> Result<Child, Refusal> {
    // Holding means waiting for the gateway's close, so a refusal (which
    // closes the connection) also ends the stand-in.
    let script = format!(
        "import socket,sys\n\
         s=socket.socket(socket.AF_UNIX)\ns.connect(sys.argv[1])\n\
         s.sendall({:?}.encode())\n\
         {}\n",
        lines.iter().flat_map(|l| [*l, "\n"]).collect::<String>(),
        if hold { "s.recv(1)" } else { "s.close()" }
    );
    move |plan: &Plan| {
        let python = ["/usr/bin/python3", "/bin/python3"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
            .expect("python3 for the stand-in helper");
        tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("\"$0\" -c \"$1\" \"$2\" & exec sleep 300")
            .arg(python)
            .arg(&script)
            .arg(&plan.control)
            .kill_on_drop(true)
            // Piped, as the real launch's is, so a row can see the launch keep it.
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Refusal::Step(format!("the stand-in ({e})")))
    }
}

/// One launch against `lines`: its answer, and whether the spawned process
/// was still in `/proc` when the launch returned.
async fn launch_against(
    lines: &[&str],
    hold: bool,
    within: Duration,
) -> (Result<Started, StartFailed>, bool) {
    let runtime = tempfile::tempdir().expect("runtime");
    let mut prepared = prepare(&sh(), &[], ambient(runtime.path()), Phase::Run).expect("prepared");
    let pid = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let seen = pid.clone();
    let spawn = stand_in(lines, hold);
    let spawn = move |plan: &Plan| {
        let child = spawn(plan)?;
        seen.store(child.id().unwrap_or(0), Ordering::SeqCst);
        Ok(child)
    };
    let deadline = tokio::time::Instant::now() + within;
    let (launched, _) = launch_with(&mut prepared, spawn, deadline, SHORT, reap_exit).await;
    let alive = Path::new(&format!("/proc/{}", pid.load(Ordering::SeqCst))).exists();
    (launched, alive)
}

/// R41 (launch half), kills m-default-done, m-accept-second, m-unbounded-wait
/// and m-no-eof-check at the launch: each ending that is not one status then
/// the close is "no valid status", a reported refusal is its step, a silent
/// open connection is the deadline's refusal, and on every refusal the
/// spawned process is killed and reaped before the launch returns. Positive
/// control: one `setup_done` then the close starts.
#[tokio::test]
async fn r41_each_status_ending_at_the_launch() {
    const NO_STATUS: &str = "the sandbox helper sent no valid status";
    let done = r#"{"setup_done":true}"#;
    let refused = r#"{"setup_refused":true,"step":"binding","denied":false}"#;
    let cases: [(&str, &[&str], bool, Refusal); 5] = [
        (
            "closed with no line",
            &[],
            false,
            Refusal::Step(NO_STATUS.into()),
        ),
        (
            "a malformed line",
            &["{\"setup\":1}"],
            false,
            Refusal::Step(NO_STATUS.into()),
        ),
        (
            "a second status",
            &[done, done],
            false,
            Refusal::Step(NO_STATUS.into()),
        ),
        (
            "held open after the status",
            &[done],
            true,
            Refusal::Step(NO_STATUS.into()),
        ),
        (
            "binding refused",
            &[refused],
            false,
            Refusal::Step("binding".into()),
        ),
    ];
    let mut wrong = Vec::new();
    let roomy = Duration::from_secs(20);
    // Connected and silent, with a deadline before the setup bound (5 s):
    // the deadline's own refusal.
    let late = Refusal::Step("the preview's deadline passed before the sandbox's status".into());
    let silent: [(&str, &[&str], bool, Refusal); 1] = [("silent and open", &[], true, late)];
    let runs = cases
        .into_iter()
        .map(|case| (case, roomy))
        .chain(silent.map(|case| (case, Duration::from_secs(2))));
    for ((name, lines, hold, want), within) in runs {
        let (launched, alive) = launch_against(lines, hold, within).await;
        match launched {
            Err(failed) if failed.refusal == want && failed.unreaped.is_none() && !alive => {}
            Err(failed) => wrong.push(format!(
                "{name}: {:?}, unreaped {}, alive {alive}",
                failed.refusal,
                failed.unreaped.is_some()
            )),
            Ok(_) => wrong.push(format!("{name}: started")),
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    let (started, _) = launch_against(&[done], false, roomy).await;
    assert!(started.is_ok(), "one setup_done then the close starts");
}

/// Kills m-wait-closes-stdin: a started preview still holds its stdin. The
/// caller speaks MCP on it, and a held helper or a target reading it would
/// otherwise see the end of input at once. tokio's `Child::wait` closes the
/// child's stdin when first polled, and the launch races it against the
/// session.
#[tokio::test]
async fn a_started_preview_keeps_its_stdin_open() {
    let done = r#"{"setup_done":true}"#;
    let (launched, _) = launch_against(&[done], false, Duration::from_secs(20)).await;
    let Ok(started) = launched else {
        panic!("one setup_done then the close should start");
    };
    assert!(
        started.child.stdin.is_some(),
        "the launch closed the preview's stdin"
    );
}

/// D3, pins where the fetch step's clock starts: at the launch, so a fetch
/// refusal's time holds a delay inside the launch (1 s, before the spawn)
/// and not the 4 s between the prepare and the launch. A clock started
/// earlier reads 5 s or more; one started after the spawn reads under 1 s.
/// The 4 s of room above the inner delay is for a slow start under load.
#[tokio::test]
async fn the_fetch_steps_clock_starts_at_the_launch() {
    let runtime = tempfile::tempdir().expect("runtime");
    let mut prepared = prepared_with(proxy(runtime.path()), Some(npm()));
    let control = runtime.path().join("control.sock");
    prepared.listener = Some(tokio::net::UnixListener::bind(&control).expect("listener"));
    prepared.plan.control = control.to_str().expect("UTF-8 runtime path").to_owned();
    // The prepare is over; the launch comes 4 s later.
    tokio::time::sleep(Duration::from_secs(4)).await; // timing: precondition
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    // Not fetch_start: the fetch half refuses, so its words carry the time.
    let helper = stand_in(&[r#"{"not":"fetch_start"}"#], false);
    let spawn = move |plan: &Plan| {
        // Inside the launch: the spawn runs after the clock starts.
        std::thread::sleep(Duration::from_secs(1)); // timing: lower-bound
        helper(plan)
    };
    let (launched, _) = launch_with(&mut prepared, spawn, deadline, SHORT, reap_exit).await;
    let refusal = launched.expect_err("refused").refusal;
    let Refusal::Step(text) = &refusal else {
        panic!("{refusal:?}");
    };
    let ms: u64 = text
        .strip_prefix("the sandbox sent something other than fetch_start (")
        .and_then(|rest| rest.strip_suffix(" ms into the fetch step)"))
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("{text}"));
    assert!(ms >= 1000, "{ms} ms: the clock started after the spawn");
    assert!(ms < 5000, "{ms} ms: the clock started before the launch");
}
