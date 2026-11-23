// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The helper's status through the real launcher, helper and kernel (the
//! CI rows R23 to R29, R35e, R42, R43, and the spawn's environment). The
//! gateway binary the helper runs as is named by
//! `PREVIEW_SANDBOX_GATEWAY_BIN`; a host that refuses the sandbox skips
//! these, except where `PREVIEW_SANDBOX_REQUIRED` makes that a failure.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

use super::fetch_registry::Registry;
use super::fetch_rows::{
    GUARD, TestDialer, TestResolve, gateway_bin, marked, package, preview, sandbox_runs,
};
use super::launcher::{Phase, Prepared, launch_prepared, prepare};
use super::plan::{Fault, Plan};
use super::{Ambient, launch};
use crate::preview_sandbox::control::{CONTROL_BOUNDS, accept_helper, serve_control};
use crate::preview_sandbox::control_msg::{SetupStatus, SetupStep};
use crate::preview_sandbox::{Refusal, Started, Target};

/// The gateway binary, once this host is known to run the sandbox; `None`
/// to skip.
async fn helper() -> Option<PathBuf> {
    let gateway = gateway_bin()?;
    sandbox_runs(&gateway).await.then_some(gateway)
}

fn target(program: &str, args: &[&str]) -> Target {
    Target {
        program: PathBuf::from(program),
        args: args.iter().map(OsString::from).collect(),
    }
}

fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(60)
}

/// A prepared non-fetching preview whose control directory lives under a
/// directory the row owns.
struct Rig {
    prepared: Prepared,
    _runtime: tempfile::TempDir,
}

fn rig(target: &Target) -> Rig {
    let runtime = tempfile::tempdir().expect("runtime");
    let ambient = Ambient {
        ca_bundle: None,
        runtime_dir: Some(OsString::from(runtime.path())),
        path: std::env::var_os("PATH"),
    };
    let prepared = prepare(target, &[], ambient, Phase::Run).expect("prepared");
    Rig {
        prepared,
        _runtime: runtime,
    }
}

/// Start `target` with `edit` applied to its plan.
async fn start_edited(
    gateway: &Path,
    target: &Target,
    edit: impl FnOnce(&mut Plan),
) -> Result<Started, Refusal> {
    let mut rig = rig(target);
    edit(&mut rig.prepared.plan);
    launch_prepared(&mut rig.prepared, gateway, deadline())
        .await
        .map_err(|failed| failed.refusal)
}

/// Wait up to `bound` for `check` to hold.
async fn soon(bound: Duration, check: impl Fn() -> bool) -> bool {
    let until = tokio::time::Instant::now() + bound;
    while !check() {
        if tokio::time::Instant::now() >= until {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
}

/// The pids whose parent is `parent`.
fn children_of(parent: u32) -> Vec<u32> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").expect("/proc").flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        let its_parent = stat
            .rsplit_once(") ")
            .and_then(|(_, rest)| rest.split_whitespace().nth(1))
            .and_then(|p| p.parse::<u32>().ok());
        if its_parent == Some(parent) {
            found.push(pid);
        }
    }
    found
}

/// The live processes that are exactly `sleep <marker>`: the target itself,
/// never `unshare` or the helper, whose own command lines carry the plan and
/// so the marker too (`marked` counts those, for the whole-namespace checks).
fn sleeping(marker: &str) -> Vec<u32> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").expect("/proc").flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        let state = stat
            .rsplit_once(") ")
            .and_then(|(_, rest)| rest.split_whitespace().next());
        if !matches!(state, Some(s) if !matches!(s, "Z" | "X" | "x")) {
            continue;
        }
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let argv: Vec<&[u8]> = cmdline
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .collect();
        let is_sleep = argv
            .first()
            .is_some_and(|a| a.rsplit(|b| *b == b'/').next() == Some(b"sleep".as_slice()));
        if is_sleep && argv.len() == 2 && argv[1] == marker.as_bytes() {
            found.push(pid);
        }
    }
    found
}

/// A regular file outside `/tmp` (which the helper's staging covers), in a
/// scratch directory the caller keeps.
fn outside_tmp_file() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("scratch");
    let file = dir.path().join("plain");
    std::fs::write(&file, "x").expect("file");
    let file = file.to_str().expect("UTF-8 scratch path").to_owned();
    (dir, file)
}

/// R25, kills m-generic-refusal, m-wrong-step and m-denied-always-false: one
/// preview per step, each refused with that step's words and nothing more.
/// By plan data: binding (a bind source under a regular file), masking (a
/// mask there), the target missing; by the fault field: mounting,
/// remounting, pivoting and limits.
#[cfg(tp4)]
#[tokio::test]
async fn r25_each_setup_step_is_reported_by_its_name() {
    type PlanEdit = Box<dyn FnOnce(&mut Plan)>;
    let Some(gateway) = helper().await else {
        return;
    };
    let (_scratch, file) = outside_tmp_file();
    let sh = target("/bin/sh", &["-c", "true"]);
    let fail_at = |step| {
        move |plan: &mut Plan| {
            plan.fault = Some(Fault::FailAt {
                step,
                denied: false,
            });
        }
    };
    let binding = file.clone();
    let masking = file.clone();
    let cases: Vec<(&str, PlanEdit)> = vec![
        (
            "binding",
            Box::new(move |p: &mut Plan| p.read_only.push(format!("{binding}/x"))),
        ),
        (
            "masking",
            Box::new(move |p: &mut Plan| {
                p.read_only.push(masking.clone());
                p.masked.push(format!("{masking}/x"));
            }),
        ),
        (
            "target_missing",
            Box::new(|p: &mut Plan| p.program = "/nonexistent/preview-program".into()),
        ),
        ("mounting", Box::new(fail_at(SetupStep::Mounting))),
        ("remounting", Box::new(fail_at(SetupStep::Remounting))),
        ("pivoting", Box::new(fail_at(SetupStep::Pivoting))),
        ("limits", Box::new(fail_at(SetupStep::Limits))),
    ];
    let mut wrong = Vec::new();
    for (step, edit) in cases {
        let got = start_edited(&gateway, &sh, edit).await.err();
        if got != Some(Refusal::Step(step.into())) {
            wrong.push(format!("{step}: {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// R25, the fetching cases, kills m-post-fetch-reported: a lo that cannot be
/// brought up is the loopback step, before any credential; a package with no
/// entry point fails after the run line and is the target's step, not the
/// fetch's "ended before it finished".
#[cfg(tp4)]
#[tokio::test]
async fn r25_the_fetchs_own_setup_steps_are_reported_by_their_names() {
    let Some(gateway) = helper().await else {
        return;
    };
    let fake = package("mcp-nobin", &[], serde_json::json!({}));
    let registry = Registry::start(vec![fake], "r25 CA").await;
    let path = std::env::var_os("PATH");
    let npx = target("npx", &["mcp-nobin"]);
    let ran = preview(
        &gateway,
        &npx,
        &registry.ca_pem,
        registry.port,
        path.clone(),
        GUARD,
    )
    .await;
    assert_eq!(ran.err(), Some(Refusal::Step("target_missing".into())));

    let runtime = tempfile::tempdir().expect("runtime");
    let ambient = Ambient {
        ca_bundle: None,
        runtime_dir: Some(OsString::from(runtime.path())),
        path,
    };
    let phase = Phase::Fetch {
        resolve: Arc::new(TestResolve),
        connect: Arc::new(TestDialer(registry.port)),
    };
    let mut prepared = prepare(&npx, &[], ambient, phase).expect("prepared");
    let npm = prepared
        .plan
        .fetch
        .as_mut()
        .and_then(|f| f.npm.as_mut())
        .expect("an npm fetch was planned");
    npm.ip = "/nonexistent/ip".into();
    let refused = launch_prepared(&mut prepared, &gateway, deadline())
        .await
        .err()
        .map(|failed| failed.refusal);
    assert_eq!(refused, Some(Refusal::Step("loopback".into())));
}

/// R25, the denial: a mount step the kernel refused with EPERM reaches the
/// gateway as exactly that step, denied, read here from the session itself.
#[cfg(tp4)]
#[tokio::test]
async fn r25_a_denied_step_reaches_the_gateway_as_denied() {
    let Some(gateway) = helper().await else {
        return;
    };
    let mut rig = rig(&target("/bin/sh", &["-c", "true"]));
    rig.prepared.plan.fault = Some(Fault::FailAt {
        step: SetupStep::Mounting,
        denied: true,
    });
    let listener = rig.prepared.listener.take().expect("listener");
    let mut child = launch(rig.prepared.unshare, &gateway, &rig.prepared.plan).expect("launched");
    let pid = child.id().expect("unshare's pid");
    let uid = rustix::process::getuid().as_raw();
    let status = async {
        let stream = accept_helper(listener, pid, uid, CONTROL_BOUNDS, deadline()).await?;
        serve_control(stream, None, deadline(), CONTROL_BOUNDS).await
    };
    let status = tokio::time::timeout(GUARD, status)
        .await
        .expect("within the guard");
    let _ = child.start_kill();
    let _ = child.wait().await;
    assert_eq!(
        status,
        Ok(SetupStatus::Refused {
            step: SetupStep::Mounting,
            denied: true
        })
    );
}

/// R26e, kills m-exempt-none and m-skip-exempt-check: a descriptor open
/// beside the control connection before the status is the descriptors step;
/// without it the target starts.
#[cfg(tp4)]
#[tokio::test]
async fn r26e_a_stray_descriptor_before_the_status_is_refused() {
    const MARKER: &str = "2999.261";
    let Some(gateway) = helper().await else {
        return;
    };
    let sleeper = target("/bin/sleep", &[MARKER]);
    let planted = start_edited(&gateway, &sleeper, |p| {
        p.fault = Some(Fault::PlantBeforeStatus);
    });
    assert_eq!(
        planted.await.err(),
        Some(Refusal::Step("descriptors".into()))
    );
    let started = start_edited(&gateway, &sleeper, |_| {})
        .await
        .expect("started");
    assert!(
        soon(GUARD, || !sleeping(MARKER).is_empty()).await,
        "the target ran"
    );
    drop(started);
}

/// R35e, kills m-skip-strict: a descriptor opened after the connection is
/// dropped fails the strict check, so the helper exits 97 after the gateway
/// already has `Started`, and the target never runs; without it, it runs.
#[cfg(tp4)]
#[tokio::test]
async fn r35e_a_stray_descriptor_after_the_close_stops_the_target() {
    const MARKER: &str = "2999.351";
    let Some(gateway) = helper().await else {
        return;
    };
    let sleeper = target("/bin/sleep", &[MARKER]);
    let mut started = start_edited(&gateway, &sleeper, |p| {
        p.fault = Some(Fault::PlantAfterClose);
    })
    .await
    .expect("started before the strict check");
    let status = tokio::time::timeout(GUARD, started.child.wait())
        .await
        .expect("ended within the guard")
        .expect("status");
    assert_eq!(status.code(), Some(i32::from(super::REFUSED)));
    assert!(sleeping(MARKER).is_empty(), "the target ran");
    let started = start_edited(&gateway, &sleeper, |_| {})
        .await
        .expect("started");
    assert!(
        soon(GUARD, || !sleeping(MARKER).is_empty()).await,
        "the target ran"
    );
    drop(started);
}

/// The helper's trace lines read into `order` up to and including the one
/// ending in `last`, or to the end of its stderr.
async fn read_trace_to(
    stderr: &mut BufReader<tokio::process::ChildStderr>,
    order: &mut Vec<String>,
    last: &str,
) {
    loop {
        let mut line = String::new();
        if stderr.read_line(&mut line).await.expect("stderr") == 0 {
            return;
        }
        let line = line.trim_end().to_owned();
        let done = line.ends_with(last);
        order.push(line);
        if done {
            return;
        }
    }
}

/// R23, kills m-spawn-before-send and m-hold-ignored: with the trace and the
/// hold, the gateway's `Started` comes before the helper drops the
/// connection, runs the strict check and holds; the target does not exist
/// until the row releases the hold, and then exactly once.
#[cfg(tp4)]
#[tokio::test]
async fn r23_the_status_and_the_close_come_before_the_target() {
    const MARKER: &str = "2999.231";
    let Some(gateway) = helper().await else {
        return;
    };
    let sleeper = target("/bin/sleep", &[MARKER]);
    let mut started = start_edited(&gateway, &sleeper, |p| p.fault = Some(Fault::TraceAndHold))
        .await
        .expect("started");
    let mut stderr = BufReader::new(started.child.stderr.take().expect("stderr"));
    let mut order = Vec::new();
    let read_to = read_trace_to;
    tokio::time::timeout(
        Duration::from_secs(10),
        read_to(&mut stderr, &mut order, "strict-check"),
    )
    .await
    .expect("the trace reached the strict check");
    assert!(
        sleeping(MARKER).is_empty(),
        "the target ran before the hold"
    );
    let want = ["sent", "closed", "strict-check"].map(|at| format!("preview-sandbox: order {at}"));
    assert_eq!(order, want);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        sleeping(MARKER).is_empty(),
        "the target ran during the hold"
    );
    let helpers = children_of(started.child.id().expect("unshare's pid"));
    assert_eq!(
        helpers.len(),
        1,
        "unshare's one child is the helper: {helpers:?}"
    );
    assert_eq!(
        children_of(helpers[0]),
        Vec::<u32>::new(),
        "the helper has a child before the release"
    );
    let stdin = started.child.stdin.as_mut().expect("stdin");
    stdin.write_all(b"x").await.expect("release");
    stdin.flush().await.expect("release");
    tokio::time::timeout(
        Duration::from_secs(10),
        read_to(&mut stderr, &mut order, "spawned"),
    )
    .await
    .expect("the trace reached the spawn");
    assert_eq!(
        order.last().map(String::as_str),
        Some("preview-sandbox: order spawned")
    );
    assert!(
        soon(GUARD, || sleeping(MARKER).len() == 1).await,
        "the target ran once"
    );
}

/// R23b, kills m-hold-ignores-eof: a hold whose stdin closes instead of
/// bringing the release byte refuses, naming the end of input, and the
/// target never starts.
#[cfg(tp4)]
#[tokio::test]
async fn r23b_a_hold_that_ends_without_its_release_refuses() {
    const MARKER: &str = "2999.232";
    let Some(gateway) = helper().await else {
        return;
    };
    let sleeper = target("/bin/sleep", &[MARKER]);
    let mut started = start_edited(&gateway, &sleeper, |p| p.fault = Some(Fault::TraceAndHold))
        .await
        .expect("started");
    let mut stderr = BufReader::new(started.child.stderr.take().expect("stderr"));
    let mut order = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        read_trace_to(&mut stderr, &mut order, "strict-check"),
    )
    .await
    .expect("the trace reached the strict check");
    // The end of input instead of the release byte.
    drop(started.child.stdin.take());
    let status = tokio::time::timeout(GUARD, started.child.wait())
        .await
        .expect("ended within the guard")
        .expect("status");
    let mut rest = String::new();
    stderr.read_to_string(&mut rest).await.expect("stderr");
    assert_eq!(status.code(), Some(i32::from(super::REFUSED)), "{rest}");
    assert!(
        rest.contains("preview-sandbox: refused at hold ended: eof"),
        "{rest}"
    );
    assert!(sleeping(MARKER).is_empty(), "the target ran");
}

/// What a target's shell prints about itself: its descriptors, one per line,
/// listed by a separate `ls` writing straight to stdout (a glob would open
/// the directory, and `$(...)` a pipe, in the shell itself, and list that
/// descriptor too; the path is absolute, as a fetched run's PATH holds only
/// node's and the package's bins), then the path it was given and whether
/// that path exists.
const FD_REPORT: &str =
    r#"/bin/ls /proc/$$/fd; echo "arg=$1"; test -e "$1" && echo control-visible; echo end"#;

/// R24 and R27, kill m-keep-connection: the target holds no descriptor above
/// 2, and the control socket's path does not exist inside the root.
#[cfg(tp4)]
#[tokio::test]
async fn r24_r27_the_target_holds_nothing_of_the_control_connection() {
    let Some(gateway) = helper().await else {
        return;
    };
    let mut rig = rig(&target("/bin/sh", &["-c", FD_REPORT, "sh"]));
    let control = rig.prepared.plan.control.clone();
    rig.prepared.plan.target.push(control.clone());
    let mut started = launch_prepared(&mut rig.prepared, &gateway, deadline())
        .await
        .expect("started");
    drop(started.child.stdin.take());
    let mut out = String::new();
    let mut stdout = started.child.stdout.take().expect("stdout");
    tokio::time::timeout(GUARD, stdout.read_to_string(&mut out))
        .await
        .expect("ended within the guard")
        .expect("stdout");
    assert_eq!(out, format!("0\n1\n2\narg={control}\nend\n"));
}

/// R24 and R27, the fetching half: the run after an npm fetch holds no
/// descriptor above 2 either, and cannot see the control socket's path.
#[cfg(tp4)]
#[tokio::test]
async fn r24_r27_a_fetched_run_holds_nothing_of_the_control_connection() {
    let Some(gateway) = helper().await else {
        return;
    };
    // A script's own shell keeps the script open (dash on descriptor 10), so
    // the bin execs a `sh -c`, which holds nothing but what it inherited.
    let fds = format!("#!/bin/sh\nexec /bin/sh -c '{FD_REPORT}' sh \"$@\"\n");
    let fake = super::fetch_registry::Package {
        name: "mcp-fds",
        version: "1.0.0",
        manifest: serde_json::json!({"bin": {"mcp-fds": "bin/fds.sh"}}),
        files: vec![("bin/fds.sh", fds.into_bytes(), 0o755)],
    };
    let registry = Registry::start(vec![fake], "r24 CA").await;
    let scratch = tempfile::tempdir().expect("scratch");
    let bundle = scratch.path().join("bundle.pem");
    std::fs::write(&bundle, &registry.ca_pem).expect("bundle");
    let ambient = Ambient {
        ca_bundle: Some(bundle.into_os_string()),
        runtime_dir: Some(OsString::from(scratch.path())),
        path: std::env::var_os("PATH"),
    };
    let phase = Phase::Fetch {
        resolve: Arc::new(TestResolve),
        connect: Arc::new(TestDialer(registry.port)),
    };
    let mut prepared =
        prepare(&target("npx", &["mcp-fds"]), &[], ambient, phase).expect("prepared");
    let control = prepared.plan.control.clone();
    let npm = prepared
        .plan
        .fetch
        .as_mut()
        .and_then(|f| f.npm.as_mut())
        .expect("an npm fetch was planned");
    npm.run_args = vec![control.clone()];
    let mut started = launch_prepared(&mut prepared, &gateway, deadline())
        .await
        .expect("started");
    drop(started.child.stdin.take());
    let mut out = String::new();
    let mut stdout = started.child.stdout.take().expect("stdout");
    tokio::time::timeout(GUARD, stdout.read_to_string(&mut out))
        .await
        .expect("ended within the guard")
        .expect("stdout");
    assert_eq!(out, format!("0\n1\n2\narg={control}\nend\n"));
}

/// R29, kills m-reap-unshare-only: a process the target leaves in a session
/// of its own dies with the namespace once the row kills and reaps
/// `Started.child`.
#[cfg(tp4)]
#[tokio::test]
async fn r29_an_escaped_session_dies_with_the_namespace() {
    const MARKER: &str = "2999.291";
    let Some(gateway) = helper().await else {
        return;
    };
    let script = format!("(setsid sleep {MARKER} &); exec sleep 300");
    let mut started = start_edited(&gateway, &target("/bin/sh", &["-c", &script]), |_| {})
        .await
        .expect("started");
    assert!(
        soon(GUARD, || !sleeping(MARKER).is_empty()).await,
        "the escapee ran"
    );
    let _ = started.child.start_kill();
    let _ = started.child.wait().await;
    assert!(
        soon(Duration::from_secs(5), || marked(MARKER).is_empty()).await,
        "the escapee outlived the namespace"
    );
}

/// R42, kills m-accept-any-peer: a stranger that connects before the helper
/// takes the one accept and is refused, and the launch with it; one that
/// tries after the start is turned away and the preview runs on.
#[cfg(tp4)]
#[tokio::test]
async fn r42_a_stranger_on_the_control_socket_is_refused() {
    let Some(gateway) = helper().await else {
        return;
    };
    let mut early = rig(&target("/bin/sh", &["-c", "true"]));
    let stranger = std::os::unix::net::UnixStream::connect(&early.prepared.plan.control)
        .expect("the stranger connects first");
    let refused = launch_prepared(&mut early.prepared, &gateway, deadline())
        .await
        .expect_err("a stranger's connection started a preview");
    assert_eq!(
        refused.refusal,
        Refusal::Step("the sandbox's control peer is not the sandbox's helper".into())
    );
    assert!(refused.unreaped.is_none(), "unshare was reaped");
    drop(stranger);

    let mut later = rig(&target("/bin/sleep", &["2999.421"]));
    let mut started = launch_prepared(&mut later.prepared, &gateway, deadline())
        .await
        .expect("started");
    let late = std::os::unix::net::UnixStream::connect(&later.prepared.plan.control);
    assert!(late.is_err(), "a connection after the start was taken");
    assert!(
        started.child.try_wait().expect("status").is_none(),
        "the preview ran on"
    );
}

/// R43 (ROUTE.8), kills m-no-revoke-on-error on the real helper and kernel:
/// the helper killed mid-fetch, once the registry has the fetch's first
/// request, ends the session within 5 s, and the credential it held is
/// refused at the proxy with no tunnel left open.
#[cfg(tp4)]
#[tokio::test]
async fn r43_a_helper_killed_mid_fetch_leaves_its_credential_refused() {
    let Some(gateway) = helper().await else {
        return;
    };
    let fake = package(
        "mcp-r43",
        &[("mcp-r43", "bin/cli.sh")],
        serde_json::json!({}),
    );
    let registry = Registry::start(vec![fake], "r43 CA").await;
    let scratch = tempfile::tempdir().expect("scratch");
    let bundle = scratch.path().join("bundle.pem");
    std::fs::write(&bundle, &registry.ca_pem).expect("bundle");
    let ambient = Ambient {
        ca_bundle: Some(bundle.into_os_string()),
        runtime_dir: Some(OsString::from(scratch.path())),
        path: std::env::var_os("PATH"),
    };
    let phase = Phase::Fetch {
        resolve: Arc::new(TestResolve),
        connect: Arc::new(TestDialer(registry.port)),
    };
    let mut prepared =
        prepare(&target("npx", &["mcp-r43"]), &[], ambient, phase).expect("prepared");
    let listener = prepared.listener.take().expect("listener");
    let mut child = launch(prepared.unshare, &gateway, &prepared.plan).expect("launched");
    let unshare = child.id().expect("unshare's pid");
    let uid = rustix::process::getuid().as_raw();
    let proxy = prepared.proxy.as_ref().expect("the fetch's proxy");
    let session = async {
        let stream = accept_helper(listener, unshare, uid, CONTROL_BOUNDS, deadline()).await?;
        serve_control(stream, Some(proxy), deadline(), CONTROL_BOUNDS).await
    };
    tokio::pin!(session);
    tokio::select! {
        ended = &mut session => panic!("the session ended before the registry was asked: {ended:?}"),
        () = registry.first_request() => {}
        () = tokio::time::sleep(GUARD) => panic!("the registry was not asked within the guard"),
    }
    let credential = proxy
        .live_credential()
        .expect("the fetch's credential is live");
    let helpers = children_of(unshare);
    assert_eq!(
        helpers.len(),
        1,
        "unshare's one child is the helper: {helpers:?}"
    );
    let pid = rustix::process::Pid::from_raw(i32::try_from(helpers[0]).expect("pid")).expect("pid");
    rustix::process::kill_process(pid, rustix::process::Signal::KILL).expect("kill the helper");
    let ended = tokio::time::timeout(Duration::from_secs(5), &mut session)
        .await
        .expect("the session ended within 5 s of the helper's death");
    assert!(ended.is_err(), "{ended:?}");
    let mut connect = tokio::net::UnixStream::connect(proxy.unix_path())
        .await
        .expect("the proxy listens");
    let request = format!(
        "CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n\
         Proxy-Authorization: {}\r\n\r\n",
        credential.basic()
    );
    connect
        .write_all(request.as_bytes())
        .await
        .expect("request");
    let mut answer = String::new();
    BufReader::new(&mut connect)
        .read_line(&mut answer)
        .await
        .expect("the proxy answered");
    assert!(answer.starts_with("HTTP/1.1 407"), "{answer:?}");
    assert_eq!(proxy.open_tunnels(), 0);
    assert!(
        soon(GUARD, || registry.open_connections() == 0).await,
        "a registry connection outlived the credential"
    );
    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// The spawn carries nothing a backend's rules would inject: the target's
/// whole environment is the plan's three variables (the premise the preview
/// pipe's inbound parse rests on, pinned at the spawn path).
#[cfg(tp4)]
#[tokio::test]
async fn the_target_gets_only_the_plans_environment() {
    let Some(gateway) = helper().await else {
        return;
    };
    let mut started = start_edited(&gateway, &target("/usr/bin/env", &[]), |_| {})
        .await
        .expect("started");
    drop(started.child.stdin.take());
    let mut out = String::new();
    let mut stdout = started.child.stdout.take().expect("stdout");
    tokio::time::timeout(GUARD, stdout.read_to_string(&mut out))
        .await
        .expect("ended within the guard")
        .expect("stdout");
    let mut names: Vec<&str> = out
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k))
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["HOME", "PATH", "TMPDIR"], "{out}");
}
