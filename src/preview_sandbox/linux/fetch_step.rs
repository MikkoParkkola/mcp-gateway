// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The helper's npm fetch step (ADR-027 step 6): what the fetch command runs
//! with. Its environment is cleared and holds exactly these variables, so no
//! host proxy, `NODE_OPTIONS` or npm configuration reaches it.

use std::fs;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::control_client::{self, HELPER_BOUNDS};
use super::helper::{SetupFailure, step_call};
use super::mounts::{PREVIEW_CONFIG, PROXY_SOCKET};
use super::plan::{self, Limits, NpmFetch};
use super::relay::{MAX_PAIRS, Relay};
use crate::preview_sandbox::control_msg::{FetchStep, SetupStep};
use crate::preview_sandbox::fetch_output::{last_line, read_tail};
use crate::preview_sandbox::install::check_lock;

/// The npm fetch command's whole environment: the D5 list (proxy through the
/// relay with the fetch credential, no scripts, no git, the public registry)
/// plus the CA amendment's trust variables (the snapshot as `cafile`, strict
/// TLS, and empty user and global npmrc files, two of them since npm refuses
/// one file as both). `path` is
/// node's directory, then npm's.
pub(super) fn npm_env(credential: &str, port: u16, path: &str) -> Vec<(String, String)> {
    let proxy = format!("http://x:{credential}@127.0.0.1:{port}");
    let home = super::plan::HOME;
    let ca = format!("{PREVIEW_CONFIG}/ca.pem");
    let user = format!("{PREVIEW_CONFIG}/empty-user.npmrc");
    let global = format!("{PREVIEW_CONFIG}/empty-global.npmrc");
    [
        ("PATH", path),
        ("HOME", home),
        ("TMPDIR", home),
        ("HTTPS_PROXY", proxy.as_str()),
        ("HTTP_PROXY", proxy.as_str()),
        ("npm_config_https_proxy", proxy.as_str()),
        ("npm_config_proxy", proxy.as_str()),
        ("NO_PROXY", ""),
        ("npm_config_ignore_scripts", "true"),
        ("npm_config_registry", "https://registry.npmjs.org/"),
        ("npm_config_git", "/nonexistent/git"),
        ("npm_config_audit", "false"),
        ("npm_config_fund", "false"),
        ("npm_config_update_notifier", "false"),
        // npm's cafile replaces node's built-in roots (npm >= 9, the probe's floor).
        ("npm_config_cafile", ca.as_str()),
        ("npm_config_strict_ssl", "true"),
        ("npm_config_userconfig", user.as_str()),
        ("npm_config_globalconfig", global.as_str()),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect()
}

/// The fetch command's two output pipes, each drained on its own thread so a
/// child writing a lot to one cannot block while the other is read. Joined
/// only after the sweep, when every holder of either pipe is gone.
pub(super) struct Drains {
    out: JoinHandle<std::io::Result<Vec<u8>>>,
    err: JoinHandle<std::io::Result<Vec<u8>>>,
}

/// Start draining `stdout` and `stderr`, each on its own thread to its last
/// 64 KiB.
pub(super) fn drain(
    mut stdout: std::process::ChildStdout,
    mut stderr: std::process::ChildStderr,
) -> Drains {
    let out = std::thread::spawn(move || read_tail(&mut stdout));
    let err = std::thread::spawn(move || read_tail(&mut stderr));
    Drains { out, err }
}

impl Drains {
    /// Both tails, stdout's then stderr's; a failed read leaves that tail empty.
    pub(super) fn join(self) -> (Vec<u8>, Vec<u8>) {
        let tail = |handle: JoinHandle<std::io::Result<Vec<u8>>>| {
            handle.join().ok().and_then(Result::ok).unwrap_or_default()
        };
        (tail(self.out), tail(self.err))
    }
}

/// What the run phase runs after an npm fetch.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Run {
    /// The file the drop step execs.
    pub(super) program: String,
    /// `argv[0]` (the bin) and the server's own arguments.
    pub(super) argv: Vec<String>,
    /// node's directory, then the install's bin directory.
    pub(super) path: String,
}

/// The run after an npm fetch of `spec` installed under `home`: the
/// package's own bin (`npm_bin` confines it to the package's directory),
/// exec'd directly with `run_args`, and PATH holding node's directory
/// `node_dir` and the install's `.bin`, never the plan's own program or PATH.
pub(super) fn npm_run(
    home: &std::path::Path,
    spec: &str,
    run_args: &[String],
    node_dir: &str,
) -> Result<Run, crate::preview_sandbox::Refusal> {
    let install = home.join("pkg");
    let bin = crate::preview_sandbox::install::npm_bin(&install, npm_name(spec))?;
    let program = bin.to_str().ok_or_else(|| {
        crate::preview_sandbox::Refusal::Step("the package's entry point is not UTF-8".into())
    })?;
    let dot_bin = install.join("node_modules/.bin");
    Ok(Run {
        program: program.to_owned(),
        argv: std::iter::once(program.to_owned())
            .chain(run_args.iter().cloned())
            .collect(),
        path: format!("{node_dir}:{}", dot_bin.display()),
    })
}

/// The package name in an npm spec: `name` or `@scope/name`, without the
/// `@version` that may follow (an `@` after the first character).
fn npm_name(spec: &str) -> &str {
    match spec.get(1..).and_then(|rest| rest.find('@')) {
        Some(at) => &spec[..=at],
        None => spec,
    }
}

/// How long `ip link set lo up` may take.
const LO_BOUND: Duration = Duration::from_secs(2);
/// How long the sweep may take to leave only PID 1.
const SWEEP_BOUND: Duration = Duration::from_secs(2);
/// How long the relay's threads may take to end once stopped.
const RELAY_BOUND: Duration = Duration::from_secs(2);
/// The largest `package-lock.json` read.
const LOCK_CAP: u64 = 4 * 1024 * 1024;

/// The helper's npm fetch step (ADR-027 step 6): npm's steps inside the
/// shared fetch frame; the run is returned only when the fetch and all of the
/// teardown succeeded.
pub(super) fn npm(
    control: &mut UnixStream,
    npm: &NpmFetch,
    limits: Limits,
) -> Result<Run, FetchError> {
    frame(control, &npm.ip, |credential, port, deadline| {
        install(npm, credential, port, deadline, limits)
    })?;
    npm_run(
        Path::new(plan::HOME),
        &npm.spec,
        &npm.run_args,
        &npm.node_dir,
    )
    .map_err(|r| FetchError::Setup(SetupFailure::new(SetupStep::TargetMissing, r.to_string())))
}

/// How a fetch step failed, by where: before `fetch_start` it is a setup
/// step, reported as the helper's status; from `fetch_start` until the run
/// line is out, the fetch's own `fetch_done` refusal went out (or the channel
/// is dead), so no status may follow; after the run line it is the run's
/// entry point, a setup step again.
/// The helper's whole setup ends the same two ways, so it shares this type.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum FetchError {
    Setup(SetupFailure),
    Reported(String),
}

impl From<SetupFailure> for FetchError {
    fn from(failure: SetupFailure) -> Self {
        Self::Setup(failure)
    }
}

/// The fetch frame every fetcher's steps run inside. Setup that can fail
/// comes before the credential: `lo` up (with the host's `ip`), then the
/// relay. From `fetch_start` on, every exit goes through one teardown (sweep,
/// relay stopped, `fetch_done` and `expired`, the proxy socket removed).
/// `fetch` gets the credential, the relay's port and the fetch's one
/// deadline, and runs every step of the fetch under that deadline.
pub(super) fn frame(
    control: &mut UnixStream,
    ip: &str,
    fetch: impl FnOnce(&str, u16, Instant) -> Result<(), FetchFailure>,
) -> Result<(), FetchError> {
    lo_up(ip).map_err(FetchError::Setup)?;
    let relay = step_call(
        SetupStep::Loopback,
        || "starting the relay".to_owned(),
        || Relay::start(Path::new(PROXY_SOCKET), MAX_PAIRS),
    )
    .map_err(FetchError::Setup)?;
    let issued = match control_client::start_fetch(control, HELPER_BOUNDS) {
        Ok(issued) => issued,
        Err(step) => {
            let _ = relay.stop(RELAY_BOUND);
            return Err(FetchError::Reported(step));
        }
    };
    // One deadline for the whole fetch: every step of it.
    let Some(deadline) = fetch_deadline(issued.deadline_ms) else {
        // A channel failure: no step to report; the gateway refuses at EOF.
        let _ = relay.stop(RELAY_BOUND);
        return Err(FetchError::Reported(
            "the gateway's fetch deadline is out of range".into(),
        ));
    };
    let fetched = fetch(&issued.credential, relay.port(), deadline);
    teardown(control, relay, fetched).map_err(FetchError::Reported)
}

/// A failed fetch step: the step the gateway is told, and the detail kept for
/// the helper's own stderr (it never crosses the control socket).
#[derive(Debug, PartialEq, Eq)]
pub(super) struct FetchFailure {
    pub(super) step: FetchStep,
    pub(super) detail: String,
}

impl FetchFailure {
    pub(super) fn at(step: FetchStep) -> impl FnOnce(String) -> Self {
        move |detail| Self { step, detail }
    }
}

/// The failure the gateway is told: the fetch's own, else the first failed
/// teardown step, in order.
fn first_failure(
    fetched: Result<(), FetchFailure>,
    teardown: [Result<(), FetchFailure>; 3],
) -> Result<(), FetchFailure> {
    fetched?;
    teardown.into_iter().try_for_each(|step| step)
}

/// The fetch's one deadline, `ms` from now; `None` when `ms` does not fit
/// in milliseconds or the sum lies past what an instant can hold (refused,
/// never a panic with the credential live).
fn fetch_deadline(ms: u128) -> Option<Instant> {
    let left = u64::try_from(ms).ok()?;
    Instant::now().checked_add(Duration::from_millis(left))
}

/// The teardown, in order, every step attempted: sweep, relay stopped, the
/// proxy socket removed, then `fetch_done` naming the first failure (the
/// fetch's own before any teardown step's). Only an unrefused fetch goes on
/// to `expired` and its acknowledgement; the run follows only on Ok.
fn teardown(
    control: &mut UnixStream,
    relay: Relay,
    fetched: Result<(), FetchFailure>,
) -> Result<(), String> {
    let swept = sweep(SWEEP_BOUND).map_err(FetchFailure::at(FetchStep::Sweep));
    let stopped = relay
        .stop(RELAY_BOUND)
        .map_err(FetchFailure::at(FetchStep::Relay));
    let removed =
        super::mounts::remove_proxy_socket().map_err(FetchFailure::at(FetchStep::ProxySocket));
    let failed = first_failure(fetched, [swept, stopped, removed]);
    let step = failed.as_ref().err().map(|failure| failure.step);
    let reported = control_client::finish_fetch(control, HELPER_BOUNDS, step);
    failed.map_err(|failure| failure.detail)?;
    reported
}

/// `ip link set lo up`, run by the helper itself (it keeps the namespace's
/// capabilities; `ip` is the host's own binary), environment cleared.
fn lo_up(ip: &str) -> Result<(), SetupFailure> {
    let mut child = step_call(
        SetupStep::Loopback,
        || "bringing lo up".to_owned(),
        || {
            Command::new(ip)
                .args(["link", "set", "lo", "up"])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        },
    )?;
    let failed = |detail: String| SetupFailure::new(SetupStep::Loopback, detail);
    match wait_until(&mut child, Instant::now() + LO_BOUND) {
        Some(status) if status.success() => Ok(()),
        Some(status) => Err(failed(format!("bringing lo up (ip {status})"))),
        None => Err(failed("bringing lo up (ip did not end within 2 s)".into())),
    }
}

/// `child`'s exit status by `deadline`, or `None` after killing it there.
fn wait_until(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The two npm steps with the lock check between them, under one deadline;
/// each failure carries the step it happened in.
fn install(
    npm: &NpmFetch,
    credential: &str,
    port: u16,
    deadline: Instant,
    limits: Limits,
) -> Result<(), FetchFailure> {
    let setup = FetchFailure::at(FetchStep::Setup);
    let pkg = Path::new(plan::HOME).join("pkg");
    fs::create_dir_all(&pkg).map_err(|e| setup(format!("creating {} ({e})", pkg.display())))?;
    let prefix = pkg.to_str().ok_or_else(|| {
        FetchFailure::at(FetchStep::Setup)("the install prefix is not UTF-8".into())
    })?;
    let npm_dir = Path::new(&npm.npm)
        .parent()
        .and_then(Path::to_str)
        .unwrap_or(&npm.node_dir);
    let env = npm_env(credential, port, &format!("{}:{npm_dir}", npm.node_dir));
    let lock_only = [
        "install",
        "--package-lock-only",
        "--ignore-scripts",
        "--prefix",
        prefix,
        npm.spec.as_str(),
    ];
    run_dropped(
        &npm.npm, "npm", &lock_only, &env, deadline, limits, credential,
    )
    .map_err(FetchFailure::at(FetchStep::NpmInstall))?;
    read_lock(&pkg.join("package-lock.json"))
        .and_then(|lock| check_lock(&lock).map_err(|r| r.to_string()))
        .map_err(FetchFailure::at(FetchStep::LockCheck))?;
    run_dropped(
        &npm.npm,
        "npm",
        &["ci", "--ignore-scripts", "--prefix", prefix],
        &env,
        deadline,
        limits,
        credential,
    )
    .map_err(FetchFailure::at(FetchStep::NpmCi))
}

/// The lock npm wrote, at most [`LOCK_CAP`] bytes.
fn read_lock(path: &Path) -> Result<serde_json::Value, String> {
    use std::io::Read as _;
    let file = fs::File::open(path).map_err(|e| format!("reading the lock ({e})"))?;
    let mut bytes = Vec::new();
    file.take(LOCK_CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("reading the lock ({e})"))?;
    if bytes.len() as u64 > LOCK_CAP {
        return Err("reading the lock (over 4 MiB)".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("reading the lock ({e})"))
}

/// One fetch command (`program`, run as `name`) through `__preview-drop`,
/// its environment exactly `env`, its output drained; the sweep runs before
/// the drains are joined, so a descendant holding a pipe cannot stall it. A
/// failure refuses with the command's last line, the credential redacted.
/// Every fetcher's commands run here, the one place their output is read.
pub(super) fn run_dropped(
    program: &str,
    name: &str,
    args: &[&str],
    env: &[(String, String)],
    deadline: Instant,
    limits: Limits,
    credential: &str,
) -> Result<(), String> {
    let limits =
        serde_json::to_string(&limits).map_err(|e| format!("encoding the limits ({e})"))?;
    let mut child = Command::new("/proc/self/exe")
        .arg(super::DROP)
        .arg(limits)
        .arg(program)
        .arg("--")
        .arg(name)
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir(plan::HOME)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("starting {name} ({e})"))?;
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(format!("starting {name} (no output pipes)"));
    };
    let drains = drain(out, err);
    let status = wait_until(&mut child, deadline);
    sweep(SWEEP_BOUND)?;
    let (out, err) = drains.join();
    match status {
        Some(status) if status.success() => Ok(()),
        Some(_) => {
            let line = last_line(if err.is_empty() { &out } else { &err }, credential);
            Err(format!("fetching the package ({line})"))
        }
        None => Err("fetching the package (the fetch passed its deadline)".into()),
    }
}

/// SIGKILL every process in the namespace but PID 1 (this helper) and reap,
/// until `/proc` lists only PID 1 and no child is left; one still there after
/// `bound` refuses.
fn sweep(bound: Duration) -> Result<(), String> {
    use rustix::process::{Pid, Signal, WaitOptions, kill_process, wait};
    let deadline = Instant::now() + bound;
    loop {
        let others: Vec<i32> = fs::read_dir("/proc")
            .map_err(|e| format!("sweeping the fetch ({e})"))?
            .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
            .filter(|&pid| pid != 1)
            .collect();
        for pid in &others {
            if let Some(pid) = Pid::from_raw(*pid) {
                let _ = kill_process(pid, Signal::KILL);
            }
        }
        let no_child = loop {
            match wait(WaitOptions::NOHANG) {
                Ok(Some(_)) => {}
                Err(rustix::io::Errno::CHILD) => break true,
                Ok(None) | Err(_) => break false,
            }
        };
        if others.is_empty() && no_child {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "sweeping the fetch ({} processes outlived 2 s)",
                others.len()
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(tp4)]
#[cfg(test)]
#[path = "fetch_step_tests.rs"]
mod tests;
