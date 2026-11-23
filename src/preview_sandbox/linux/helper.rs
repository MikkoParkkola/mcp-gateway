// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `__preview-sandbox` on Linux: the first process of the preview's PID
//! namespace (ADR-027, Linux steps 1 to 3, 5 and 7).
//!
//! util-linux `unshare` has already made the namespaces. The helper checks it
//! really is in fresh ones, connects the gateway's control socket, builds and
//! enters the private root, reports its setup over that connection, closes
//! it, then starts the target through `__preview-drop` and stays as PID 1: it
//! reaps orphans and exits when the target does, which makes the kernel kill
//! everything left in the namespace. It never runs untrusted code itself.

use std::fs;
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::process::{Command, ExitCode};

use rustix::fs::FileType;
use rustix::process::{DumpableBehavior, WaitOptions, set_dumpable_behavior};

use super::control_client::{self, HELPER_BOUNDS};
use super::fetch_step::{FetchError, Run};
use super::plan::{self, Fetcher, HostNamespaces, Plan};
use crate::preview_sandbox::control_msg::{SetupStatus, SetupStep};

/// A setup step that failed once the control connection was open: the step
/// the gateway is told, whether the kernel refused permission, and the
/// detail for people, which goes to stderr and never over the socket.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct SetupFailure {
    pub(super) step: SetupStep,
    pub(super) denied: bool,
    pub(super) detail: String,
}

impl SetupFailure {
    /// A failure with no error behind it, so never a denial.
    pub(super) fn new(step: SetupStep, detail: impl Into<String>) -> Self {
        Self {
            step,
            denied: false,
            detail: detail.into(),
        }
    }

    /// `what` failed with `error`: a denial exactly when its kind is
    /// `PermissionDenied`, which std gives both EPERM and EACCES.
    fn from_io(step: SetupStep, what: &str, error: &io::Error) -> Self {
        Self {
            step,
            denied: error.kind() == io::ErrorKind::PermissionDenied,
            detail: format!("{what} ({error})"),
        }
    }
}

/// One fallible call of `step`, its error typed with `what` names it. In a
/// debug build the plan's fault may fail the step's first call instead,
/// with an error of the kind the fault names, so the denial is still worked
/// out here from the kind.
pub(super) fn step_call<T>(
    step: SetupStep,
    what: impl FnOnce() -> String,
    op: impl FnOnce() -> io::Result<T>,
) -> Result<T, SetupFailure> {
    fault::injected(step)
        .map_or_else(op, Err)
        .map_err(|e| SetupFailure::from_io(step, &what(), &e))
}

/// Where a debug build's planted descriptor goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Point {
    /// Before the descriptor check that precedes the status.
    BeforeStatus,
    /// After the connection is dropped, before the strict check.
    AfterClose,
}

pub(super) fn run(plan: &Plan) -> ExitCode {
    fault::arm(plan);
    // Before the connection, and host-level: stderr and exit 97.
    let fetcher = match fetcher(plan) {
        Ok(fetcher) => fetcher,
        Err(why) => return refused(&why),
    };
    if let Err(why) = check_namespaces(plan.host).and_then(|()| check_descriptors(None)) {
        return refused(&why);
    }
    // On the host path, before the new root hides it; std sockets are
    // close-on-exec.
    let mut control = match UnixStream::connect(&plan.control) {
        Ok(control) => control,
        Err(e) => return refused(&format!("connecting the control socket ({e})")),
    };
    let ready = match set_up(plan, fetcher, &mut control) {
        Ok(ready) => ready,
        Err(FetchError::Setup(failure)) => {
            eprintln!("preview-sandbox: refused at {}", failure.detail);
            let status = SetupStatus::Refused {
                step: failure.step,
                denied: failure.denied,
            };
            let bound = HELPER_BOUNDS.write;
            let _ = control_client::report_and_leave(&mut control, Some(status), bound, || {});
            return ExitCode::from(super::REFUSED);
        }
        Err(FetchError::Reported(detail)) => {
            eprintln!("preview-sandbox: refused at {detail}");
            let _ =
                control_client::report_and_leave(&mut control, None, HELPER_BOUNDS.write, || {});
            return ExitCode::from(super::REFUSED);
        }
    };
    let done = Some(SetupStatus::Done);
    let sent = || fault::trace("sent");
    if control_client::report_and_leave(&mut control, done, HELPER_BOUNDS.write, sent).is_err() {
        return ExitCode::from(super::REFUSED);
    }
    // The gateway has taken the status; the target must not inherit this.
    drop(control);
    fault::trace("closed");
    let _late = fault::plant(Point::AfterClose);
    // Strict now: the control descriptor is gone, so nothing is exempt.
    if let Err(why) = check_descriptors(None) {
        return refused(&why);
    }
    fault::trace("strict-check");
    // Only a debug build has a hold: a release build has no fault to obey.
    #[cfg(debug_assertions)]
    if let Err(why) = fault::hold() {
        return refused(&why);
    }
    supervise(plan, &ready)
}

/// The helper's own refusal before or after the report: on stderr only.
fn refused(why: &str) -> ExitCode {
    eprintln!("preview-sandbox: refused at {why}");
    ExitCode::from(super::REFUSED)
}

/// What the run needs once the setup is reported: the limits as the drop
/// stage reads them, and the fetched package's run when there was a fetch.
struct Ready {
    limits: String,
    run: Option<Run>,
}

/// Every step between the connection and the status, each failure typed
/// by its step: the root, the fetch, the target's entry point, and the
/// descriptor check that exempts only the control connection.
fn set_up(
    plan: &Plan,
    fetcher: Option<Fetcher<'_>>,
    control: &mut UnixStream,
) -> Result<Ready, FetchError> {
    // A capability-less process in the namespace then cannot read this
    // process's environ, fd table or memory through /proc/1.
    step_call(
        SetupStep::Limits,
        || "making the helper non-dumpable".into(),
        || Ok(set_dumpable_behavior(DumpableBehavior::NotDumpable)?),
    )?;
    // Encoded before the status, so a failure here can still be reported.
    let limits = serde_json::to_string(&plan.limits)
        .map_err(|e| SetupFailure::new(SetupStep::Limits, format!("encoding the limits ({e})")))?;
    // The CA snapshot, opened before staging covers host /tmp; it is bound
    // from this descriptor, which is closed once bound, before any child.
    let ca = plan
        .fetch
        .as_ref()
        .map(|paths| open_path(&paths.ca, FileType::RegularFile, "the CA snapshot"))
        .transpose()?;
    // The proxy socket likewise: it sits beside the snapshot.
    let proxy = fetcher
        .map(|fetcher| open_path(fetcher.proxy(), FileType::Socket, "the proxy socket"))
        .transpose()?;
    super::mounts::build_root(
        plan,
        ca.as_ref().map(|(fd, _)| fd),
        proxy.as_ref().map(|(fd, _)| fd),
    )?;
    if let Some((fd, identity)) = ca {
        drop(fd);
        super::mounts::check_preview_config(identity)?;
    }
    if let Some((fd, identity)) = proxy {
        drop(fd);
        super::mounts::check_proxy_socket(identity)?;
    }
    super::mounts::enter_root()?;
    let run = match (plan.fetch.is_some(), fetcher) {
        (_, Some(Fetcher::Npm(npm))) => Some(super::fetch_step::npm(control, npm, plan.limits)?),
        (_, Some(Fetcher::Uv(uv))) => Some(super::fetch_uv::uv(control, uv, plan.limits)?),
        // The bare handshake, which only rows plan.
        (true, None) => {
            fetch(control).map_err(FetchError::Reported)?;
            None
        }
        (false, None) => None,
    };
    let program = run
        .as_ref()
        .map_or(plan.program.as_str(), |run| run.program.as_str());
    check_target(program)?;
    let _early = fault::plant(Point::BeforeStatus);
    // The control connection is the one descriptor above 2 allowed here.
    let own = u32::try_from(control.as_raw_fd()).ok();
    check_descriptors(own).map_err(|why| SetupFailure::new(SetupStep::Descriptors, why))?;
    Ok(Ready { limits, run })
}

/// The file the drop stage will exec is an executable regular file in the
/// root: a program a mask hid, or a package with no entry point, refuses
/// here rather than after the report.
fn check_target(program: &str) -> Result<(), SetupFailure> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = step_call(
        SetupStep::TargetMissing,
        || format!("finding {program}"),
        || fs::metadata(program),
    )?;
    if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
        return Err(SetupFailure::new(
            SetupStep::TargetMissing,
            format!("finding {program} (not an executable file)"),
        ));
    }
    Ok(())
}

/// `what` at `path`, opened `O_PATH` (no symlink followed) and checked to be
/// of `kind`; its device and inode for the check that the bind shows this
/// file once made.
fn open_path(
    path: &str,
    kind: FileType,
    what: &str,
) -> Result<(rustix::fd::OwnedFd, (u64, u64)), SetupFailure> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let fd = step_call(
        SetupStep::Binding,
        || format!("opening {what}"),
        || Ok(rustix::fs::open(path, flags, Mode::empty())?),
    )?;
    let stat = step_call(
        SetupStep::Binding,
        || format!("checking {what}"),
        || Ok(rustix::fs::fstat(&fd)?),
    )?;
    if FileType::from_raw_mode(stat.st_mode) != kind {
        return Err(SetupFailure::new(
            SetupStep::Binding,
            format!("checking {what} (not a {kind:?})"),
        ));
    }
    Ok((fd, (stat.st_dev, stat.st_ino)))
}

/// The fetch step's handshake: the credential, then `fetch_done` and the wait
/// for `expired`. The fetch command itself runs between them (the next part).
fn fetch(control: &mut UnixStream) -> Result<(), String> {
    let _issued = control_client::start_fetch(control, HELPER_BOUNDS)?;
    control_client::finish_fetch(control, HELPER_BOUNDS, None)
}

/// Refuse unless every namespace differs from the gateway's.
fn check_namespaces(host: HostNamespaces) -> Result<(), String> {
    for (name, host_inode) in [
        ("user", host.user),
        ("mnt", host.mnt),
        ("pid", host.pid),
        ("net", host.net),
        ("ipc", host.ipc),
        ("uts", host.uts),
    ] {
        let path = format!("/proc/self/ns/{name}");
        let inode = fs::metadata(&path)
            .map_err(|e| format!("reading {path} ({e})"))?
            .ino();
        if inode == host_inode {
            return Err(format!(
                "checking namespaces (the {name} namespace is the gateway's)"
            ));
        }
    }
    Ok(())
}

/// The descriptors above 2 in `open` other than `exempt`, sorted: what the
/// descriptor check refuses (D13: before the status, the helper's own control
/// descriptor is exempt; after the close, nothing is).
pub(super) fn extra_descriptors(open: &[u32], exempt: Option<u32>) -> Vec<u32> {
    let mut extra: Vec<u32> = open
        .iter()
        .copied()
        .filter(|fd| *fd > 2 && Some(*fd) != exempt)
        .collect();
    extra.sort_unstable();
    extra
}

/// Refuse if any descriptor other than 0 to 2 and `exempt` is open: closing a
/// raw one would need `unsafe`, so a descriptor inherited without
/// close-on-exec fails the preview closed instead of leaking into it.
fn check_descriptors(exempt: Option<u32>) -> Result<(), String> {
    let mut listing =
        fs::read_dir("/proc/self/fd").map_err(|e| format!("listing descriptors ({e})"))?;
    let mut extra = Vec::new();
    for entry in listing.by_ref() {
        let entry = entry.map_err(|e| format!("listing descriptors ({e})"))?;
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if fd > 2 {
            extra.push(fd);
        }
    }
    // The listing holds one descriptor of its own, on the fd directory. It is
    // still open here, so its link still names that directory.
    let own = extra.iter().position(|fd| {
        fs::read_link(format!("/proc/self/fd/{fd}"))
            .is_ok_and(|target| target.ends_with("fd") && target.starts_with("/proc"))
    });
    drop(listing);
    if let Some(own) = own {
        extra.swap_remove(own);
    }
    let extra = extra_descriptors(&extra, exempt);
    if extra.is_empty() {
        Ok(())
    } else {
        Err(format!("checking descriptors (inherited: {extra:?})"))
    }
}

/// The one fetcher the plan names, if any; a plan naming both refuses.
fn fetcher(plan: &Plan) -> Result<Option<Fetcher<'_>>, String> {
    plan.fetch
        .as_ref()
        .map(super::plan::FetchPaths::fetcher)
        .transpose()
        .map(Option::flatten)
}

/// Start the target through `__preview-drop` and stay as PID 1 until it
/// exits, reaping every orphan the namespace hands this process.
fn supervise(plan: &Plan, ready: &Ready) -> ExitCode {
    let run = ready.run.as_ref();
    // After a fetch the run is the package's own bin, with PATH holding its
    // interpreter's directory and the install's bin; the plan's program is
    // unused.
    let (program, target) = match run {
        Some(run) => (run.program.as_str(), run.argv.as_slice()),
        None => (plan.program.as_str(), plan.target.as_slice()),
    };
    let env = plan.env.iter().map(|(k, v)| match run {
        Some(run) if k == "PATH" => (k.as_str(), run.path.as_str()),
        _ => (k.as_str(), v.as_str()),
    });
    let child = Command::new("/proc/self/exe")
        .arg(super::DROP)
        .arg(&ready.limits)
        .arg(program)
        .arg("--")
        .args(target)
        .env_clear()
        .envs(env)
        .current_dir(plan::HOME)
        .spawn();
    let child = match child {
        Ok(child) => child,
        Err(e) => return refused(&format!("starting the target ({e})")),
    };
    fault::trace("spawned");
    let target = rustix::process::Pid::from_child(&child);
    loop {
        match rustix::process::wait(WaitOptions::empty()) {
            Ok(Some((pid, status))) if pid == target => return exit_code(status),
            // An orphan the namespace reparented here.
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(e) => {
                eprintln!("preview-sandbox: waiting for the target ({e})");
                return ExitCode::FAILURE;
            }
        }
    }
}

/// The target's exit code, or 128 plus its signal, as a shell reports it.
fn exit_code(status: rustix::process::WaitStatus) -> ExitCode {
    let code = status
        .exit_status()
        .or_else(|| status.terminating_signal().map(|signal| 128 + signal))
        .unwrap_or(1);
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

/// The plan's fault, obeyed by a debug build only. A release build has no
/// fault field to read: its `arm`, `injected`, `plant` and `trace` do nothing,
/// and it has no `hold`, since `run` calls `hold` only in a debug build.
#[cfg(debug_assertions)]
mod fault {
    use std::cell::Cell;
    use std::io::{self, Read as _};

    use super::super::plan::{Fault, Plan};
    use super::Point;
    use crate::preview_sandbox::control_msg::SetupStep;

    thread_local! {
        static ARMED: Cell<Option<Fault>> = const { Cell::new(None) };
    }

    pub(super) fn arm(plan: &Plan) {
        ARMED.set(plan.fault);
    }

    /// The injected error for `step`'s first call, once.
    pub(super) fn injected(step: SetupStep) -> Option<io::Error> {
        match ARMED.get() {
            Some(Fault::FailAt { step: at, denied }) if at == step => {
                ARMED.set(None);
                let kind = if denied {
                    io::ErrorKind::PermissionDenied
                } else {
                    io::ErrorKind::Other
                };
                Some(io::Error::new(kind, "the plan's fault"))
            }
            _ => None,
        }
    }

    /// `/dev/null`, opened and kept for the caller, at the fault's point.
    pub(super) fn plant(point: Point) -> Option<std::fs::File> {
        let wanted = match point {
            Point::BeforeStatus => Fault::PlantBeforeStatus,
            Point::AfterClose => Fault::PlantAfterClose,
        };
        (ARMED.get() == Some(wanted))
            .then(|| std::fs::File::open("/dev/null").ok())
            .flatten()
    }

    pub(super) fn trace(at: &str) {
        if ARMED.get() == Some(Fault::TraceAndHold) {
            eprintln!("preview-sandbox: order {at}");
        }
    }

    /// Wait for the row's release: exactly one byte on stdin. Any other
    /// ending, the end of input or an error of any kind, is a refusal, so a
    /// hold that was not released never goes on to start the target.
    pub(super) fn hold() -> Result<(), String> {
        if ARMED.get() != Some(Fault::TraceAndHold) {
            return Ok(());
        }
        let mut byte = [0_u8; 1];
        match io::stdin().read(&mut byte) {
            Ok(1) => Ok(()),
            Ok(_) => Err("hold ended: eof".into()),
            Err(e) => Err(format!("hold ended: {e}")),
        }
    }
}

#[cfg(not(debug_assertions))]
mod fault {
    use super::super::plan::Plan;
    use super::Point;
    use crate::preview_sandbox::control_msg::SetupStep;

    pub(super) fn arm(_: &Plan) {}

    pub(super) fn injected(_: SetupStep) -> Option<std::io::Error> {
        None
    }

    pub(super) fn plant(_: Point) -> Option<std::fs::File> {
        None
    }

    pub(super) fn trace(_: &str) {}
}
