// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `__preview-sandbox` on Linux: the first process of the preview's PID
//! namespace (ADR-027, Linux steps 1 to 3, 5 and 7).
//!
//! util-linux `unshare` has already made the namespaces. The helper checks it
//! really is in fresh ones, builds and enters the private root, then starts
//! the target through `__preview-drop` and stays as PID 1: it reaps orphans
//! and exits when the target does, which makes the kernel kill everything
//! left in the namespace. It never runs untrusted code itself.

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::process::{Command, ExitCode};

use rustix::fs::FileType;
use rustix::process::{DumpableBehavior, WaitOptions, set_dumpable_behavior};

use super::control_client::{self, HELPER_BOUNDS};
use super::plan::{self, Fetcher, HostNamespaces, Plan};

pub(super) fn run(plan: &Plan) -> ExitCode {
    let control = match setup(plan) {
        Ok(control) => control,
        Err(step) => {
            eprintln!("preview-sandbox: refused at {step}");
            return ExitCode::from(super::REFUSED);
        }
    };
    let mut run = None;
    if let Some(mut control) = control {
        let fetched = match fetcher(plan) {
            Ok(Some(Fetcher::Npm(npm))) => {
                super::fetch_step::npm(&mut control, npm, plan.limits).map(Some)
            }
            Ok(Some(Fetcher::Uv(uv))) => {
                super::fetch_uv::uv(&mut control, uv, plan.limits).map(Some)
            }
            Ok(None) => fetch(&mut control).map(|()| None),
            Err(why) => Err(why),
        };
        // Dropped before any child exists, so no preview process can inherit
        // or reach the control connection.
        drop(control);
        match fetched {
            Ok(after) => run = after,
            Err(step) => {
                eprintln!("preview-sandbox: refused at {step}");
                return ExitCode::from(super::REFUSED);
            }
        }
    }
    // Nothing the fetch step opened may reach the target.
    if let Err(step) = check_descriptors() {
        eprintln!("preview-sandbox: refused at {step}");
        return ExitCode::from(super::REFUSED);
    }
    supervise(plan, run.as_ref())
}

fn setup(plan: &Plan) -> Result<Option<UnixStream>, String> {
    check_namespaces(plan.host)?;
    check_descriptors()?;
    // After the descriptor check, on the host path, before the new root
    // hides it; std sockets are close-on-exec.
    let control = plan
        .fetch
        .as_ref()
        .map(|paths| {
            UnixStream::connect(&paths.control)
                .map_err(|e| format!("connecting the control socket ({e})"))
        })
        .transpose()?;
    // A capability-less process in the namespace then cannot read this
    // process's environ, fd table or memory through /proc/1.
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|e| format!("making the helper non-dumpable ({e})"))?;
    // The CA snapshot, opened before staging covers host /tmp; it is bound
    // from this descriptor, which is closed once bound, before any child.
    let ca = plan
        .fetch
        .as_ref()
        .map(|paths| open_path(&paths.ca, FileType::RegularFile, "the CA snapshot"))
        .transpose()?;
    // The proxy socket likewise: it sits beside the snapshot.
    let proxy = fetcher(plan)?
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
    Ok(control)
}

/// `what` at `path`, opened `O_PATH` (no symlink followed) and checked to be
/// of `kind`; its device and inode for the check that the bind shows this
/// file once made.
fn open_path(
    path: &str,
    kind: FileType,
    what: &str,
) -> Result<(rustix::fd::OwnedFd, (u64, u64)), String> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let fd = rustix::fs::open(path, flags, Mode::empty())
        .map_err(|e| format!("opening {what} ({e})"))?;
    let stat = rustix::fs::fstat(&fd).map_err(|e| format!("checking {what} ({e})"))?;
    if FileType::from_raw_mode(stat.st_mode) != kind {
        return Err(format!("checking {what} (not a {kind:?})"));
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

/// Refuse if any descriptor other than 0 to 2 is open: closing a raw one
/// would need `unsafe`, so a descriptor inherited without close-on-exec fails
/// the preview closed instead of leaking into it.
fn check_descriptors() -> Result<(), String> {
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
    let extra = extra_descriptors(&extra, None);
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
fn supervise(plan: &Plan, run: Option<&super::fetch_step::Run>) -> ExitCode {
    let limits = match serde_json::to_string(&plan.limits) {
        Ok(limits) => limits,
        Err(e) => {
            eprintln!("preview-sandbox: refused at encoding the limits ({e})");
            return ExitCode::from(super::REFUSED);
        }
    };
    // After an npm fetch the run is the package's own bin, with PATH holding
    // node and the install's bin directory; the plan's program is unused.
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
        .arg(limits)
        .arg(program)
        .arg("--")
        .args(target)
        .env_clear()
        .envs(env)
        .current_dir(plan::HOME)
        .spawn();
    let child = match child {
        Ok(child) => child,
        Err(e) => {
            eprintln!("preview-sandbox: refused at starting the target ({e})");
            return ExitCode::from(super::REFUSED);
        }
    };
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
