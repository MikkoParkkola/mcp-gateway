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
use std::process::{Command, ExitCode};

use rustix::process::{DumpableBehavior, WaitOptions, set_dumpable_behavior};

use super::plan::{self, HostNamespaces, Plan};

pub(super) fn run(plan: &Plan) -> ExitCode {
    if let Err(step) = setup(plan) {
        eprintln!("preview-sandbox: refused at {step}");
        return ExitCode::from(super::REFUSED);
    }
    supervise(plan)
}

fn setup(plan: &Plan) -> Result<(), String> {
    check_namespaces(plan.host)?;
    check_descriptors()?;
    // A capability-less process in the namespace then cannot read this
    // process's environ, fd table or memory through /proc/1.
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|e| format!("making the helper non-dumpable ({e})"))?;
    super::mounts::build_root(plan)?;
    super::mounts::enter_root()
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
    if extra.is_empty() {
        Ok(())
    } else {
        extra.sort_unstable();
        Err(format!("checking descriptors (inherited: {extra:?})"))
    }
}

/// Start the target through `__preview-drop` and stay as PID 1 until it
/// exits, reaping every orphan the namespace hands this process.
fn supervise(plan: &Plan) -> ExitCode {
    let limits = match serde_json::to_string(&plan.limits) {
        Ok(limits) => limits,
        Err(e) => {
            eprintln!("preview-sandbox: refused at encoding the limits ({e})");
            return ExitCode::from(super::REFUSED);
        }
    };
    let child = Command::new("/proc/self/exe")
        .arg(super::DROP)
        .arg(limits)
        .arg("--")
        .args(&plan.target)
        .env_clear()
        .envs(plan.env.iter().map(|(k, v)| (k, v)))
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
