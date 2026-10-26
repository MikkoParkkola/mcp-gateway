// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `__preview-drop`: the last process the gateway's code runs in before a
//! preview target (ADR-027, Linux step 5).
//!
//! The helper starts it inside the namespaces, still holding the namespace
//! capabilities `--map-root-user` granted. It drops every privilege in the
//! order the kernel needs (clearing `CAP_SETPCAP` first would make the later
//! calls fail), sets no-new-privileges and the resource limits, installs the
//! seccomp filters, and execs the target. Every call is a safe rustix or std
//! function, and any failure refuses: the target never starts half-dropped.

use std::ffi::OsString;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, ExitCode};

use rustix::process::{Resource, Rlimit, setrlimit};
use rustix::thread::{
    CapabilitiesSecureBits, CapabilitySet, CapabilitySets, clear_ambient_capability_set,
    remove_capability_from_bounding_set, set_capabilities, set_capabilities_secure_bits,
    set_no_new_privs,
};

use super::plan::Limits;

/// The refusal text for a failed `step`.
fn fail(step: &'static str) -> impl FnOnce(rustix::io::Errno) -> String {
    move |e| format!("{step} ({e})")
}

/// Run the drop and exec `target`. Returns only on failure.
pub(super) fn run(limits: Limits, target: &[OsString]) -> ExitCode {
    match drop_then_exec(limits, target) {
        Err(step) => {
            // The helper relays this line to the gateway as the refusal.
            eprintln!("preview-sandbox: refused at {step}");
            ExitCode::from(super::REFUSED)
        }
    }
}

fn drop_then_exec(limits: Limits, target: &[OsString]) -> Result<std::convert::Infallible, String> {
    let (program, args) = target.split_first().ok_or("an empty target")?;

    // Secure bits and their locks first: root in the namespace can then never
    // regain capabilities by uid tricks, and the bits cannot be cleared.
    set_capabilities_secure_bits(
        CapabilitiesSecureBits::NO_ROOT
            | CapabilitiesSecureBits::NO_ROOT_LOCKED
            | CapabilitiesSecureBits::NO_SETUID_FIXUP
            | CapabilitiesSecureBits::NO_SETUID_FIXUP_LOCKED,
    )
    .map_err(fail("setting the secure bits"))?;
    // Needs CAP_SETPCAP, which goes last, with the other sets.
    for bit in CapabilitySet::all().iter() {
        match remove_capability_from_bounding_set(bit) {
            // A capability newer than the running kernel is not in its set.
            Ok(()) | Err(rustix::io::Errno::INVAL) => {}
            Err(e) => return Err(fail("emptying the bounding set")(e)),
        }
    }
    clear_ambient_capability_set().map_err(fail("clearing the ambient set"))?;
    set_capabilities(
        None,
        CapabilitySets {
            effective: CapabilitySet::empty(),
            permitted: CapabilitySet::empty(),
            inheritable: CapabilitySet::empty(),
        },
    )
    .map_err(fail("clearing the capability sets"))?;
    set_no_new_privs(true).map_err(fail("setting no-new-privileges"))?;

    for (resource, value, step) in [
        (
            Resource::As,
            limits.address_space,
            "limiting the address space",
        ),
        (Resource::Fsize, limits.file_size, "limiting file size"),
        (Resource::Nofile, limits.open_files, "limiting open files"),
        (Resource::Nproc, limits.processes, "limiting processes"),
    ] {
        let limit = Rlimit {
            current: Some(value),
            maximum: Some(value),
        };
        setrlimit(resource, limit).map_err(fail(step))?;
    }

    super::seccomp::apply().map_err(|e| format!("installing the seccomp filter ({e})"))?;

    // `exec` returns only on failure; the environment the helper set is kept.
    let error = Command::new(program).args(args).exec();
    Err(format!("starting {} ({error})", program.to_string_lossy()))
}
