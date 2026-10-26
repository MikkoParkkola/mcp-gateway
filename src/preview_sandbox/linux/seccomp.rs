// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The seccomp filters `__preview-drop` applies just before it execs a preview
//! child (ADR-027, Linux step 5).
//!
//! Two filters, both installed: the kernel runs every installed filter and the
//! most restrictive answer wins, and seccompiler gives a filter one match
//! action, while `clone3` needs `ENOSYS` (so libc falls back to plain `clone`)
//! and the rest `EPERM`. A default-allow deny list, not an allowlist: the
//! namespaces and the private root are the boundary, and the filter only
//! narrows the kernel surface (the ADR records why an allowlist was not taken).

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch, sock_filter,
};

/// `SECCOMP_RET_KILL_PROCESS`.
const KILL_PROCESS: u32 = 0x8000_0000;

/// The preamble prepended to the first filter, as `(code, jt, jf, k)`, value
/// for value as ADR-027 publishes it. seccompiler's rules are keyed by syscall
/// number and cannot say "any number with the x32 bit set", and an
/// architecture check alone passes x32 numbers.
#[cfg(target_arch = "x86_64")]
pub(crate) const PREAMBLE: &[(u16, u8, u8, u32)] = &[
    (0x20, 0, 0, 4),           // load seccomp_data.arch
    (0x15, 1, 0, 0xC000_003E), // AUDIT_ARCH_X86_64: skip the kill
    (0x06, 0, 0, KILL_PROCESS),
    (0x20, 0, 0, 0),           // load seccomp_data.nr
    (0x45, 0, 1, 0x4000_0000), // x32 bit set: fall to the kill; clear: skip it
    (0x06, 0, 0, KILL_PROCESS),
];

/// aarch64 has no x32 ABI, so its preamble is the architecture check alone.
#[cfg(target_arch = "aarch64")]
pub(crate) const PREAMBLE: &[(u16, u8, u8, u32)] = &[
    (0x20, 0, 0, 4),           // load seccomp_data.arch
    (0x15, 1, 0, 0xC000_00B7), // AUDIT_ARCH_AARCH64: skip the kill
    (0x06, 0, 0, KILL_PROCESS),
];

#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;

/// Every namespace flag `clone` takes; a `clone` naming any of them is refused.
const NAMESPACE_FLAGS: [u64; 8] = [
    0x0000_0080, // CLONE_NEWTIME
    0x0002_0000, // CLONE_NEWNS
    0x0200_0000, // CLONE_NEWCGROUP
    0x0400_0000, // CLONE_NEWUTS
    0x0800_0000, // CLONE_NEWIPC
    0x1000_0000, // CLONE_NEWUSER
    0x2000_0000, // CLONE_NEWPID
    0x4000_0000, // CLONE_NEWNET
];

/// Calls refused outright with `EPERM`: the keyrings (an inherited session
/// keyring stays unreadable), tracing and cross-process memory, namespace and
/// mount changes (the new mount API included), `io_uring` and `bpf`.
const DENIED: [libc::c_long; 22] = [
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_bpf,
    libc::SYS_open_tree,
    libc::SYS_move_mount,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
];

/// The two programs, in the order they are installed.
pub(crate) fn programs() -> Result<[BpfProgram; 2], seccompiler::BackendError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> =
        DENIED.iter().map(|&nr| (nr, Vec::new())).collect();
    // `clone`'s flags are its first argument on both architectures. Rules in
    // one chain are OR'd, so one rule per flag reads "any namespace flag set".
    let clone_rules = NAMESPACE_FLAGS
        .iter()
        .map(|&flag| {
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(flag),
                flag,
            )
            .and_then(|condition| SeccompRule::new(vec![condition]))
        })
        .collect::<Result<Vec<_>, _>>()?;
    rules.insert(libc::SYS_clone, clone_rules);
    let deny = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM.cast_unsigned()),
        ARCH,
    )?;
    let mut first: BpfProgram = PREAMBLE
        .iter()
        .map(|&(code, jt, jf, k)| sock_filter { code, jt, jf, k })
        .collect();
    first.extend(BpfProgram::try_from(deny)?);

    let clone3 = SeccompFilter::new(
        BTreeMap::from([(libc::SYS_clone3, Vec::new())]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS.cast_unsigned()),
        ARCH,
    )?;
    Ok([first, BpfProgram::try_from(clone3)?])
}

/// Install both programs on the calling thread. `__preview-drop` is
/// single-threaded when it calls this, and the target it execs inherits them.
pub(crate) fn apply() -> Result<(), seccompiler::Error> {
    for program in programs().map_err(seccompiler::Error::Backend)? {
        seccompiler::apply_filter(&program)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The applied program starts with the published tuples, value for value.
    #[test]
    fn first_program_starts_with_the_published_preamble() {
        let [first, _] = programs().expect("filters compile");
        let head: Vec<_> = first[..PREAMBLE.len()]
            .iter()
            .map(|i| (i.code, i.jt, i.jf, i.k))
            .collect();
        // Typed out from ADR-027's table, not read from `PREAMBLE`, so an edit
        // to the constant cannot also change what it is checked against.
        #[cfg(target_arch = "x86_64")]
        let published: &[(u16, u8, u8, u32)] = &[
            (0x20, 0, 0, 4),
            (0x15, 1, 0, 0xC000_003E),
            (0x06, 0, 0, 0x8000_0000),
            (0x20, 0, 0, 0),
            (0x45, 0, 1, 0x4000_0000),
            (0x06, 0, 0, 0x8000_0000),
        ];
        #[cfg(target_arch = "aarch64")]
        let published: &[(u16, u8, u8, u32)] = &[
            (0x20, 0, 0, 4),
            (0x15, 1, 0, 0xC000_00B7),
            (0x06, 0, 0, 0x8000_0000),
        ];
        assert_eq!(head, published);
        // seccompiler's own program follows, starting with its arch load.
        assert_eq!(first[PREAMBLE.len()].code, 0x20);
    }

    /// A jump lands inside the preamble or on the first instruction after it
    /// (seccompiler's program), never past it.
    #[test]
    fn every_preamble_jump_lands_at_most_one_past_it() {
        for (at, &(code, jt, jf, _)) in PREAMBLE.iter().enumerate() {
            if code & 0x07 == 0x05 {
                assert!(at + 1 + usize::from(jt.max(jf)) <= PREAMBLE.len());
            }
        }
    }

    #[test]
    fn the_preamble_ends_in_a_kill_for_every_failing_test() {
        assert!(
            PREAMBLE
                .iter()
                .filter(|i| i.0 == 0x06)
                .all(|i| i.3 == KILL_PROCESS)
        );
    }
}
