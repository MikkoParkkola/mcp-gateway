// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The core-dump guard a passthrough token lease requires (MIK-8833, design
//! E8). A lease holds a subscriber's own backend token in memory; a core dump
//! or a same-uid ptrace would copy it out. Before any lease exists the process
//! sets its core-file limit to zero (every Unix rustix covers) and, on Linux
//! and Android, marks itself not dumpable. If either cannot be applied, no
//! lease is created: the caller refuses with `core_dump_guard_unavailable`.

use std::sync::OnceLock;

/// The guard's state for this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DumpGuard {
    /// Both calls this platform has were applied.
    Applied,
    /// A call failed; the value names it (`setrlimit_core`, `prctl_dumpable`).
    Failed(&'static str),
    /// This platform has no call that prevents core dumps.
    #[cfg_attr(
        unix,
        allow(dead_code, reason = "constructed only where apply has no calls")
    )]
    Unsupported,
}

impl DumpGuard {
    /// The refusal detail a lease names when the guard is not applied.
    pub(crate) fn refusal_detail(self) -> Option<&'static str> {
        match self {
            Self::Applied => None,
            Self::Failed(call) => Some(call),
            Self::Unsupported => Some("platform_unsupported"),
        }
    }
}

/// Apply the guard once per process and return its state; later calls return
/// the first result.
pub(crate) fn ensure() -> DumpGuard {
    static GUARD: OnceLock<DumpGuard> = OnceLock::new();
    *GUARD.get_or_init(apply)
}

/// Make the platform's calls: a zero core-file limit, soft and hard (lowering
/// the hard limit is one-way for an unprivileged process, as intended), and
/// on Linux and Android a not-dumpable process, which also blocks same-uid
/// ptrace and `/proc/<pid>/mem` reads. The cfg sets mirror rustix 1.1's own
/// module gates (`process/mod.rs`).
#[cfg(all(
    unix,
    not(any(
        target_os = "espidf",
        target_os = "fuchsia",
        target_os = "horizon",
        target_os = "redox",
        target_os = "vita",
        target_os = "wasi"
    ))
))]
fn apply() -> DumpGuard {
    use rustix::process::{Resource, Rlimit, setrlimit};
    let zero = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    let core = setrlimit(Resource::Core, zero).map_err(std::io::Error::from);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let dumpable = Some(
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .map_err(std::io::Error::from),
    );
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let dumpable = None;
    classify(&core, dumpable.as_ref())
}

/// No call here prevents core dumps, so no lease is offered.
#[cfg(not(all(
    unix,
    not(any(
        target_os = "espidf",
        target_os = "fuchsia",
        target_os = "horizon",
        target_os = "redox",
        target_os = "vita",
        target_os = "wasi"
    ))
)))]
fn apply() -> DumpGuard {
    DumpGuard::Unsupported
}

/// The guard's state from the platform's call results: `core` is the
/// core-limit call, `dumpable` the Linux dumpable call where one exists.
/// Compiled where `apply` makes calls, and for its tests.
#[cfg(any(
    test,
    all(
        unix,
        not(any(
            target_os = "espidf",
            target_os = "fuchsia",
            target_os = "horizon",
            target_os = "redox",
            target_os = "vita",
            target_os = "wasi"
        ))
    )
))]
fn classify(core: &std::io::Result<()>, dumpable: Option<&std::io::Result<()>>) -> DumpGuard {
    if core.is_err() {
        return DumpGuard::Failed("setrlimit_core");
    }
    if dumpable.is_some_and(std::io::Result::is_err) {
        return DumpGuard::Failed("prctl_dumpable");
    }
    DumpGuard::Applied
}

#[cfg(test)]
#[path = "dump_guard_tests.rs"]
mod tests;
