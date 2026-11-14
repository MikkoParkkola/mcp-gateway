// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The invocation a restart re-execs, captured once at CLI entry
//! (restart slice 4a): argv0 and the argv tail as given, the startup cwd and
//! PATH, the resolved target and the entry signal mask. Nothing is
//! canonicalized and nothing is looked up again later, so a restart runs the
//! program the operator started, spelled as they spelled it.
//!
//! Capture never stops startup: any failure leaves restart `Unavailable` with
//! a reason and the gateway serves on.
// Slice 4a ships the invocation ahead of its readers: slice 7 binds
// the digest and file id, slice 4b's exec reads the stored fields. `expect`, so
// the attribute fails the build once they land and it is no longer needed.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "readers land in restart slices 4b and 7")
)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::cli::Cli;

/// What `cli::run` hands to the capture: the process's own values in
/// production, synthetic ones in tests.
pub(crate) struct CaptureInputs {
    pub(crate) args: Vec<OsString>,
    pub(crate) cwd: std::io::Result<PathBuf>,
    pub(crate) path_env: Option<OsString>,
    #[cfg(unix)]
    pub(crate) mask: nix::sys::signal::SigSet,
}

/// Why restart is off. Shown to the operator as recovery text (slice 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnavailableReason {
    /// `cli::run` has not captured (for example, an embedder's `Gateway::run`).
    NotCaptured,
    /// Restart is guidance-only on this platform.
    Unsupported,
    /// The process was started with no argv0, or an empty one.
    NoArgv0,
    /// A subcommand runs, not the server.
    NotServe,
    /// The `Cli` handed to `cli::run` is not what the process's own argv
    /// parses to, so re-running that argv would start something else.
    Embedded,
    /// A bare argv0 names no executable regular file on the startup PATH.
    NotFound,
    /// A slash-spelled argv0 is not an executable regular file.
    NotExecutable,
    /// The startup working directory could not be read.
    Cwd,
    /// The process started with this signal blocked; a restarted gateway
    /// could not be stopped with it.
    #[cfg(unix)]
    BlockedSignal(nix::sys::signal::Signal),
}

/// The process-global capture result.
#[derive(Debug)]
pub(crate) enum InvocationState {
    #[cfg(unix)]
    Ready(Invocation),
    Unavailable(UnavailableReason),
}

/// Identity a confirmation binds to (slice 7): fixed for the process lifetime,
/// never logged, shown or sent.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvocationDigest(pub(super) [u8; 32]);

impl std::fmt::Debug for InvocationDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InvocationDigest(..)")
    }
}

/// The target file's identity at the time of the call (slice 7 binds it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileId {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
}

/// A Ready capture. Its `Debug` shows lengths only: argv may carry secrets.
#[cfg(unix)]
pub(crate) struct Invocation {
    pub(super) argv0: OsString,
    pub(super) tail: Vec<OsString>,
    pub(super) cwd: PathBuf,
    pub(super) target: PathBuf,
    pub(super) entry_mask: nix::sys::signal::SigSet,
}

#[cfg(unix)]
impl std::fmt::Debug for Invocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invocation")
            .field("argv0_len", &self.argv0.len())
            .field("tail_items", &self.tail.len())
            .field("cwd_len", &self.cwd.as_os_str().len())
            .field("target_len", &self.target.as_os_str().len())
            .finish_non_exhaustive()
    }
}

static INVOCATION: OnceLock<InvocationState> = OnceLock::new();
static NOT_CAPTURED: InvocationState = InvocationState::Unavailable(UnavailableReason::NotCaptured);

/// The capture, or `Unavailable(NotCaptured)` before (or without) one. Never
/// initializes the global, so a later capture still lands.
pub(crate) fn invocation() -> &'static InvocationState {
    INVOCATION.get().unwrap_or(&NOT_CAPTURED)
}

// RED-PHASE STUB A (always unavailable, wrong values): replaced by the real
// implementation in the next commit. Every row must fail against it.

impl InvocationState {
    /// The confirmation binding (slice 7); None when restart is unavailable.
    pub(crate) fn digest(&self) -> Option<InvocationDigest> {
        None
    }

    /// The target file's identity now, following symlinks as execve does;
    /// None when restart is unavailable.
    pub(crate) fn target_file_id(&self) -> Option<std::io::Result<FileId>> {
        None
    }
}

#[cfg(unix)]
impl Invocation {
    pub(super) fn digest(&self) -> InvocationDigest {
        InvocationDigest([0; 32])
    }

    #[cfg(test)]
    pub(super) fn for_test(
        argv0: OsString,
        tail: Vec<OsString>,
        cwd: PathBuf,
        target: PathBuf,
        entry_mask: nix::sys::signal::SigSet,
    ) -> Self {
        let _ = (argv0, tail, cwd, target, entry_mask);
        Self {
            argv0: OsString::new(),
            tail: Vec::new(),
            cwd: PathBuf::new(),
            target: PathBuf::new(),
            entry_mask: nix::sys::signal::SigSet::empty(),
        }
    }
}

/// True when `path` is a regular file this process may execute.
#[cfg(unix)]
pub(crate) fn is_executable_regular(path: &std::path::Path) -> bool {
    let _ = path;
    false
}

/// The calling thread's signal mask, read without changing it.
#[cfg(unix)]
pub(crate) fn current_thread_mask() -> nix::sys::signal::SigSet {
    nix::sys::signal::SigSet::empty()
}

/// Pure capture: no global state, no I/O beyond `probe`.
#[cfg(unix)]
pub(crate) fn capture_from(
    inputs: CaptureInputs,
    given: &Cli,
    probe: &dyn Fn(&std::path::Path) -> bool,
) -> InvocationState {
    let _ = (inputs, given, probe);
    InvocationState::Unavailable(UnavailableReason::NotFound)
}

/// Capture once and install the result; the first call wins.
pub(crate) fn capture_and_install(inputs: CaptureInputs, given: &Cli) {
    let _ = (inputs, given);
}
