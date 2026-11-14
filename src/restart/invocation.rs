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
// Off unix the stored invocation is never built, so the same items stay dead
// in test builds there too.
#![cfg_attr(
    any(not(test), not(unix)),
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
    #[cfg(not(unix))]
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
    Ready(Box<Invocation>),
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
    /// With the change time, catches a rewrite into the same inode. ctime is
    /// stamped at the filesystem's clock tick (often a few ms), so a
    /// same-size rewrite within one tick can keep both.
    pub(crate) size: u64,
    pub(crate) ctime_sec: i64,
    pub(crate) ctime_nsec: i64,
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

impl InvocationState {
    /// The confirmation binding (slice 7); None when restart is unavailable.
    pub(crate) fn digest(&self) -> Option<InvocationDigest> {
        match self {
            #[cfg(unix)]
            Self::Ready(inv) => Some(inv.digest()),
            Self::Unavailable(_) => None,
        }
    }

    /// The target file's identity now, following symlinks as execve does;
    /// None when restart is unavailable.
    pub(crate) fn target_file_id(&self) -> Option<std::io::Result<FileId>> {
        match self {
            #[cfg(unix)]
            Self::Ready(inv) => Some(inv.file_id()),
            Self::Unavailable(_) => None,
        }
    }
}

#[cfg(unix)]
impl Invocation {
    /// SHA-256 over a domain tag, a field count, then each field length-
    /// prefixed (little-endian u64): argv0, the tail count and items, cwd,
    /// target. PATH is left out: it only chose the target, which is in.
    pub(super) fn digest(&self) -> InvocationDigest {
        use sha2::{Digest as _, Sha256};
        use std::os::unix::ffi::OsStrExt as _;
        fn field(h: &mut Sha256, bytes: &[u8]) {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        let mut h = Sha256::new();
        h.update(b"mcp-gateway/invocation/v1\0");
        h.update(4_u32.to_le_bytes());
        field(&mut h, self.argv0.as_bytes());
        h.update((self.tail.len() as u64).to_le_bytes());
        for item in &self.tail {
            field(&mut h, item.as_bytes());
        }
        field(&mut h, self.cwd.as_os_str().as_bytes());
        field(&mut h, self.target.as_os_str().as_bytes());
        InvocationDigest(h.finalize().into())
    }

    fn file_id(&self) -> std::io::Result<FileId> {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::metadata(&self.target)?;
        Ok(FileId {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        })
    }

    #[cfg(test)]
    pub(super) fn for_test(
        argv0: OsString,
        tail: Vec<OsString>,
        cwd: PathBuf,
        target: PathBuf,
        entry_mask: nix::sys::signal::SigSet,
    ) -> Self {
        Self {
            argv0,
            tail,
            cwd,
            target,
            entry_mask,
        }
    }
}

/// True when `path` is a regular file this process may execute (symlinks
/// followed, as execve does).
#[cfg(unix)]
pub(crate) fn is_executable_regular(path: &std::path::Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file())
        && rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()
}

/// The calling thread's signal mask, read without changing it. A failed read
/// counts as everything blocked, so the capture refuses rather than guesses.
#[cfg(unix)]
pub(crate) fn current_thread_mask() -> nix::sys::signal::SigSet {
    nix::sys::signal::SigSet::thread_get_mask().unwrap_or_else(|_| nix::sys::signal::SigSet::all())
}

/// Signals an operator or supervisor stops the gateway with; one blocked at
/// entry would be blocked in the restarted gateway too.
#[cfg(unix)]
const STOP_SIGNALS: [nix::sys::signal::Signal; 4] = [
    nix::sys::signal::Signal::SIGINT,
    nix::sys::signal::Signal::SIGTERM,
    nix::sys::signal::Signal::SIGHUP,
    nix::sys::signal::Signal::SIGPIPE,
];

/// Pure capture: no global state, no I/O beyond `probe`.
#[cfg(unix)]
pub(crate) fn capture_from(
    inputs: CaptureInputs,
    given: &Cli,
    probe: &dyn Fn(&std::path::Path) -> bool,
) -> InvocationState {
    use UnavailableReason as Off;
    let off = InvocationState::Unavailable;
    if given.command.is_some() {
        return off(Off::NotServe);
    }
    let Some(argv0) = inputs.args.first().filter(|a| !a.is_empty()) else {
        return off(Off::NoArgv0);
    };
    if let Some(sig) = STOP_SIGNALS.into_iter().find(|s| inputs.mask.contains(*s)) {
        return off(Off::BlockedSignal(sig));
    }
    let Ok(cwd) = inputs.cwd else {
        return off(Off::Cwd);
    };
    match <Cli as clap::Parser>::try_parse_from(&inputs.args) {
        Ok(parsed) if same_serve(&parsed, given) => {}
        _ => return off(Off::Embedded),
    }
    match resolve(argv0, &cwd, inputs.path_env.as_deref(), probe) {
        Ok(target) => InvocationState::Ready(Box::new(Invocation {
            argv0: argv0.clone(),
            tail: inputs.args[1..].to_vec(),
            cwd,
            target,
            entry_mask: inputs.mask,
        })),
        Err(reason) => off(reason),
    }
}

/// Whether two serve invocations are the same, field for field. Exhaustive
/// on purpose: a new `Cli` field fails to compile here until it is compared.
#[cfg(unix)]
fn same_serve(a: &Cli, b: &Cli) -> bool {
    let Cli {
        config,
        port,
        host,
        log_level,
        log_format,
        no_meta_mcp,
        protocol_revision_window,
        command,
    } = a;
    command.is_none()
        && b.command.is_none()
        && *config == b.config
        && *port == b.port
        && *host == b.host
        && *log_level == b.log_level
        && *log_format == b.log_format
        && *no_meta_mcp == b.no_meta_mcp
        && *protocol_revision_window == b.protocol_revision_window
}

/// argv0 with a `/` is anchored to the startup cwd as spelled; a bare name
/// takes the first executable regular file on the startup PATH, empty and
/// relative entries anchored to the cwd. No canonicalizing, no default PATH.
#[cfg(unix)]
fn resolve(
    argv0: &std::ffi::OsStr,
    cwd: &std::path::Path,
    path_env: Option<&std::ffi::OsStr>,
    probe: &dyn Fn(&std::path::Path) -> bool,
) -> Result<PathBuf, UnavailableReason> {
    use std::os::unix::ffi::OsStrExt as _;
    if argv0.as_bytes().contains(&b'/') {
        let target = cwd.join(argv0);
        return if probe(&target) {
            Ok(target)
        } else {
            Err(UnavailableReason::NotExecutable)
        };
    }
    let path_env = path_env.ok_or(UnavailableReason::NotFound)?;
    std::env::split_paths(path_env)
        .map(|dir| cwd.join(dir).join(argv0))
        .find(|candidate| probe(candidate))
        .ok_or(UnavailableReason::NotFound)
}

/// Capture once and install the result; the first call wins.
#[cfg(unix)]
pub(crate) fn capture_and_install(inputs: CaptureInputs, given: &Cli) {
    if INVOCATION.get().is_none() {
        // A lost race keeps the first value, which is the rule.
        let _ = INVOCATION.set(capture_from(inputs, given, &is_executable_regular));
    }
}

/// Off unix, restart is guidance-only.
#[cfg(not(unix))]
pub(crate) fn capture_and_install(inputs: CaptureInputs, given: &Cli) {
    let _ = (inputs, given);
    let _ = INVOCATION.set(InvocationState::Unavailable(UnavailableReason::Unsupported));
}
