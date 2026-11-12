// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The macOS [`ProcessTable`]: libproc for the tree, the start times and the
//! process state; signals by pid after an identity re-read. ADR-030 allows
//! `unsafe` here, for `proc_listallpids` and `proc_pidinfo` only.
//!
//! macOS has no pidfd, so the sweep reaches every process by bare pid: it stops
//! the process first, re-reads its identity, and only then kills (the sweep's
//! order, pinned by its rows). The start time has microsecond resolution.
//! `pbi_comm` and `pbi_name` are never read: no command line leaves this file.
//!
//! The arithmetic that guards the buffers and the field decoding is plain
//! functions with no platform types, so its rows run on every host.
#![allow(unsafe_code)]

#[cfg(target_os = "macos")]
use super::{Handle, ProcessTable, Sig, SignalError, by_pid_gate};
use super::{Identity, Listing, ProcState};

/// `p_stat` values from `<sys/proc.h>`.
const SSTOP: u32 = 4;
const SZOMB: u32 = 5;

/// The most pid slots one listing may use: far above any real process table, so
/// a lying size call cannot make the sweep allocate without bound.
const SLOT_CAP: usize = 1 << 20;
/// How often a listing that keeps outgrowing its buffer is retried.
#[cfg(target_os = "macos")]
const LIST_ATTEMPTS: u32 = 4;

/// What `pbi_status` says the process is doing.
fn status_of(status: u32) -> ProcState {
    match status {
        SSTOP => ProcState::Stopped,
        SZOMB => ProcState::Zombie,
        _ => ProcState::Running,
    }
}

/// The start time in microseconds; `None` when the microsecond part is not a
/// fraction of a second or the total does not fit.
fn start_micros(sec: u64, usec: u64) -> Option<u64> {
    if usec >= 1_000_000 {
        return None;
    }
    sec.checked_mul(1_000_000)?.checked_add(usec)
}

/// Pid slots for a fill and the byte length handed to the kernel for them, from
/// the pid count the size call reported: the count plus a quarter and a fixed
/// margin, since processes start between the calls. One source for both, so the
/// buffer and the length it is told can never disagree.
fn slots_for(estimate: i32) -> Option<(usize, i32)> {
    let estimate = usize::try_from(estimate).ok().filter(|count| *count > 0)?;
    let slots = estimate
        .checked_add(estimate / 4)?
        .checked_add(64)?
        .min(SLOT_CAP);
    let bytes = i32::try_from(slots.checked_mul(size_of::<i32>())?).ok()?;
    Some((slots, bytes))
}

/// How a fill ended.
#[derive(Debug, PartialEq, Eq)]
enum Fill {
    /// This many pids are valid.
    Complete(usize),
    /// The buffer was full: the table may have grown past it, list again.
    Again,
    Failed,
}

/// Judge a fill's return value against the buffer it was given. The kernel's
/// count is never trusted past the buffer: a count that reaches the slot count
/// is a full buffer, however large it claims to be.
fn judge_fill(returned: i32, slots: usize) -> Fill {
    let Ok(count) = usize::try_from(returned) else {
        return Fill::Failed;
    };
    if count == 0 {
        Fill::Failed
    } else if count >= slots {
        Fill::Again
    } else {
        Fill::Complete(count)
    }
}

/// The process record as the table reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Info {
    ppid: u32,
    start: u64,
    state: ProcState,
}

/// Why a record could not be had.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Miss {
    /// No such process: an exit, which the table may believe.
    Gone,
    /// Not ours to read (another user's process): it cannot be a descendant the
    /// gateway may signal, so it is left out rather than called a failure.
    Foreign,
    /// Any other failure: says nothing about whether the process exists.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Lookup {
    Found(Info),
    Missing(Miss),
}

/// `errno` values of `ESRCH` and `EPERM` (the same on macOS and Linux).
const ESRCH: i32 = 3;
const EPERM: i32 = 1;

fn miss_of(errno: Option<i32>) -> Miss {
    match errno {
        Some(ESRCH) => Miss::Gone,
        Some(EPERM) => Miss::Foreign,
        _ => Miss::Failed,
    }
}

/// Decode the fields of a `proc_bsdinfo` record the kernel returned for
/// `asked`. A record that names another pid, or whose start time does not fit,
/// is a failure, never a process.
fn decode(asked: u32, named: u32, parent: u32, status: u32, sec: u64, usec: u64) -> Lookup {
    if named != asked {
        return Lookup::Missing(Miss::Failed);
    }
    match start_micros(sec, usec) {
        Some(start) => Lookup::Found(Info {
            ppid: parent,
            start,
            state: status_of(status),
        }),
        None => Lookup::Missing(Miss::Failed),
    }
}

/// What the table needs from libproc: the real calls on macOS, a script in rows.
trait Probe {
    /// Every pid, or `None` when the listing failed.
    fn list(&mut self) -> Option<Vec<u32>>;
    fn info(&mut self, pid: u32) -> Lookup;
}

/// The whole table. A failed listing or a failed entry makes it incomplete: the
/// sweep must not read absence from it as an exit.
fn table_read(probe: &mut dyn Probe) -> Listing {
    let Some(pids) = probe.list() else {
        return Listing {
            rows: Vec::new(),
            complete: false,
        };
    };
    let mut listing = Listing {
        rows: Vec::new(),
        complete: true,
    };
    for pid in pids {
        match probe.info(pid) {
            Lookup::Found(info) => listing.rows.push((
                Identity {
                    pid,
                    start: info.start,
                },
                info.ppid,
            )),
            Lookup::Missing(Miss::Gone | Miss::Foreign) => {}
            Lookup::Missing(Miss::Failed) => listing.complete = false,
        }
    }
    listing
}

/// A member's state. A read that failed, or that is not ours to make, is not an
/// exit: it is `Unknown`.
fn table_state(probe: &mut dyn Probe, id: Identity) -> ProcState {
    match probe.info(id.pid) {
        Lookup::Found(info) if info.start == id.start => info.state,
        Lookup::Found(_) | Lookup::Missing(Miss::Gone) => ProcState::Gone,
        Lookup::Missing(Miss::Foreign | Miss::Failed) => ProcState::Unknown,
    }
}

/// libproc itself.
#[cfg(target_os = "macos")]
struct Libproc;

#[cfg(target_os = "macos")]
impl Probe for Libproc {
    fn list(&mut self) -> Option<Vec<u32>> {
        for _ in 0..LIST_ATTEMPTS {
            // SAFETY: contract 1 and 6: a null buffer with a zero length is the
            // documented size query; it writes nothing and returns a count.
            let estimate = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
            let (slots, bytes) = slots_for(estimate)?;
            let mut pids = vec![0_i32; slots];
            // SAFETY: contract 1 and 2: `pids` is a live, writable buffer of
            // exactly `bytes` bytes, 4-byte aligned as an `i32` slice, and the
            // kernel writes at most `bytes` into it.
            let returned = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
            match judge_fill(returned, slots) {
                Fill::Complete(count) => {
                    return Some(
                        pids[..count]
                            .iter()
                            .filter_map(|pid| u32::try_from(*pid).ok().filter(|pid| *pid > 0))
                            .collect(),
                    );
                }
                Fill::Again => {}
                Fill::Failed => return None,
            }
        }
        None
    }

    fn info(&mut self, pid: u32) -> Lookup {
        let Some((asked, size)) = i32::try_from(pid)
            .ok()
            .zip(i32::try_from(size_of::<libc::proc_bsdinfo>()).ok())
        else {
            return Lookup::Missing(Miss::Failed);
        };
        let mut record = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        // SAFETY: contract 1 and 3: `record` is a live, writable, properly
        // aligned `proc_bsdinfo` of exactly `size` bytes, and the kernel writes
        // at most `size`.
        let returned = unsafe {
            libc::proc_pidinfo(
                asked,
                libc::PROC_PIDTBSDINFO,
                0,
                record.as_mut_ptr().cast(),
                size,
            )
        };
        if returned != size {
            return Lookup::Missing(miss_of(std::io::Error::last_os_error().raw_os_error()));
        }
        // SAFETY: contract 3: the call returned the full record size, so every
        // field was written; the type is plain integers and arrays, for which
        // the zeroed start state is valid in any case.
        let record = unsafe { record.assume_init() };
        decode(
            pid,
            record.pbi_pid,
            record.pbi_ppid,
            record.pbi_status,
            record.pbi_start_tvsec,
            record.pbi_start_tvusec,
        )
    }
}

/// One sweep's table.
#[cfg(target_os = "macos")]
pub(in crate::transport::stdio) struct MacTable {
    origin: std::time::Instant,
}

#[cfg(target_os = "macos")]
impl MacTable {
    pub(in crate::transport::stdio) fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }

    /// The pid with the start time that tells it from a later process.
    pub(in crate::transport::stdio) fn identity_of(pid: u32) -> Option<Identity> {
        match Libproc.info(pid) {
            Lookup::Found(info) => Some(Identity {
                pid,
                start: info.start,
            }),
            Lookup::Missing(_) => None,
        }
    }
}

#[cfg(target_os = "macos")]
impl ProcessTable for MacTable {
    fn read(&mut self) -> Listing {
        table_read(&mut Libproc)
    }

    fn state(&mut self, id: Identity) -> ProcState {
        table_state(&mut Libproc, id)
    }

    /// By pid only: there is no handle to hold. The identity is re-read
    /// immediately before the signal; the sweep stops a process before it kills.
    fn signal(&mut self, id: Identity, sig: Sig, _held: bool) -> Result<Handle, SignalError> {
        use rustix::process::{Pid, Signal, kill_process};
        let pid = i32::try_from(id.pid)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or(SignalError::Failed)?;
        match Libproc.info(id.pid) {
            Lookup::Found(info) if info.start == id.start => by_pid_gate(sig, info.state)?,
            Lookup::Found(_) | Lookup::Missing(Miss::Gone) => return Err(SignalError::Mismatch),
            Lookup::Missing(Miss::Foreign) => return Err(SignalError::Denied),
            Lookup::Missing(Miss::Failed) => return Err(SignalError::Failed),
        }
        let signal = match sig {
            Sig::Stop => Signal::STOP,
            Sig::Cont => Signal::CONT,
            Sig::Kill => Signal::KILL,
        };
        kill_process(pid, signal)
            .map(|()| Handle::ByPid)
            .map_err(|err| match err {
                rustix::io::Errno::SRCH => SignalError::Mismatch,
                rustix::io::Errno::PERM => SignalError::Denied,
                _ => SignalError::Failed,
            })
    }

    fn now(&mut self) -> std::time::Duration {
        self.origin.elapsed()
    }
}

#[cfg(test)]
#[path = "stdio_sweep_macos_tests.rs"]
mod tests;
