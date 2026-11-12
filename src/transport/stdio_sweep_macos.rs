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

use super::ProcState;
#[cfg(target_os = "macos")]
use super::{Handle, Identity, ProcessTable, Sig, SignalError};

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

/// Pid slots for a fill, from the pid count the size call reported: the count
/// plus a quarter and a fixed margin, since processes start between the calls.
fn slots_for(estimate: i32) -> Option<usize> {
    let estimate = usize::try_from(estimate).ok().filter(|count| *count > 0)?;
    let slots = estimate
        .checked_add(estimate / 4)?
        .checked_add(64)?
        .min(SLOT_CAP);
    // The same limit the byte length handed to the kernel has to respect.
    i32::try_from(slots.checked_mul(size_of::<i32>())?).ok()?;
    Some(slots)
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
#[cfg(target_os = "macos")]
struct Info {
    ppid: u32,
    start: u64,
    state: ProcState,
}

#[cfg(target_os = "macos")]
fn list_pids() -> Option<Vec<u32>> {
    for _ in 0..LIST_ATTEMPTS {
        // SAFETY: contract 1 and 6: a null buffer with a zero length is the
        // documented size query; it writes nothing and returns a count.
        let estimate = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        let slots = slots_for(estimate)?;
        let mut pids = vec![0_i32; slots];
        let bytes = i32::try_from(slots.checked_mul(size_of::<i32>())?).ok()?;
        // SAFETY: contract 1 and 2: `pids` is a live, writable buffer of exactly
        // `bytes` bytes, 4-byte aligned as an `i32` slice, and the kernel writes
        // at most `bytes` into it.
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

#[cfg(target_os = "macos")]
fn info_of(pid: u32) -> Option<Info> {
    let size = i32::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    let mut record = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: contract 1 and 3: `record` is a live, writable, properly aligned
    // `proc_bsdinfo` of exactly `size` bytes, and the kernel writes at most `size`.
    let returned = unsafe {
        libc::proc_pidinfo(
            i32::try_from(pid).ok()?,
            libc::PROC_PIDTBSDINFO,
            0,
            record.as_mut_ptr().cast(),
            size,
        )
    };
    if returned != size {
        return None;
    }
    // SAFETY: contract 3: the call returned the full record size, so every
    // field was written; the type is plain integers and arrays, for which the
    // zeroed start state is valid in any case.
    let record = unsafe { record.assume_init() };
    if record.pbi_pid != pid {
        return None;
    }
    Some(Info {
        ppid: record.pbi_ppid,
        start: start_micros(record.pbi_start_tvsec, record.pbi_start_tvusec)?,
        state: status_of(record.pbi_status),
    })
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
        Some(Identity {
            pid,
            start: info_of(pid)?.start,
        })
    }
}

#[cfg(target_os = "macos")]
impl ProcessTable for MacTable {
    fn read(&mut self) -> Vec<(Identity, u32)> {
        list_pids()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|pid| {
                let info = info_of(pid)?;
                Some((
                    Identity {
                        pid,
                        start: info.start,
                    },
                    info.ppid,
                ))
            })
            .collect()
    }

    fn state(&mut self, id: Identity) -> ProcState {
        match info_of(id.pid) {
            Some(info) if info.start == id.start => info.state,
            _ => ProcState::Gone,
        }
    }

    /// By pid only: there is no handle to hold. The identity is re-read
    /// immediately before the signal; the sweep stops a process before it kills.
    fn signal(&mut self, id: Identity, sig: Sig, _held: bool) -> Result<Handle, SignalError> {
        use rustix::process::{Pid, Signal, kill_process};
        let pid = i32::try_from(id.pid)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or(SignalError::Failed)?;
        if info_of(id.pid).map(|info| info.start) != Some(id.start) {
            return Err(SignalError::Mismatch);
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
