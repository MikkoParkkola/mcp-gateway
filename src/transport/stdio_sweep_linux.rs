// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Linux [`ProcessTable`]: `/proc` for the tree and the process start times,
//! a pidfd for every process the budget allows.
//!
//! The pidfd is opened BEFORE the start time is checked, so the check names the
//! process the descriptor holds: once it matches, the pid can be reused all it
//! likes and a signal through the descriptor still reaches only that process.
//! Without a descriptor the table re-reads the start time and signals by pid;
//! the sweep stops such a process first, so the window between the read and the
//! kill is one in which the target cannot exit and free its pid by itself.
//! Command lines are never read: nothing here can put one in a log.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use rustix::process::{Pid, PidfdFlags, Signal, kill_process, pidfd_open, pidfd_send_signal};

use super::{Handle, Identity, ProcState, ProcessTable, Sig, SignalError};

/// What `/proc/<pid>/stat` says about a process.
#[derive(Debug, PartialEq, Eq)]
struct Stat {
    ppid: u32,
    start: u64,
    state: ProcState,
}

/// Parse a `stat` line. The command name sits in parentheses and may itself hold
/// spaces and parentheses, so the fields are counted from the LAST `)`.
fn parse_stat(text: &str) -> Option<Stat> {
    let rest = text[text.rfind(')')? + 1..].split_ascii_whitespace();
    let fields: Vec<&str> = rest.collect();
    // After the name: state (0), ppid (1), ..., starttime (19).
    let state = match fields.first()?.as_bytes().first()? {
        b'T' | b't' => ProcState::Stopped,
        b'Z' | b'X' | b'x' => ProcState::Zombie,
        _ => ProcState::Running,
    };
    Some(Stat {
        ppid: fields.get(1)?.parse().ok()?,
        start: fields.get(19)?.parse().ok()?,
        state,
    })
}

fn read_stat(pid: u32) -> Option<Stat> {
    parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

fn signal_of(sig: Sig) -> Signal {
    match sig {
        Sig::Stop => Signal::STOP,
        Sig::Cont => Signal::CONT,
        Sig::Kill => Signal::KILL,
    }
}

fn pid_of(id: Identity) -> Option<Pid> {
    Pid::from_raw(i32::try_from(id.pid).ok()?)
}

fn denied(err: rustix::io::Errno) -> SignalError {
    match err {
        rustix::io::Errno::SRCH => SignalError::Mismatch,
        rustix::io::Errno::PERM => SignalError::Denied,
        _ => SignalError::Failed,
    }
}

/// One sweep's table: the descriptors it holds close when the table drops.
pub(in crate::transport::stdio) struct LinuxTable {
    fds: HashMap<Identity, OwnedFd>,
    origin: Instant,
}

impl LinuxTable {
    pub(in crate::transport::stdio) fn new() -> Self {
        Self {
            fds: HashMap::new(),
            origin: Instant::now(),
        }
    }

    /// The pid with the start time that tells it from a later process.
    pub(in crate::transport::stdio) fn identity_of(pid: u32) -> Option<Identity> {
        Some(Identity {
            pid,
            start: read_stat(pid)?.start,
        })
    }

    /// The descriptor for `id`, opened first and checked second; `None` when the
    /// kernel refuses one (no pidfd support, descriptor limit) or the pid is
    /// no longer that process.
    fn held(&mut self, id: Identity) -> Result<Option<&OwnedFd>, SignalError> {
        let fd = match self.fds.entry(id) {
            Entry::Occupied(held) => held.into_mut(),
            Entry::Vacant(slot) => {
                let Some(pid) = pid_of(id) else {
                    return Err(SignalError::Failed);
                };
                let Ok(fd) = pidfd_open(pid, PidfdFlags::empty()) else {
                    return Ok(None);
                };
                if read_stat(id.pid).map(|s| s.start) != Some(id.start) {
                    return Err(SignalError::Mismatch);
                }
                slot.insert(fd)
            }
        };
        Ok(Some(&*fd))
    }
}

impl ProcessTable for LinuxTable {
    fn read(&mut self) -> Vec<(Identity, u32)> {
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        dir.filter_map(|entry| {
            let pid: u32 = entry.ok()?.file_name().to_str()?.parse().ok()?;
            let stat = read_stat(pid)?;
            Some((
                Identity {
                    pid,
                    start: stat.start,
                },
                stat.ppid,
            ))
        })
        .collect()
    }

    fn state(&mut self, id: Identity) -> ProcState {
        match read_stat(id.pid) {
            Some(stat) if stat.start == id.start => stat.state,
            _ => ProcState::Gone,
        }
    }

    fn signal(&mut self, id: Identity, sig: Sig, held: bool) -> Result<Handle, SignalError> {
        let signal = signal_of(sig);
        if held && let Some(fd) = self.held(id)? {
            return pidfd_send_signal(fd, signal)
                .map(|()| Handle::Held)
                .map_err(denied);
        }
        let pid = pid_of(id).ok_or(SignalError::Failed)?;
        if read_stat(id.pid).map(|s| s.start) != Some(id.start) {
            return Err(SignalError::Mismatch);
        }
        kill_process(pid, signal)
            .map(|()| Handle::ByPid)
            .map_err(denied)
    }

    fn now(&mut self) -> Duration {
        self.origin.elapsed()
    }
}

#[cfg(test)]
#[path = "stdio_sweep_linux_tests.rs"]
mod tests;
