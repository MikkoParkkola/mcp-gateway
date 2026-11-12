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

use super::{
    Handle, Identity, Listing, ProcState, ProcessTable, Rescue, Sig, SignalError, by_pid_gate,
    is_stray_stop,
};

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

/// What one `stat` read told: the process, its absence, or a failure that says
/// nothing about whether it exists. Only the first two may be believed.
#[derive(Debug, PartialEq, Eq)]
enum Lookup {
    Found(Stat),
    /// The process does not exist (no such file, or it exited mid-read).
    Gone,
    /// Any other error, or text that does not parse: not "gone".
    Unreadable,
}

/// `ESRCH`: reading a task's `/proc` file as it exits fails with this.
const ESRCH: i32 = 3;

fn lookup_of(read: std::io::Result<String>) -> Lookup {
    match read {
        Ok(text) => parse_stat(&text).map_or(Lookup::Unreadable, Lookup::Found),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Lookup::Gone,
        Err(err) if err.raw_os_error() == Some(ESRCH) => Lookup::Gone,
        Err(_) => Lookup::Unreadable,
    }
}

fn read_stat(pid: u32) -> Lookup {
    lookup_of(std::fs::read_to_string(format!("/proc/{pid}/stat")))
}

/// Whether `id` still names the process it was taken from.
#[derive(Debug, PartialEq, Eq)]
enum Check {
    Same,
    /// Gone, or the pid now belongs to a process with another start time.
    Different,
    Unreadable,
}

fn check(id: Identity) -> Check {
    match read_stat(id.pid) {
        Lookup::Found(stat) if stat.start == id.start => Check::Same,
        Lookup::Found(_) | Lookup::Gone => Check::Different,
        Lookup::Unreadable => Check::Unreadable,
    }
}

fn refusal(check: &Check) -> SignalError {
    match check {
        Check::Unreadable => SignalError::Failed,
        _ => SignalError::Mismatch,
    }
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
        match read_stat(pid) {
            Lookup::Found(stat) => Some(Identity {
                pid,
                start: stat.start,
            }),
            _ => None,
        }
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
                match check(id) {
                    Check::Same => {}
                    other => return Err(refusal(&other)),
                }
                slot.insert(fd)
            }
        };
        Ok(Some(&*fd))
    }
}

impl ProcessTable for LinuxTable {
    fn read(&mut self) -> Listing {
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return Listing {
                rows: Vec::new(),
                complete: false,
                unreadable: Vec::new(),
            };
        };
        let mut listing = Listing {
            rows: Vec::new(),
            complete: true,
            unreadable: Vec::new(),
        };
        for entry in dir {
            let Ok(entry) = entry else {
                listing.complete = false;
                continue;
            };
            // Non-numeric names (`self`, `sys`, ...) are not processes.
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            match read_stat(pid) {
                Lookup::Found(stat) => listing.rows.push((
                    Identity {
                        pid,
                        start: stat.start,
                    },
                    stat.ppid,
                )),
                Lookup::Gone => {}
                Lookup::Unreadable => {
                    listing.complete = false;
                    listing.unreadable.push(pid);
                }
            }
        }
        listing
    }

    fn state(&mut self, id: Identity) -> ProcState {
        match read_stat(id.pid) {
            Lookup::Found(stat) if stat.start == id.start => stat.state,
            Lookup::Found(_) | Lookup::Gone => ProcState::Gone,
            Lookup::Unreadable => ProcState::Unknown,
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
        // By pid, no handle: the identity is re-read AND a Kill is refused unless
        // the process is stopped (or a zombie), so its pid cannot be freed and
        // reused between this read and the signal.
        match read_stat(id.pid) {
            Lookup::Found(stat) if stat.start == id.start => by_pid_gate(sig, stat.state)?,
            Lookup::Found(_) | Lookup::Gone => return Err(SignalError::Mismatch),
            Lookup::Unreadable => return Err(SignalError::Failed),
        }
        kill_process(pid, signal)
            .map(|()| Handle::ByPid)
            .map_err(denied)
    }

    fn now(&mut self) -> Duration {
        self.origin.elapsed()
    }

    fn release(&mut self, id: Identity) {
        self.fds.remove(&id);
    }

    fn rescue(&mut self, member: Identity) -> Rescue {
        match read_stat(member.pid) {
            Lookup::Found(stat)
                if is_stray_stop(
                    member,
                    Identity {
                        pid: member.pid,
                        start: stat.start,
                    },
                    stat.state,
                ) =>
            {
                match pid_of(member).map(|pid| kill_process(pid, Signal::CONT)) {
                    Some(Ok(())) => Rescue::Resumed,
                    _ => Rescue::Failed,
                }
            }
            Lookup::Unreadable => Rescue::Failed,
            Lookup::Found(_) | Lookup::Gone => Rescue::NothingToDo,
        }
    }

    fn idle(&mut self) {
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
#[path = "stdio_sweep_linux_tests.rs"]
mod tests;
