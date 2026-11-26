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

#[path = "stdio_sweep_linux_pinned.rs"]
mod pinned;
use pinned::Pinned;

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

/// Whether a failed `/proc` read means the process is gone (the file vanished
/// with it, or it exited while its directory was open).
fn is_gone(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::NotFound || err.raw_os_error() == Some(ESRCH)
}

fn lookup_of(read: std::io::Result<String>) -> Lookup {
    match read {
        Ok(text) => parse_stat(&text).map_or(Lookup::Unreadable, Lookup::Found),
        Err(err) if is_gone(&err) => Lookup::Gone,
        Err(_) => Lookup::Unreadable,
    }
}

fn stat_file(path: &std::path::Path) -> Lookup {
    lookup_of(std::fs::read_to_string(path))
}

fn read_stat(pid: u32) -> Lookup {
    stat_file(std::path::Path::new(&format!("/proc/{pid}/stat")))
}

/// Whether `proc_root` has the per-task `children` files: the probe reads this
/// process's own main-thread entry, which exists exactly when the kernel was
/// built with them (`CONFIG_PROC_CHILDREN`).
fn has_children_files(proc_root: &std::path::Path) -> bool {
    let tid = rustix::thread::gettid().as_raw_nonzero().get();
    proc_root.join(format!("self/task/{tid}/children")).exists()
}

/// One children file: the pids it lists, `Ok(None)` when the task is gone
/// (the file vanished with it), `Err` for any other failure.
fn children_in(text: std::io::Result<String>) -> Result<Option<Vec<u32>>, ()> {
    match text {
        Ok(text) => Ok(Some(
            text.split_ascii_whitespace()
                .filter_map(|pid| pid.parse().ok())
                .collect(),
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) if err.raw_os_error() == Some(ESRCH) => Ok(None),
        Err(_) => Err(()),
    }
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

fn error_for(check: &Check) -> SignalError {
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
    /// Where the process table is read from: `/proc`, or a test's fake tree.
    proc_root: std::path::PathBuf,
    /// Whether this kernel has the per-task `children` files (probed once, at
    /// creation): without them every reading is the full scan, for life.
    walkable: bool,
    /// Processes a reading of this table found fully exited (design delta
    /// D5'''' (i')). A table serves one sweep, so the set lives for one
    /// freeze and is dropped with it.
    exited: std::collections::HashSet<Identity>,
    /// Test only: stat and children-file reads so far, and the read count at
    /// which this table's clock jumps past every `until`.
    #[cfg(test)]
    pub(super) reads: usize,
    #[cfg(test)]
    pub(super) expire_after_reads: Option<usize>,
    /// Test only: read by the full scan even where children files exist.
    #[cfg(test)]
    pub(super) force_full_scan: bool,
    /// Test only: after read number `.0`, write text `.2` to file `.1`, once;
    /// `rewrite_fired` records that it happened, so a row can assert it.
    #[cfg(test)]
    pub(super) rewrite_after_read: Option<(usize, std::path::PathBuf, String)>,
    #[cfg(test)]
    pub(super) rewrite_fired: bool,
    /// Test only: after read number `.0`, rename each (from, to) pair in order,
    /// once: a fake pid reuse (the walked directory moves away and a stranger
    /// takes its path). `moved` records that every rename succeeded.
    #[cfg(test)]
    pub(super) move_after_read: Option<(usize, Vec<(std::path::PathBuf, std::path::PathBuf)>)>,
    #[cfg(test)]
    pub(super) moved: bool,
}

impl LinuxTable {
    pub(in crate::transport::stdio) fn new() -> Self {
        Self::at(std::path::PathBuf::from("/proc"))
    }

    fn at(proc_root: std::path::PathBuf) -> Self {
        let walkable = has_children_files(&proc_root);
        Self {
            fds: HashMap::new(),
            origin: Instant::now(),
            proc_root,
            walkable,
            exited: std::collections::HashSet::new(),
            #[cfg(test)]
            reads: 0,
            #[cfg(test)]
            expire_after_reads: None,
            #[cfg(test)]
            force_full_scan: false,
            #[cfg(test)]
            rewrite_after_read: None,
            #[cfg(test)]
            rewrite_fired: false,
            #[cfg(test)]
            move_after_read: None,
            #[cfg(test)]
            moved: false,
        }
    }

    /// Test only: a table over a fake process tree at `root`.
    #[cfg(test)]
    pub(super) fn with_root(root: &std::path::Path) -> Self {
        Self::at(root.to_path_buf())
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
                    other => return Err(error_for(&other)),
                }
                slot.insert(fd)
            }
        };
        Ok(Some(&*fd))
    }

    /// One `stat` read under this table's proc root.
    fn stat_at(&mut self, pid: u32) -> Lookup {
        let read = stat_file(&self.proc_root.join(format!("{pid}/stat")));
        #[cfg(test)]
        self.tick();
        read
    }

    /// One task's own `stat`, read through the walked process's pinned directory.
    fn task_stat_at(&mut self, dir: &Pinned, tid: &std::ffi::OsStr) -> Lookup {
        let read = lookup_of(dir.read(&std::path::Path::new("task").join(tid).join("stat")));
        #[cfg(test)]
        self.tick();
        read
    }

    /// Count one stat or children-file read (or one entry of rule (iii)'s task
    /// directory re-read), after its bytes were read. Test
    /// only: the count drives `expire_after_reads`, and `rewrite_after_read`
    /// writes its one file right after its one read returned, so a row can
    /// change a file between two reads. Called only from test builds.
    #[cfg(test)]
    fn tick(&mut self) {
        self.reads += 1;
        if let Some((at, path, text)) = &self.rewrite_after_read
            && self.reads == *at
        {
            // A new task directory needs its parent made first.
            let made = path
                .parent()
                .is_none_or(|dir| std::fs::create_dir_all(dir).is_ok());
            self.rewrite_fired = made && std::fs::write(path, text).is_ok();
        }
        if let Some((at, pairs)) = &self.move_after_read
            && self.reads == *at
        {
            self.moved = pairs
                .iter()
                .all(|(from, to)| std::fs::rename(from, to).is_ok());
        }
    }

    /// One task's own state (design delta D5'), read before and again after
    /// its children file: `None` when the task is gone. An unreadable stat
    /// leaves the reading incomplete and counts as `Unknown`, which settles
    /// nothing.
    fn task_state(
        &mut self,
        dir: &Pinned,
        tid: &std::ffi::OsStr,
        listing: &mut Listing,
    ) -> Option<ProcState> {
        match self.task_stat_at(dir, tid) {
            Lookup::Found(stat) => Some(stat.state),
            Lookup::Gone => None,
            Lookup::Unreadable => {
                listing.complete = false;
                Some(ProcState::Unknown)
            }
        }
    }

    /// One task's `children` file, read through the pinned directory.
    fn children_at(&mut self, dir: &Pinned, tid: &std::ffi::OsStr) -> Result<Option<Vec<u32>>, ()> {
        let read = children_in(dir.read(&std::path::Path::new("task").join(tid).join("children")));
        #[cfg(test)]
        self.tick();
        read
    }

    fn expired(&mut self, until: Duration) -> bool {
        ProcessTable::now(self) >= until
    }

    /// The walk: each walked seed stat'ed directly, then every task's children
    /// file of every live one, down the tree; each stat-only seed stat'ed for its
    /// own death. `until` is checked before every read: a reading cut short is
    /// neither complete nor settled, and keeps what it found.
    fn walk(&mut self, walk: &[Identity], stat_only: &[Identity], until: Duration) -> Listing {
        let mut listing = Listing {
            rows: Vec::new(),
            complete: true,
            unreadable: Vec::new(),
            gone: Vec::new(),
            settled: true,
        };
        let mut queue: Vec<Identity> = Vec::new();
        let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for seed in walk {
            if self.expired(until) {
                return cut(listing);
            }
            if let Some(parent) = self.seed(*seed, &mut listing) {
                listing.rows.push((*seed, parent));
                if seen.insert(seed.pid) {
                    queue.push(*seed);
                }
            }
        }
        while let Some(who) = queue.pop() {
            if !self.walk_one(who, until, &mut listing, &mut queue, &mut seen) {
                return cut(listing);
            }
        }
        for seed in stat_only {
            if self.expired(until) {
                return cut(listing);
            }
            let _ = self.seed(*seed, &mut listing);
        }
        listing
    }

    /// Stat a seed: its parent when it is still that process; else it is
    /// named gone (or unreadable, which proves nothing).
    fn seed(&mut self, seed: Identity, listing: &mut Listing) -> Option<u32> {
        match self.stat_at(seed.pid) {
            Lookup::Found(stat) if stat.start == seed.start => Some(stat.ppid),
            Lookup::Found(_) | Lookup::Gone => {
                listing.gone.push(seed);
                None
            }
            Lookup::Unreadable => {
                listing.complete = false;
                listing.unreadable.push(seed.pid);
                None
            }
        }
    }

    /// Read every task's children of `pid` and stat each new child. `false`
    /// when `until` passed (the caller cuts the reading short). The kernel's
    /// children file is complete only while the task cannot fork or reap AND
    /// its listed children are stopped, so the reading settles only under
    /// design delta D5''': (i) each task's own state, read before and after its
    /// file, is Stopped both times (the leader's state alone does not cover its
    /// threads: an exited leader is a zombie while they run); (ii) every listed
    /// child is still this pid's child and Stopped at its listing stat; (iii)
    /// the task set did not grow during the walk. A Zombie settles nothing (it
    /// cannot tell a dead process from a zombie leader whose threads still run,
    /// and a child that died may have handed its children to a parent already
    /// read), with one exception, design delta D5'''' (i'): a walked process
    /// that is EXITED (task dir = its leader only, at both directory reads;
    /// leader Zombie before and after an empty children file) settles when this
    /// table already found the same identity EXITED in an earlier reading. Every
    /// thread's exit handed its children on before it left the task dir, so
    /// the earlier reading saw a finished exit and this one sees the children
    /// wherever they went. The first reading to find it stays unsettled.
    fn walk_one(
        &mut self,
        who: Identity,
        until: Duration,
        listing: &mut Listing,
        queue: &mut Vec<Identity>,
        seen: &mut std::collections::HashSet<u32>,
    ) -> bool {
        let pid = who.pid;
        if self.expired(until) {
            return false;
        }
        // Option A: pin the process. Its directory is opened once, checked to
        // still be `who` through the open directory, and every other read of
        // this walk goes through it, so a later process at this pid is never
        // read. The identity read is not counted by the test seam.
        let dir = match Pinned::open(&self.proc_root.join(pid.to_string())) {
            Ok(dir) => dir,
            // Gone since it was listed: its state was never judged here, and
            // it may have handed its children to a parent already read.
            Err(err) if is_gone(&err) => {
                listing.settled = false;
                return true;
            }
            Err(_) => {
                listing.complete = false;
                return true;
            }
        };
        match lookup_of(dir.read(std::path::Path::new("stat"))) {
            Lookup::Found(stat) if stat.start == who.start => {}
            // Exited, or the pid already belongs to another process: `who` is
            // not walked, and the change leaves the reading unsettled.
            Lookup::Found(_) | Lookup::Gone => {
                listing.settled = false;
                return true;
            }
            Lookup::Unreadable => {
                listing.complete = false;
                listing.settled = false;
                return true;
            }
        }
        let tasks = match dir.list(std::path::Path::new("task")) {
            Ok(tasks) => tasks,
            Err(err) if is_gone(&err) => {
                listing.settled = false;
                return true;
            }
            Err(_) => {
                listing.complete = false;
                return true;
            }
        };
        let mut tids: Vec<std::ffi::OsString> = Vec::new();
        // (i) failed on some task; and whether the process is still EXITED.
        let mut unstopped = false;
        let mut exited = true;
        for tid in tasks {
            tids.push(tid.clone());
            if self.expired(until) {
                return false;
            }
            // (i) A task gone before its read is skipped (its file went with
            // it) but still unsettles: its children went to a sibling task.
            let Some(before) = self.task_state(&dir, &tid, listing) else {
                listing.settled = false;
                exited = false;
                continue;
            };
            if self.expired(until) {
                return false;
            }
            let children = match self.children_at(&dir, &tid) {
                Ok(Some(children)) => children,
                Ok(None) => {
                    listing.settled = false;
                    exited = false;
                    continue;
                }
                Err(()) => {
                    listing.complete = false;
                    listing.settled = false;
                    exited = false;
                    continue;
                }
            };
            exited &= children.is_empty();
            for child in children {
                if self.expired(until) {
                    return false;
                }
                self.judge_child(pid, child, listing, queue, seen);
            }
            if self.expired(until) {
                return false;
            }
            // (i) Stopped at both reads: a task that cannot fork or reap.
            let after = self.task_state(&dir, &tid, listing);
            exited &= before == ProcState::Zombie && after == Some(ProcState::Zombie);
            if before != ProcState::Stopped || after != Some(ProcState::Stopped) {
                unstopped = true;
            }
        }
        if self.expired(until) {
            return false;
        }
        // (iii) A thread created after the first directory read was never
        // walked: a tid only the second read lists unsettles the reading.
        match self.task_set_held(&dir, &tids, until, listing) {
            None => return false,
            Some(true) => {}
            Some(false) => {
                listing.settled = false;
                exited = false;
            }
        }
        // (i') The leader alone, at both directory reads.
        exited &= tids.len() == 1 && tids[0].to_str() == Some(pid.to_string().as_str());
        if unstopped && !(exited && self.exited.contains(&who)) {
            listing.settled = false;
        }
        if exited {
            self.exited.insert(who);
        }
        true
    }

    /// One child listed in `pid`'s children file, judged under (ii) and, if it
    /// is still `pid`'s child, added to the reading once.
    fn judge_child(
        &mut self,
        pid: u32,
        child: u32,
        listing: &mut Listing,
        queue: &mut Vec<Identity>,
        seen: &mut std::collections::HashSet<u32>,
    ) {
        // (ii) Every listed child, stat'ed after the whole file was
        // read: a removal mid-read (the kernel then skips a sibling)
        // shows as gone, a reused pid or a reparent as another parent.
        // It must also be Stopped HERE, not only at its own later walk:
        // the parent's children file is reliable only while the
        // children are stopped during that read. Judged for a child
        // already seen too (a member walked as a seed, D5'''' (ii'')):
        // its own walk must not stand in for this check.
        let already = seen.contains(&child);
        match self.stat_at(child) {
            Lookup::Found(stat) if stat.ppid == pid => {
                if stat.state != ProcState::Stopped {
                    listing.settled = false;
                }
                // Added only once: a child turned away under another
                // parent is still taken here, under its real one.
                if !already {
                    let id = Identity {
                        pid: child,
                        start: stat.start,
                    };
                    seen.insert(child);
                    listing.rows.push((id, stat.ppid));
                    queue.push(id);
                }
            }
            Lookup::Found(_) | Lookup::Gone => listing.settled = false,
            Lookup::Unreadable => {
                listing.complete = false;
                listing.settled = false;
                if !already {
                    listing.unreadable.push(child);
                }
            }
        }
    }

    /// Rule (iii)'s second read of `pid`'s task directory: `Some(true)` only
    /// when it reads and names no tid the first read missed. An entry that
    /// fails to read also leaves the reading incomplete. `None` when `until`
    /// passed during it (checked per entry: a thread-heavy process must not
    /// run the read past the slice); the caller cuts the reading short.
    fn task_set_held(
        &mut self,
        dir: &Pinned,
        tids: &[std::ffi::OsString],
        until: Duration,
        listing: &mut Listing,
    ) -> Option<bool> {
        let known: std::collections::HashSet<&std::ffi::OsStr> =
            tids.iter().map(std::ffi::OsString::as_os_str).collect();
        let again = match dir.list(std::path::Path::new("task")) {
            Ok(again) => again,
            Err(err) => {
                if !is_gone(&err) {
                    listing.complete = false;
                }
                return Some(false);
            }
        };
        let mut held = true;
        for tid in again {
            #[cfg(test)]
            self.tick();
            if self.expired(until) {
                return None;
            }
            held &= known.contains(tid.as_os_str());
        }
        Some(held)
    }

    /// The full scan: every process under the proc root, one `stat` each.
    fn scan(&mut self) -> Listing {
        let Ok(dir) = std::fs::read_dir(&self.proc_root) else {
            return Listing {
                rows: Vec::new(),
                complete: false,
                unreadable: Vec::new(),
                gone: Vec::new(),
                settled: true,
            };
        };
        let mut listing = Listing {
            rows: Vec::new(),
            complete: true,
            unreadable: Vec::new(),
            gone: Vec::new(),
            settled: true,
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
            match self.stat_at(pid) {
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
}

/// A reading cut short by its `until`: neither complete nor settled.
fn cut(mut listing: Listing) -> Listing {
    listing.complete = false;
    listing.settled = false;
    listing
}

impl ProcessTable for LinuxTable {
    fn read(&mut self, walk: &[Identity], stat_only: &[Identity], until: Duration) -> Listing {
        #[cfg(test)]
        let forced = self.force_full_scan;
        #[cfg(not(test))]
        let forced = false;
        if self.walkable && !forced {
            return self.walk(walk, stat_only, until);
        }
        // The fallback reads to the end of the root: until does not cut it.
        let mut listing = self.scan();
        let seeds: Vec<Identity> = walk.iter().chain(stat_only).copied().collect();
        listing.gone = super::full_scan_gone(&seeds, &listing);
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
        #[cfg(test)]
        if self
            .expire_after_reads
            .is_some_and(|after| self.reads >= after)
        {
            return Duration::MAX;
        }
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

    fn idle(&mut self, pause: Duration) {
        std::thread::sleep(pause);
    }
}

#[cfg(tp5)]
#[cfg(test)]
#[path = "stdio_sweep_linux_tests.rs"]
mod tests;
#[cfg(tp5)]
#[cfg(test)]
#[path = "stdio_sweep_linux_walk_tests.rs"]
mod walk_tests;
