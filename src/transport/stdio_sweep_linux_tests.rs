// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the Linux table: the stat parser on awkward names, and the table
//! against real child processes (a held descriptor and a bare pid).

use std::process::{Child, Command, Stdio};
use std::time::Instant;

use super::super::{PidfdBudget, Sweep, SweepConfig};
use super::*;

fn sleeper() -> Child {
    Command::new("sleep")
        .arg("60")
        .stdin(Stdio::null())
        .spawn()
        .expect("sleep starts")
}

fn identity(child: &Child) -> Identity {
    let pid = child.id();
    Identity {
        pid,
        start: LinuxTable::identity_of(pid)
            .expect("a live child has a stat")
            .start,
    }
}

/// Wait until the table reports `want` (the signal lands asynchronously).
fn settle(table: &mut LinuxTable, id: Identity, want: ProcState) -> bool {
    (0..200).any(|_| {
        std::thread::sleep(Duration::from_millis(10));
        table.state(id) == want
    })
}

/// A stat line with `name` as the command and 19 filler fields between ppid and
/// the start time, which reads 777.
fn line(name: &str, state: char) -> String {
    let filler = vec!["0"; 17].join(" ");
    format!("42 ({name}) {state} 7 {filler} 777 0 0")
}

#[test]
fn the_stat_parser_counts_fields_from_the_last_paren() {
    for name in ["sleep", "a b", "x) S 1 2 3", "(((", "ünï"] {
        let stat = parse_stat(&line(name, 'S')).expect(name);
        assert_eq!((stat.ppid, stat.start), (7, 777), "{name}");
    }
}

#[test]
fn the_stat_parser_maps_states_and_refuses_short_lines() {
    for (code, want) in [
        ('R', ProcState::Running),
        ('S', ProcState::Running),
        ('D', ProcState::Running),
        ('T', ProcState::Stopped),
        ('t', ProcState::Stopped),
        ('Z', ProcState::Zombie),
    ] {
        assert_eq!(parse_stat(&line("p", code)).expect("parses").state, want);
    }
    assert_eq!(parse_stat("42 (p) S 7 0 0"), None);
    assert_eq!(parse_stat("no parens at all"), None);
}

#[test]
fn the_table_lists_a_child_under_this_process() {
    let mut child = sleeper();
    let id = identity(&child);
    let me = std::process::id();
    let rows = LinuxTable::new().read().rows;
    assert!(rows.contains(&(id, me)), "child {id:?} under {me}");
    child.kill().expect("kill");
    child.wait().expect("reap");
}

#[test]
fn a_held_signal_stops_then_kills_the_child() {
    let mut child = sleeper();
    let id = identity(&child);
    let mut table = LinuxTable::new();
    assert_eq!(table.signal(id, Sig::Stop, true), Ok(Handle::Held));
    assert!(settle(&mut table, id, ProcState::Stopped), "stopped");
    assert_eq!(table.signal(id, Sig::Kill, true), Ok(Handle::Held));
    assert!(settle(&mut table, id, ProcState::Zombie), "killed");
    child.wait().expect("reap");
    assert_eq!(table.state(id), ProcState::Gone);
}

#[test]
fn a_bare_pid_signal_reaches_the_child_and_says_so() {
    let mut child = sleeper();
    let id = identity(&child);
    let mut table = LinuxTable::new();
    assert_eq!(table.signal(id, Sig::Stop, false), Ok(Handle::ByPid));
    assert!(settle(&mut table, id, ProcState::Stopped), "stopped");
    assert_eq!(table.signal(id, Sig::Kill, false), Ok(Handle::ByPid));
    child.wait().expect("reap");
}

#[test]
fn a_wrong_start_time_is_never_signalled_either_way() {
    let mut child = sleeper();
    let real = identity(&child);
    let stale = Identity {
        start: real.start + 1,
        ..real
    };
    let mut table = LinuxTable::new();
    for held in [true, false] {
        assert_eq!(
            table.signal(stale, Sig::Kill, held),
            Err(SignalError::Mismatch),
            "held={held}"
        );
    }
    assert_eq!(table.state(stale), ProcState::Gone);
    assert_eq!(
        table.state(real),
        ProcState::Running,
        "the child is untouched"
    );
    child.kill().expect("kill");
    child.wait().expect("reap");
}

#[test]
fn a_reaped_child_is_gone_and_a_signal_to_it_is_a_mismatch() {
    let mut child = sleeper();
    let id = identity(&child);
    child.kill().expect("kill");
    child.wait().expect("reap");
    let mut table = LinuxTable::new();
    assert_eq!(table.state(id), ProcState::Gone);
    for held in [true, false] {
        assert!(table.signal(id, Sig::Kill, held).is_err(), "held={held}");
    }
}

/// Delegates to the Linux table and records when the terminal kills begin and
/// when the last signal went out.
struct Timed {
    inner: LinuxTable,
    start: Instant,
    first_kill: Option<Duration>,
    last_signal: Duration,
}

impl ProcessTable for Timed {
    fn read(&mut self) -> Listing {
        self.inner.read()
    }
    fn state(&mut self, id: Identity) -> ProcState {
        self.inner.state(id)
    }
    fn signal(&mut self, id: Identity, sig: Sig, held: bool) -> Result<Handle, SignalError> {
        if sig == Sig::Kill && self.first_kill.is_none() {
            self.first_kill = Some(self.start.elapsed());
        }
        let result = self.inner.signal(id, sig, held);
        self.last_signal = self.start.elapsed();
        result
    }
    fn now(&mut self) -> Duration {
        self.inner.now()
    }
}

/// Measurement, not a gate: a root shell with 1000, then 4000,
/// sleeping children, swept with real pidfds. Prints how long the freeze phase
/// and the terminal kill phase take, for the design record. Run by hand:
/// `cargo test --lib measure_the_kill_phase -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, run by hand with --nocapture"]
fn measure_the_kill_phase_at_the_cap() {
    use rustix::process::{Resource, getrlimit, setrlimit};
    // The pidfds of the largest run need descriptors: raise the soft limit.
    let limit = getrlimit(Resource::Nofile);
    setrlimit(
        Resource::Nofile,
        rustix::process::Rlimit {
            current: limit.maximum,
            maximum: limit.maximum,
        },
    )
    .expect("raise the descriptor limit");
    for n in [1000_usize, 4000] {
        measure_one(n);
    }
}

fn measure_one(n: usize) {
    let script = format!("i=0; while [ $i -lt {n} ]; do sleep 120 & i=$((i+1)); done; wait");
    let mut root = Command::new("sh")
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("root starts");
    let root_id = identity(&root);
    let mut table = Timed {
        inner: LinuxTable::new(),
        start: Instant::now(),
        first_kill: None,
        last_signal: Duration::ZERO,
    };
    let kids = |table: &mut Timed| {
        table
            .read()
            .rows
            .iter()
            .filter(|(_, ppid)| *ppid == root_id.pid)
            .count()
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    while kids(&mut table) < n {
        assert!(
            Instant::now() < deadline,
            "the root never reached {n} children"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let cfg = SweepConfig {
        freeze_slice: Duration::from_secs(10),
        cap: n + 16,
    };
    let budget = PidfdBudget::new(n + 16);
    let mut sweep = Sweep::new(root_id, cfg);
    sweep.snapshot(&mut table);
    table.start = Instant::now();
    let report = sweep.run(&mut table, &budget);
    let total = table.start.elapsed();
    let first_kill = table.first_kill.expect("kills were sent");
    eprintln!(
        "MEASURE n={n} killed={} residual={} passes={} total={total:?} freeze_phase={first_kill:?} kill_phase={:?}",
        report.killed.len(),
        report.residual.len(),
        report.passes,
        table.last_signal.saturating_sub(first_kill),
    );
    assert!(
        report.killed.len() > n,
        "every child and the root are killed"
    );
    root.wait().expect("reap");
}

#[test]
fn a_read_error_is_unreadable_never_gone() {
    use std::io::{Error, ErrorKind};
    let stat = line("p", 'S');
    assert!(matches!(lookup_of(Ok(stat)), Lookup::Found(_)));
    assert_eq!(
        lookup_of(Err(Error::from(ErrorKind::NotFound))),
        Lookup::Gone,
        "no such file is an exit"
    );
    assert_eq!(
        lookup_of(Err(Error::from_raw_os_error(ESRCH))),
        Lookup::Gone,
        "a task that exits mid-read"
    );
    for err in [
        Error::from(ErrorKind::PermissionDenied),
        Error::from_raw_os_error(5), // EIO
        Error::from(ErrorKind::Interrupted),
    ] {
        assert_eq!(lookup_of(Err(err)), Lookup::Unreadable);
    }
    assert_eq!(lookup_of(Ok("garbage".to_owned())), Lookup::Unreadable);
}

#[test]
fn an_unreadable_identity_is_refused_as_a_failure_not_a_mismatch() {
    assert_eq!(refusal(&Check::Unreadable), SignalError::Failed);
    assert_eq!(refusal(&Check::Different), SignalError::Mismatch);
}

/// Over a bare pid the table refuses a Kill to a running child and allows it
/// once the child is stopped. Red if the gate is missing from the by-pid path.
#[test]
fn a_bare_pid_kill_of_a_running_child_is_refused_until_it_is_stopped() {
    let mut child = sleeper();
    let id = identity(&child);
    let mut table = LinuxTable::new();
    assert_eq!(
        table.signal(id, Sig::Kill, false),
        Err(SignalError::NotStopped)
    );
    assert_eq!(
        table.state(id),
        ProcState::Running,
        "the child is untouched"
    );
    assert_eq!(table.signal(id, Sig::Stop, false), Ok(Handle::ByPid));
    assert!(settle(&mut table, id, ProcState::Stopped), "stopped");
    assert_eq!(table.signal(id, Sig::Kill, false), Ok(Handle::ByPid));
    child.wait().expect("reap");
}

/// Through a held pidfd the process cannot be swapped, so no gate applies.
#[test]
fn a_held_kill_needs_no_stop_first() {
    let mut child = sleeper();
    let id = identity(&child);
    let mut table = LinuxTable::new();
    assert_eq!(table.signal(id, Sig::Kill, true), Ok(Handle::Held));
    child.wait().expect("reap");
}
