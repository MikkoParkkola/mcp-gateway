// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the Linux table: the stat parser on awkward names, and the table
//! against real child processes (a held descriptor and a bare pid).

use std::process::{Child, Command, Stdio};

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
        start: read_stat(pid).expect("a live child has a stat").start,
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
    let rows = LinuxTable::new().read();
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
