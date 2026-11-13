// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the macOS table's arithmetic, which is platform-free and so runs on
//! every host: buffer sizing, fill judgement, start time and state decoding.

use super::*;

#[test]
fn the_start_time_keeps_microseconds_and_refuses_overflow() {
    assert_eq!(start_micros(1, 5), Some(1_000_005));
    assert_eq!(start_micros(0, 999_999), Some(999_999));
    assert_eq!(start_micros(1, 1_000_000), None, "usec is a fraction");
    assert_eq!(start_micros(u64::MAX, 0), None, "seconds overflow");
    let top = u64::MAX / 1_000_000;
    assert_eq!(
        start_micros(top, 0),
        Some(top * 1_000_000),
        "the product fits"
    );
    assert_eq!(
        start_micros(top, 999_999),
        None,
        "the product fits but adding the microseconds overflows"
    );
    let last = u64::MAX / 1_000_000 - 1;
    assert_eq!(
        start_micros(last, 999_999),
        Some(last * 1_000_000 + 999_999)
    );
}

#[test]
fn two_starts_a_microsecond_apart_are_different_identities() {
    assert_ne!(start_micros(100, 1), start_micros(100, 2));
}

#[test]
fn status_maps_stopped_and_zombie_and_everything_else_runs() {
    assert_eq!(status_of(4), ProcState::Stopped);
    assert_eq!(status_of(5), ProcState::Zombie);
    for other in [0, 1, 2, 3, 6, u32::MAX] {
        assert_eq!(status_of(other), ProcState::Running, "{other}");
    }
}

#[test]
fn slots_leave_headroom_and_refuse_a_bad_estimate() {
    assert_eq!(slots_for(400), Some((400 + 100 + 64, (400 + 100 + 64) * 4)));
    assert_eq!(slots_for(1), Some((1 + 64, (1 + 64) * 4)));
    for bad in [0, -1, i32::MIN] {
        assert_eq!(slots_for(bad), None, "{bad}");
    }
}

#[test]
fn slots_are_capped_and_the_byte_length_fits_an_int() {
    let (slots, bytes) = slots_for(i32::MAX).expect("a huge estimate is capped, not refused");
    assert_eq!(slots, SLOT_CAP);
    assert_eq!(
        usize::try_from(bytes).expect("positive"),
        slots * size_of::<i32>(),
        "the byte length is the buffer's, from one source"
    );
}

#[test]
fn a_fill_is_judged_against_its_buffer_not_the_kernels_claim() {
    assert_eq!(judge_fill(10, 100), Fill::Complete(10));
    assert_eq!(judge_fill(99, 100), Fill::Complete(99));
    assert_eq!(
        judge_fill(100, 100),
        Fill::Again,
        "a full buffer lists again"
    );
    assert_eq!(
        judge_fill(i32::MAX, 100),
        Fill::Again,
        "a count past the buffer is never read"
    );
    assert_eq!(judge_fill(0, 100), Fill::Failed);
    assert_eq!(judge_fill(-1, 100), Fill::Failed);
}

/// A scripted libproc: a pid list (or its failure) and a lookup per pid.
struct Script {
    pids: Option<Vec<u32>>,
    infos: Vec<(u32, Lookup)>,
}

impl Probe for Script {
    fn list(&mut self) -> Option<Vec<u32>> {
        self.pids.clone()
    }
    fn info(&mut self, pid: u32) -> Lookup {
        self.infos
            .iter()
            .find(|(p, _)| *p == pid)
            .map_or(Lookup::Missing(Miss::Gone), |(_, lookup)| lookup.clone())
    }
}

fn found(ppid: u32, start: u64) -> Lookup {
    Lookup::Found(Info {
        ppid,
        start,
        state: ProcState::Running,
    })
}

fn who(pid: u32, start: u64) -> Identity {
    Identity { pid, start }
}

#[test]
fn a_clean_listing_is_complete_and_omits_exits_and_foreign_pids() {
    let mut probe = Script {
        pids: Some(vec![10, 11, 12, 13]),
        infos: vec![
            (10, found(1, 100)),
            (11, found(10, 110)),
            (12, Lookup::Missing(Miss::Gone)),
            (13, Lookup::Missing(Miss::Foreign)),
        ],
    };
    let listing = table_read(&mut probe);
    assert!(
        listing.complete,
        "an exit and a foreign pid are not failures"
    );
    assert_eq!(listing.rows, vec![(who(10, 100), 1), (who(11, 110), 10)]);
}

#[test]
fn a_failed_pid_read_makes_the_listing_incomplete() {
    let mut probe = Script {
        pids: Some(vec![10, 11]),
        infos: vec![(10, found(1, 100)), (11, Lookup::Missing(Miss::Failed))],
    };
    let listing = table_read(&mut probe);
    assert!(!listing.complete, "a failed read says nothing about pid 11");
    assert_eq!(listing.rows, vec![(who(10, 100), 1)]);
}

#[test]
fn a_failed_listing_is_incomplete_and_empty() {
    let mut probe = Script {
        pids: None,
        infos: vec![(10, found(1, 100))],
    };
    let listing = table_read(&mut probe);
    assert!(!listing.complete);
    assert!(listing.rows.is_empty());
}

#[test]
fn a_member_state_is_gone_only_on_a_proven_exit_or_reuse() {
    let mut probe = Script {
        pids: None,
        infos: vec![
            (10, found(1, 100)),
            (11, Lookup::Missing(Miss::Gone)),
            (12, Lookup::Missing(Miss::Failed)),
            (13, Lookup::Missing(Miss::Foreign)),
        ],
    };
    assert_eq!(table_state(&mut probe, who(10, 100)), ProcState::Running);
    assert_eq!(
        table_state(&mut probe, who(10, 99)),
        ProcState::Gone,
        "the pid now has another start time"
    );
    assert_eq!(table_state(&mut probe, who(11, 1)), ProcState::Gone);
    assert_eq!(
        table_state(&mut probe, who(12, 1)),
        ProcState::Unknown,
        "a failed read is not an exit"
    );
    assert_eq!(table_state(&mut probe, who(13, 1)), ProcState::Unknown);
}

#[test]
fn errno_maps_to_gone_foreign_or_failed() {
    assert_eq!(miss_of(Some(ESRCH)), Miss::Gone);
    assert_eq!(miss_of(Some(EPERM)), Miss::Foreign);
    for other in [Some(5), Some(22), Some(0), None] {
        assert_eq!(miss_of(other), Miss::Failed, "{other:?}");
    }
}

#[test]
fn a_record_is_decoded_only_for_the_pid_asked() {
    let found = decode(10, 10, 4, 4, 100, 5);
    assert_eq!(
        found,
        Lookup::Found(Info {
            ppid: 4,
            start: 100_000_005,
            state: ProcState::Stopped,
        })
    );
    assert_eq!(
        decode(10, 11, 4, 2, 100, 5),
        Lookup::Missing(Miss::Failed),
        "a record that names another pid"
    );
    assert_eq!(
        decode(10, 10, 4, 2, 100, 1_000_000),
        Lookup::Missing(Miss::Failed),
        "a start time that is not a fraction of a second"
    );
}

/// The real libproc, on the macOS shard only: this process lists itself with a
/// parent and a start time, and a pid that cannot exist is gone, not a failure.
#[cfg(target_os = "macos")]
#[test]
fn libproc_lists_this_process_and_reads_its_identity() {
    let me = std::process::id();
    let mut table = MacTable::new();
    let listing = table.read();
    assert!(listing.complete, "a listing on a healthy host is complete");
    let mine = listing
        .rows
        .iter()
        .find(|(id, _)| id.pid == me)
        .expect("this process is in the table");
    assert_eq!(Some(mine.0), MacTable::identity_of(me));
    assert_eq!(table.state(mine.0), ProcState::Running);
    assert_eq!(
        table.state(Identity {
            pid: me,
            start: mine.0.start + 1
        }),
        ProcState::Gone,
        "another start time is another process"
    );
    assert_eq!(
        Libproc.info(i32::MAX as u32),
        Lookup::Missing(Miss::Gone),
        "no such process"
    );
}
