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
    assert_eq!(slots_for(400), Some(400 + 100 + 64));
    assert_eq!(slots_for(1), Some(1 + 64));
    for bad in [0, -1, i32::MIN] {
        assert_eq!(slots_for(bad), None, "{bad}");
    }
}

#[test]
fn slots_are_capped_and_the_byte_length_fits_an_int() {
    let slots = slots_for(i32::MAX).expect("a huge estimate is capped, not refused");
    assert_eq!(slots, SLOT_CAP);
    let bytes = slots * size_of::<i32>();
    assert!(i32::try_from(bytes).is_ok(), "{bytes} bytes fit a c_int");
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
