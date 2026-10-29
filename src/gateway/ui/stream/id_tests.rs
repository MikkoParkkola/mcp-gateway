// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The composite id: round trip, order and refusals.

use super::id::{IdError, LogCursor, LogPart, StreamId};

fn part(n: u64) -> LogPart {
    LogPart {
        counter: n,
        hash16: "0123456789abcdef".to_owned(),
    }
}

fn full() -> StreamId {
    StreamId {
        boot: Some(0xdead_beef_0000_0001),
        status: Some(7),
        reload: Some(2),
        queue: Some(1),
        cursor: LogCursor {
            inv: Some(part(41)),
            gov: Some(part(3)),
        },
    }
}

#[test]
fn a_full_id_prints_in_the_fixed_order() {
    assert_eq!(
        full().render(),
        "bdeadbeef00000001.s7.r2.q1.i41-0123456789abcdef.g3-0123456789abcdef"
    );
}

#[test]
fn every_subset_of_parts_round_trips() {
    for mask in 0..64u32 {
        let id = StreamId {
            boot: (mask & 1 != 0).then_some(9),
            status: (mask & 2 != 0).then_some(4),
            reload: (mask & 4 != 0).then_some(5),
            queue: (mask & 8 != 0).then_some(6),
            cursor: LogCursor {
                inv: (mask & 16 != 0).then(|| part(8)),
                gov: (mask & 32 != 0).then(|| part(9)),
            },
        };
        assert_eq!(StreamId::parse(&id.render()), Ok(id.clone()), "mask {mask}");
    }
}

#[test]
fn an_empty_id_is_the_empty_string_and_parses_back() {
    assert_eq!(StreamId::default().render(), "");
    assert_eq!(StreamId::parse(""), Ok(StreamId::default()));
}

#[test]
fn malformed_ids_are_refused() {
    for bad in [
        "x1",
        "s",
        "sx",
        "s1.s2",
        "r1.s1",
        "i5",
        "i5-zz",
        "i5-0123456789abcdef.i6-0123456789abcdef",
        "s1..r2",
        "g1-0123456789abcde",
        "s99999999999999999999999",
    ] {
        assert_eq!(StreamId::parse(bad), Err(IdError), "{bad}");
    }
}
