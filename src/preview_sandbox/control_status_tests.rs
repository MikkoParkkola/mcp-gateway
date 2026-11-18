// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The helper's setup status (D13): R22, the closed message set, and R32,
//! the order the gateway accepts it in.

use super::{ControlEvent, Ending, Seen, SetupStatus, SetupStep, ending, next};

/// Every step's wire name, written out (never read from the enum).
const WIRE: [&str; 10] = [
    "namespaces",
    "descriptors",
    "mounting",
    "binding",
    "masking",
    "remounting",
    "pivoting",
    "loopback",
    "limits",
    "target-missing",
];

/// R22, kills "the step is open text" and "a flag may be false": every step
/// and both `denied` values round-trip under their own wire name, the done
/// line round-trips, and every malformed shape refuses.
#[test]
fn r22_each_status_round_trips_and_every_other_shape_refuses() {
    assert_eq!(SetupStep::ALL.len(), WIRE.len());
    for (step, name) in SetupStep::ALL.into_iter().zip(WIRE) {
        for denied in [true, false] {
            let status = SetupStatus::Refused { step, denied };
            let line = status.encode();
            assert_eq!(
                line,
                format!("{{\"setup_refused\":true,\"step\":\"{name}\",\"denied\":{denied}}}")
            );
            assert_eq!(SetupStatus::parse(&line), Some(status), "{line}");
        }
    }
    assert_eq!(SetupStatus::Done.encode(), "{\"setup_done\":true}");
    assert_eq!(
        SetupStatus::parse("{\"setup_done\":true}"),
        Some(SetupStatus::Done)
    );
    for line in [
        "{\"setup_refused\":true,\"step\":\"no-such-step\",\"denied\":false}",
        "{\"setup_refused\":true,\"step\":\"binding (EACCES)\",\"denied\":false}",
        "{\"setup_refused\":true,\"step\":null,\"denied\":false}",
        "{\"setup_refused\":true,\"step\":\"binding\"}",
        "{\"setup_refused\":true,\"step\":\"binding\",\"denied\":\"yes\"}",
        "{\"setup_done\":false}",
        "{\"setup_refused\":false,\"step\":\"binding\",\"denied\":false}",
        "{\"setup_done\":true,\"why\":\"x\"}",
        "{\"setup_done\":true,\"setup_refused\":true,\"step\":\"binding\",\"denied\":false}",
        "{}",
    ] {
        assert_eq!(SetupStatus::parse(line), None, "{line}");
    }
}

const DONE: ControlEvent = ControlEvent::Status(SetupStatus::Done);
const REFUSED: ControlEvent = ControlEvent::Status(SetupStatus::Refused {
    step: SetupStep::Binding,
    denied: false,
});
const FETCH_OK: ControlEvent = ControlEvent::FetchDone { refused: false };
const FETCH_REFUSED: ControlEvent = ControlEvent::FetchDone { refused: true };
const ENDED_DONE: Seen = Seen::Ended(Ending::Status(SetupStatus::Done));
const ENDED_REFUSED: Seen = Seen::Ended(Ending::Status(SetupStatus::Refused {
    step: SetupStep::Binding,
    denied: false,
}));
const ENDED_FETCH: Seen = Seen::Ended(Ending::FetchRefused);

/// R32, kills "the order is not enforced" and "the mode is ignored": the full
/// transition table, each cell a literal, for a plan with a fetch phase.
#[test]
fn r32_fetching_sessions_follow_the_table() {
    use ControlEvent::FetchStart;
    let events = [FetchStart, FETCH_OK, FETCH_REFUSED, DONE, REFUSED];
    let table: [(Seen, [Option<Seen>; 5]); 5] = [
        (
            Seen::Start,
            [Some(Seen::Fetching), None, None, None, Some(ENDED_REFUSED)],
        ),
        (
            Seen::Fetching,
            [None, Some(Seen::Fetched), Some(ENDED_FETCH), None, None],
        ),
        (
            Seen::Fetched,
            [None, None, None, Some(ENDED_DONE), Some(ENDED_REFUSED)],
        ),
        (ENDED_DONE, [None, None, None, None, None]),
        (ENDED_FETCH, [None, None, None, None, None]),
    ];
    for (at, row) in table {
        for (event, want) in events.into_iter().zip(row) {
            assert_eq!(next(true, at, event), want, "{at:?} on {event:?}");
        }
    }
}

/// R32 for a plan with no fetch phase: a fetch message is out of order
/// anywhere, and the done status is the only ending besides a refusal.
#[test]
fn r32_non_fetching_sessions_follow_the_table() {
    use ControlEvent::FetchStart;
    let events = [FetchStart, FETCH_OK, FETCH_REFUSED, DONE, REFUSED];
    let table: [(Seen, [Option<Seen>; 5]); 2] = [
        (
            Seen::Start,
            [None, None, None, Some(ENDED_DONE), Some(ENDED_REFUSED)],
        ),
        (ENDED_DONE, [None, None, None, None, None]),
    ];
    for (at, row) in table {
        for (event, want) in events.into_iter().zip(row) {
            assert_eq!(next(false, at, event), want, "{at:?} on {event:?}");
        }
    }
}

/// R32's spot checks over whole sessions, the close included: a session that
/// closes before an ending has none.
#[test]
fn r32_whole_sessions_end_as_listed() {
    use ControlEvent::FetchStart;
    let refused = Ending::Status(SetupStatus::Refused {
        step: SetupStep::Binding,
        denied: false,
    });
    let done = Ending::Status(SetupStatus::Done);
    // Without a fetch phase.
    assert_eq!(ending(false, &[DONE]), Some(done));
    assert_eq!(ending(false, &[REFUSED]), Some(refused));
    assert_eq!(ending(false, &[]), None);
    assert_eq!(ending(false, &[DONE, DONE]), None);
    assert_eq!(ending(false, &[REFUSED, DONE]), None);
    assert_eq!(ending(false, &[FetchStart]), None);
    // With one.
    assert_eq!(ending(true, &[FetchStart, FETCH_OK, DONE]), Some(done));
    assert_eq!(ending(true, &[FetchStart, FETCH_OK, REFUSED]), Some(refused));
    assert_eq!(
        ending(true, &[FetchStart, FETCH_REFUSED]),
        Some(Ending::FetchRefused)
    );
    assert_eq!(ending(true, &[REFUSED]), Some(refused));
    assert_eq!(ending(true, &[]), None);
    assert_eq!(ending(true, &[FetchStart]), None);
    assert_eq!(ending(true, &[FetchStart, DONE]), None);
    assert_eq!(ending(true, &[FetchStart, FETCH_REFUSED, DONE]), None);
    assert_eq!(ending(true, &[FetchStart, FETCH_REFUSED, REFUSED]), None);
    assert_eq!(ending(true, &[FetchStart, FETCH_OK]), None);
    assert_eq!(ending(true, &[DONE]), None);
    assert_eq!(ending(true, &[REFUSED, FetchStart]), None);
    assert_eq!(ending(true, &[FetchStart, REFUSED]), None);
    assert_eq!(ending(true, &[FetchStart, REFUSED, FETCH_OK]), None);
}
