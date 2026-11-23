// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The helper's setup status (D13): R22, the closed message set. The order
//! the gateway accepts it in is pinned on the session itself (R32w).

use super::{SetupStatus, SetupStep};

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
