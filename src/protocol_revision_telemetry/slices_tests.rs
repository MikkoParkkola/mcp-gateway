// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every bounded label, on every transport, reaches its slice: an index
//! lookup that missed one would drop counts without a word.

use super::*;

const TRANSPORTS: [Transport; 3] = [Transport::Http, Transport::Stdio, Transport::Internal];

#[test]
fn every_revision_and_client_label_is_counted_on_every_transport() {
    let revisions = MEASURED_REVISIONS
        .iter()
        .copied()
        .chain(std::iter::once(OTHER_REVISION));
    for transport in TRANSPORTS {
        let mut slices = TransportSlices::default();
        for revision in revisions.clone() {
            for client in MEASURED_CLIENTS {
                slices.count(transport, Some(revision), client, || "absent");
            }
        }
        let snapshot = slices.snapshot(transport);
        let per_revision = u64::try_from(MEASURED_CLIENTS.len()).expect("small");
        assert_eq!(snapshot.by_revision.len(), MEASURED_REVISIONS.len() + 1);
        assert!(
            snapshot.by_revision.values().all(|n| *n == per_revision),
            "{snapshot:?}"
        );
        assert_eq!(snapshot.by_client.len(), MEASURED_CLIENTS.len());
        assert_eq!(
            snapshot.total,
            per_revision * u64::try_from(snapshot.by_revision.len()).expect("small")
        );
        assert_eq!(
            snapshot.by_transport.get(transport.as_str()),
            Some(&snapshot.total)
        );
        assert_eq!(snapshot.unattributed, 0);
        if transport == Transport::Stdio {
            // The window's own sums (revisions + unattributed, clients and
            // transports each equal the total) hold for what a slice writes.
            let mut window = crate::protocol_revision_telemetry::window::WindowV2::empty(1);
            window.stdio = snapshot.clone();
            crate::protocol_revision_telemetry::window::validate_window_v2(&window)
                .expect("a slice snapshot is a valid window slice");
        }
        for other in TRANSPORTS.into_iter().filter(|t| *t != transport) {
            assert_eq!(
                slices.snapshot(other),
                Snapshot::default(),
                "{other:?} saw {transport:?}"
            );
        }
    }
}

#[test]
fn every_missing_revision_agent_key_is_counted() {
    let keys: Vec<&'static str> = NAMED_CLIENTS
        .iter()
        .chain(USER_AGENT_FAMILIES)
        .copied()
        .collect();
    for transport in TRANSPORTS {
        let mut slices = TransportSlices::default();
        for key in &keys {
            slices.count(transport, None, "other", || key);
        }
        let agents = slices.agents(transport);
        assert_eq!(agents.len(), keys.len(), "{agents:?}");
        assert!(agents.values().all(|n| *n == 1));
        let snapshot = slices.snapshot(transport);
        assert_eq!(
            snapshot.unattributed,
            u64::try_from(keys.len()).expect("small")
        );
        assert_eq!(snapshot.total, snapshot.unattributed);
    }
}

#[test]
fn an_empty_slice_is_an_empty_snapshot() {
    let slices = TransportSlices::default();
    for transport in TRANSPORTS {
        assert_eq!(slices.snapshot(transport), Snapshot::default());
        assert!(slices.agents(transport).is_empty());
    }
}
