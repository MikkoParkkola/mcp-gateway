// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-transport counters for the U1 v2 window, allocation-free on the
//! request path.
//!
//! Every request is counted here, including the stdio refusal paths that a
//! fixed allocation budget bounds (`signing_nonce_allocations`). The slices
//! are therefore fixed arrays indexed by the bounded labels, and become a
//! [`Snapshot`] (with its string keys) only when the window is written.

use std::collections::BTreeMap;

use super::agents::{NAMED_CLIENTS, USER_AGENT_FAMILIES};
use super::{MEASURED_CLIENTS, MEASURED_REVISIONS, OTHER_REVISION, Snapshot, Transport};

const REVISIONS: usize = MEASURED_REVISIONS.len() + 1;
const CLIENTS: usize = MEASURED_CLIENTS.len();
const AGENTS: usize = NAMED_CLIENTS.len() + USER_AGENT_FAMILIES.len();

#[derive(Debug, Default, Clone, Copy)]
struct Slice {
    /// Indexed like `MEASURED_REVISIONS`, then `other`.
    by_revision: [u64; REVISIONS],
    /// Indexed like `MEASURED_CLIENTS`.
    by_client: [u64; CLIENTS],
    /// Missing-revision callers, indexed like `NAMED_CLIENTS` then
    /// `USER_AGENT_FAMILIES`.
    agents: [u64; AGENTS],
    unattributed: u64,
    total: u64,
}

/// One [`Slice`] per [`Transport`].
#[derive(Debug, Default)]
pub(super) struct TransportSlices([Slice; 3]);

impl TransportSlices {
    /// Count one request. Every label is one the registry already bounded;
    /// a label outside its list (impossible by construction) is not counted.
    pub(super) fn count(
        &mut self,
        transport: Transport,
        revision: Option<&'static str>,
        client: &'static str,
        missing_revision_agent: impl FnOnce() -> &'static str,
    ) {
        let slice = &mut self.0[transport_index(transport)];
        slice.total += 1;
        if let Some(i) = index_of(MEASURED_CLIENTS, client) {
            slice.by_client[i] += 1;
        }
        match revision {
            Some(rev) => {
                if let Some(i) = revision_index(rev) {
                    slice.by_revision[i] += 1;
                }
            }
            None => {
                slice.unattributed += 1;
                if let Some(i) = agent_index(missing_revision_agent()) {
                    slice.agents[i] += 1;
                }
            }
        }
    }

    /// This transport's counts as a [`Snapshot`]: only labels seen, as the
    /// merged view records them.
    pub(super) fn snapshot(&self, transport: Transport) -> Snapshot {
        let slice = &self.0[transport_index(transport)];
        let revisions = MEASURED_REVISIONS
            .iter()
            .copied()
            .chain(std::iter::once(OTHER_REVISION));
        Snapshot {
            by_revision: seen(revisions, &slice.by_revision),
            by_client: seen(MEASURED_CLIENTS.iter().copied(), &slice.by_client),
            by_transport: if slice.total == 0 {
                BTreeMap::new()
            } else {
                BTreeMap::from([(transport.as_str().to_string(), slice.total)])
            },
            unattributed: slice.unattributed,
            total: slice.total,
        }
    }

    /// This transport's missing-revision callers, only keys seen.
    pub(super) fn agents(&self, transport: Transport) -> BTreeMap<String, u64> {
        let keys = NAMED_CLIENTS.iter().chain(USER_AGENT_FAMILIES).copied();
        seen(keys, &self.0[transport_index(transport)].agents)
    }
}

fn transport_index(transport: Transport) -> usize {
    match transport {
        Transport::Http => 0,
        Transport::Stdio => 1,
        Transport::Internal => 2,
    }
}

fn index_of(list: &[&str], label: &str) -> Option<usize> {
    list.iter().position(|candidate| *candidate == label)
}

fn revision_index(revision: &str) -> Option<usize> {
    index_of(MEASURED_REVISIONS, revision)
        .or_else(|| (revision == OTHER_REVISION).then_some(MEASURED_REVISIONS.len()))
}

fn agent_index(agent: &str) -> Option<usize> {
    index_of(NAMED_CLIENTS, agent)
        .or_else(|| index_of(USER_AGENT_FAMILIES, agent).map(|i| NAMED_CLIENTS.len() + i))
}

fn seen<'a>(keys: impl Iterator<Item = &'a str>, counts: &[u64]) -> BTreeMap<String, u64> {
    keys.zip(counts)
        .filter(|(_, count)| **count > 0)
        .map(|(key, count)| (key.to_string(), *count))
        .collect()
}
