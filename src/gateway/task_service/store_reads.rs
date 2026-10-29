// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The store's read-only queries over the committed image: owner-scoped
//! upstream reads, the descriptor-fit probe and the test-only readers. Moved
//! out of `store.rs` unchanged; they take no ordering lock and write nothing.

use super::*;

impl TaskStore {
    /// The owner-scoped upstream descriptor of one committed row, with the
    /// revision and status it was read at.
    ///
    /// Owner-scoped through [`owned`], so a foreign caller is told the task is
    /// absent and learns nothing about a handle. A descriptor that does not
    /// belong to the record it was read from is dropped here rather than
    /// returned: a read path may not authorize against an inconsistent target.
    pub(crate) fn upstream_of(
        &self,
        owner: &str,
        id: &str,
    ) -> Result<(Option<UpstreamRecord>, u64, TaskStatus), StoreError> {
        let state = self.0.state();
        if !state.ready {
            return Err(StoreError::Unavailable);
        }
        let entry = owned(&state, owner, id)?;
        let descriptor = entry
            .record
            .upstream
            .clone()
            .filter(|upstream| upstream.consistent_with(&entry.record.admission));
        Ok((descriptor, entry.record.revision, entry.task.status()))
    }

    /// Whether the committed row could still hold the COMPLETE recovery
    /// descriptor for `(backend, tool, arguments)` and the widest handle a peer
    /// may answer with.
    ///
    /// Measured, never estimated: the candidate is the record as it stands with
    /// the descriptor `mark_upstream` would attach, serialized by the same
    /// [`serialize`] the write uses and compared against the same
    /// `record_bytes` bound. JSON escaping is therefore counted by
    /// construction — an argument whose bytes fit but whose ENCODING does not is
    /// refused here — and the handle is reserved at
    /// [`widest_handle_reservation`], so no answer this store would accept can
    /// make a measured-fitting descriptor overflow afterwards. There is no
    /// arithmetic to overflow: nothing is added up, one candidate is encoded.
    ///
    /// Owner-scoped through [`owned`] and read-only: it takes no ordering lock,
    /// writes nothing, and tells a foreign caller only what an absent task
    /// tells it. Conservative at the revision it is asked at — `dispatched` is
    /// still `false`, which encodes one byte WIDER than the `true` the row will
    /// carry when the descriptor is written — and `mark_upstream`'s own check
    /// stays the authority over anything that grows in between.
    pub(crate) fn admits_upstream_descriptor(
        &self,
        owner: &str,
        id: &str,
        backend: &str,
        tool: &str,
        arguments: &serde_json::Value,
    ) -> Result<bool, StoreError> {
        let (task, mut candidate) = {
            let state = self.0.state();
            if !state.ready {
                return Err(StoreError::Unavailable);
            }
            let entry = owned(&state, owner, id)?;
            (entry.task.clone(), entry.record.clone())
        };
        // The record's OWN admitted digest, exactly as `capture_upstream` binds
        // it: measuring against a digest derived a second time would measure a
        // descriptor this record could never be given.
        let operation_digest = candidate.admission.operation_digest.clone();
        candidate.upstream = Some(UpstreamRecord {
            handle: widest_handle_reservation(),
            backend: backend.to_owned(),
            tool: tool.to_owned(),
            arguments: arguments.clone(),
            operation_digest,
        });
        candidate.version = candidate.version.max(UPSTREAM_VERSION);
        let budget = self.0.limits.record_bytes;
        // And once cancelled: see `targets::cancelled_bytes`. Measured
        // at the widest instant chrono can encode, so no real cancel's
        // timestamp is wider, and no clock is read.
        Ok(serialize(&candidate)?.len() <= budget
            && targets::cancelled_bytes(
                &task,
                &candidate,
                chrono::DateTime::<chrono::Utc>::MAX_UTC,
            )? <= budget)
    }

    /// Test-only: the durable recovery descriptor of `id`, whatever owner holds
    /// it.
    ///
    /// Owner-agnostic on purpose. A route-level regression knows the task
    /// identifier the client was answered with and nothing else; reproducing
    /// admission's principal hashing to read what dispatch persisted would put
    /// the test's own derivation between it and the record. It is a read of the
    /// committed image and exists only under `cfg(test)`.
    #[cfg(test)]
    pub(crate) fn upstream_for_test(&self, id: &str) -> Option<UpstreamRecord> {
        self.0
            .state()
            .entries
            .get(id)
            .and_then(|entry| entry.record.upstream.clone())
    }

    /// The committed rows, the ones `get` can return (not
    /// capacity occupancy, which also counts reserved and sealed files).
    #[cfg(test)]
    pub(crate) fn committed_count_for_test(&self) -> usize {
        self.0.state().entries.len()
    }

    /// Test-only: the owner digest of `id`, whatever owner holds it.
    #[cfg(test)]
    pub(crate) fn owner_digest_for_test(&self, id: &str) -> Option<String> {
        self.0
            .state()
            .entries
            .get(id)
            .map(|entry| entry.record.admission.principal_digest.clone())
    }

    /// The admitted operation digest of one owner-scoped row.
    ///
    /// Read, never recomputed: the dispatch path binds its recovery descriptor
    /// to the digest the record itself was admitted under.
    pub(crate) fn operation_digest_of(&self, owner: &str, id: &str) -> Option<String> {
        let state = self.0.state();
        if !state.ready {
            return None;
        }
        owned(&state, owner, id)
            .ok()
            .map(|entry| entry.record.admission.operation_digest.clone())
    }
}
