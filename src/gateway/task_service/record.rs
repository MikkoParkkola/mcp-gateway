// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Private durable record; never returned as the public Task wire projection.

use crate::protocol::tasks::{Task, TaskSnapshot};
use serde::{Deserialize, Serialize};

/// Current on-disk record format. The loader accepts `1..=RECORD_VERSION` and
/// never rewrites a supported legacy row.
pub(super) const RECORD_VERSION: u32 = 2;

/// The record version that introduced `dispatched`. Spelled separately from
/// [`RECORD_VERSION`] because it is a fact about one field: a later format bump
/// must not silently reclassify a v2 row that did record its marker.
pub(super) const MARKER_VERSION: u32 = 2;

/// Persisted values supplied by the sole admission authority. Production
/// conversion from its opaque `TaskBinding` is deliberately not installed yet.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AdmissionRecord {
    pub(super) identity_digest: String,
    pub(super) principal_digest: String,
    pub(super) operation_digest: String,
    pub(super) representation_digest: String,
    pub(super) metadata_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Record {
    pub(super) version: u32,
    /// Gateway-internal dispatch marker. Serialized even when false so a current
    /// never-dispatched row is distinguishable from a legacy row that could not
    /// record the fact. Absent on v1; `#[serde(default)]` loads that as false
    /// without inventing a field on disk.
    #[serde(default)]
    pub(super) dispatched: bool,
    pub(super) admission: AdmissionRecord,
    pub(super) backend: String,
    pub(super) revision: u64,
    pub(super) model: TaskSnapshot,
}

/// An explicitly pre-admitted creation boundary. Tests can construct it while
/// the admission owner delivers the reviewed, lease-only production conversion.
pub(super) struct PreparedTask {
    pub(super) record: Record,
    /// The admission token this task was authorized by, resolved inside the
    /// store's cancellation-surviving section. `None` only in fixtures that
    /// exercise the store without admission.
    pub(super) publication: Option<crate::idempotency::admission::TaskPublication>,
}

impl PreparedTask {
    /// Build a prepared task from an admitted lease's binding and its one-shot
    /// publication token. The digests are the binding's own: the task service
    /// stores what admission derived and never derives identity itself.
    pub(super) fn admitted(
        task: &Task,
        binding: &crate::idempotency::admission::TaskBinding,
        publication: crate::idempotency::admission::TaskPublication,
        backend: &str,
    ) -> Self {
        Self {
            record: Record {
                version: RECORD_VERSION,
                dispatched: false,
                admission: AdmissionRecord {
                    identity_digest: binding.identity().to_owned(),
                    principal_digest: binding.principal_digest().to_owned(),
                    operation_digest: binding.operation().to_owned(),
                    representation_digest: binding.representation().to_owned(),
                    metadata_bytes: binding.metadata_bytes(),
                },
                backend: backend.into(),
                revision: 1,
                model: task.snapshot(),
            },
            publication: Some(publication),
        }
    }

    #[cfg(test)]
    pub(super) fn for_test(task: &Task, owner: &str, identity: u64) -> Self {
        Self {
            publication: None,
            record: Record {
                version: RECORD_VERSION,
                dispatched: false,
                admission: AdmissionRecord {
                    identity_digest: format!("{identity:064x}"),
                    principal_digest: owner.to_owned(),
                    operation_digest: "a".repeat(64),
                    representation_digest: "b".repeat(64),
                    metadata_bytes: 256,
                },
                backend: "fixture-backend".into(),
                revision: 1,
                model: task.snapshot(),
            },
        }
    }
}

/// One non-terminal row as startup found it: what recovery needs and nothing it
/// may derive. The owner is the digest the record itself persisted — recovery
/// holds no principal to hash and never invents one.
pub(super) struct InterruptedTask {
    pub(super) id: String,
    pub(super) owner_digest: String,
    pub(super) revision: u64,
    /// `working`, `version >= MARKER_VERSION`, marker unset: the only state a
    /// record can prove the backend never saw. An abandoned input round is not
    /// one, whatever its marker says.
    pub(super) never_dispatched: bool,
}

/// A committed view; the private admission and backend fields stay in Record.
#[derive(Debug)]
pub(crate) struct CommittedTask {
    pub(crate) task: Task,
    pub(crate) revision: u64,
}
