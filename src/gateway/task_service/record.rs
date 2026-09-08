// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Private durable record; never returned as the public Task wire projection.

use crate::protocol::tasks::{Task, TaskSnapshot};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Current on-disk format. The loader accepts `1..=RECORD_VERSION` and never
/// rewrites a supported legacy row. Bumped to 3 in the SAME increment that
/// widened the loader and added [`UpstreamRecord`]: a `version: 3` write
/// reaching a binary whose loader still hard-refuses 3 bricks the store.
pub(super) const RECORD_VERSION: u32 = 3;

/// The record version that introduced `dispatched`. Spelled separately from
/// [`RECORD_VERSION`] because it is a fact about one field: a later format bump
/// must not silently reclassify a v2 row that did record its marker.
pub(super) const MARKER_VERSION: u32 = 2;

/// The record version that introduced [`Record::upstream`]. Spelled separately
/// from [`RECORD_VERSION`] for the same reason [`MARKER_VERSION`] is: a later
/// bump must not reclassify a v3 row that did record its handle.
pub(super) const UPSTREAM_VERSION: u32 = 3;

/// Upper bound on a durable upstream handle, in bytes.
///
/// The handle is an opaque peer-chosen string — the pinned SDK's is 43 URL-safe
/// characters, but nothing on the wire promises that — so it is bounded before
/// it is persisted. An over-long handle is not captured and the row stays
/// `unknown`; it is never truncated, because half a handle addresses nothing.
pub(super) const MAX_UPSTREAM_HANDLE_BYTES: usize = 512;

/// A stand-in handle whose JSON encoding is the widest any accepted handle can
/// have, for measuring a record before a peer has answered with one.
///
/// The reservation has to be a real handle rather than a number, because the
/// bound above is on the handle's BYTES and the record budget is on the encoded
/// record. `serde_json` escapes a C0 control byte as `\u00XX` — six characters —
/// and nothing it emits is wider: `"` and `\` cost two, `\n` and its siblings
/// cost two, and every other byte is copied through. So a full
/// [`MAX_UPSTREAM_HANDLE_BYTES`] of NUL is the maximum encoding of the maximum
/// accepted handle, and measuring with it can never reserve too little.
///
/// Byte length, not character count: `\0` is one UTF-8 byte, so this string is
/// exactly the largest handle `mark_upstream` will accept.
pub(super) fn widest_handle_reservation() -> String {
    "\0".repeat(MAX_UPSTREAM_HANDLE_BYTES)
}

/// What a durable row must carry to be recoverable, and nothing it may derive.
///
/// The descriptor is captured by the trusted dispatch path and never rebuilt
/// from read parameters. It holds no transport authorization header, bearer or
/// JWT, no prior signature, and no serialized identity: a later read
/// re-authorizes the ORIGINAL target against the CURRENT caller, and a saved
/// credential would be the thing that made that check decorative.
///
/// `arguments` is the complete inner value `ToolTarget` was built from, because
/// `authorize_invocation` hands exactly that to the pluggable `ToolAuthorizer`
/// — persisting only the names would re-authorize a narrower call than the one
/// that ran.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpstreamRecord {
    /// The peer's own task identifier. Opaque: never parsed as a gateway id.
    pub(crate) handle: String,
    /// Backend the original operation was dispatched to, and the only backend
    /// a query for this handle may be sent to.
    pub(crate) backend: String,
    /// Backend tool name of the original operation.
    pub(crate) tool: String,
    /// The original inner `arguments` JSON.
    pub(crate) arguments: Value,
    /// The admission operation digest this descriptor was captured beside.
    /// Checked on load: a descriptor that does not belong to the record it was
    /// read from is refused rather than authorized.
    pub(crate) operation_digest: String,
}

impl UpstreamRecord {
    /// Whether this descriptor still belongs to the record holding it.
    pub(super) fn consistent_with(&self, admission: &AdmissionRecord) -> bool {
        self.operation_digest == admission.operation_digest
            && !self.handle.is_empty()
            && self.handle.len() <= MAX_UPSTREAM_HANDLE_BYTES
            && !self.backend.is_empty()
            && !self.tool.is_empty()
    }
}

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
    /// The durable upstream handle and its recovery descriptor. Absent on
    /// v1/v2 and on every row whose backend never returned one; `#[serde(default)]`
    /// loads that as `None` without inventing a field on disk, and
    /// `skip_serializing_if` keeps a pre-upstream row byte-identical.
    ///
    /// Gateway state, not admission input: `AdmissionRecord::metadata_bytes` is
    /// untouched by it, so capturing a handle cannot perturb an admitted digest.
    /// It does count against `max_record_bytes`, which `mark_upstream` enforces
    /// before the write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) upstream: Option<UpstreamRecord>,
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
                upstream: None,
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
                upstream: None,
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
    /// Whether the row is `working` rather than `input_required`. Only a
    /// `working` row may be deferred to a later owner read: an abandoned input
    /// round keeps its reviewed I3 treatment, and deferring one would leave a
    /// non-terminal record no read could ever advance.
    pub(super) is_working: bool,
    /// The durable handle this row can still be recovered through, if any. A
    /// row is recoverable only once its handle is durable; until then it is
    /// `unknown` and is never claimed.
    pub(super) upstream: Option<UpstreamRecord>,
}

/// A committed view; the private admission and backend fields stay in Record.
#[derive(Debug)]
pub(crate) struct CommittedTask {
    pub(crate) task: Task,
    pub(crate) revision: u64,
}
