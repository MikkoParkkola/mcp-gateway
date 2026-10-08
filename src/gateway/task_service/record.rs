// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Private durable record; never returned as the public Task wire projection.

use crate::protocol::tasks::{Task, TaskSnapshot, TaskStatus};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

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

/// The record version that introduced [`Record::input_round`], and the
/// highest the loader accepts. Written only on a row that opens a round, the
/// way `mark_upstream` raises a row to [`UPSTREAM_VERSION`]: every other row
/// stays at [`RECORD_VERSION`], byte-identical, and an older loader refuses
/// only a row that holds a continuation it could not honour.
pub(super) const INPUT_ROUND_VERSION: u32 = 4;

/// The record version that introduced [`Record::targets`]. Written only on a row
/// that carries at least one target; every other row keeps its version and its
/// bytes. A beta loader (`1..=3`) refuses such a row, which UPGRADING-4.0 states.
pub(super) const TARGET_VERSION: u32 = 5;

/// The record version that introduced [`Record::error_author`]. Written only on
/// a Failed row whose error the peer wrote (MIK-7887.RECEIPT.1); every other
/// row keeps its version and its bytes. An older loader refuses such a row,
/// which UPGRADING-4.0 item 105 states.
pub(super) const ERROR_AUTHOR_VERSION: u32 = 6;

/// The highest record version the loader accepts: the newest field's version.
pub(super) const MAX_LOADABLE_VERSION: u32 = ERROR_AUTHOR_VERSION;

/// One backend call a task's result was produced by: names only, never
/// arguments. No current invocation policy reads `ToolTarget.arguments`; a
/// policy that did would have to revisit replay authorization.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Target {
    pub(crate) server: String,
    pub(crate) tool: String,
}

/// How far before the stored continuation's own expiry a round stops taking
/// answers: room for an accepted answer to reach redemption (#2429).
pub(crate) const CONTINUATION_DEADLINE_MARGIN_SECS: u64 = 10;

/// An open input round's continuation: what a resume needs and nothing else.
///
/// Gateway state, never part of the wire task. `request_state` is the
/// continuation envelope this gateway sealed into the interim result, redeemed
/// by the resume exactly as a client retry would present it. `tool` and
/// `arguments` are the call the round interrupted, resent as they were, and
/// `accepted_inputs` holds the answers accepted so far. Dropped on every
/// terminal transition. Counts against `max_record_bytes`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InputRound {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) request_state: Option<String>,
    pub(crate) tool: String,
    pub(crate) arguments: Value,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub(crate) accepted_inputs: Map<String, Value>,
    /// When the stored continuation stops being redeemable, less a margin, in
    /// unix seconds (#2429). `None`: no continuation is stored, and the task's
    /// TTL alone bounds the round.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) continuation_deadline: Option<u64>,
}

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
    /// The open input round, if any. Absent on v1-v3 rows and on every row
    /// with no round outstanding, so such a row serializes as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) input_round: Option<InputRound>,
    /// The backend calls this task made or will make, for re-authorizing a
    /// stored result before it is delivered. Absent on rows written before
    /// [`TARGET_VERSION`] and on rows that dispatched nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) targets: Vec<Target>,
    /// Set when the row settled as the gateway's own bounded failure because
    /// the real outcome did not fit the record budget: it holds no backend
    /// output, so delivering it needs no target check.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) output_free: bool,
    /// Who wrote a Failed row's stored error, decided where it is known
    /// (MIK-7887.RECEIPT.1). Private: never on the wire or in a `tasks/get`
    /// body. Absent on older rows and on every non-Failed row; absent is read
    /// as "not established", which receipts nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) error_author: Option<ErrorAuthor>,
    pub(super) admission: AdmissionRecord,
    pub(super) backend: String,
    pub(super) revision: u64,
    pub(super) model: TaskSnapshot,
    /// MIK-7993: the members of the stored result the gateway wrote, so a
    /// `tasks/get` receipt leaves exactly those out. Absent when none, so
    /// such a row serializes as before. Declared last, after `admission`: a
    /// row damaged or cut inside it reads as damaged after its key, which
    /// keeps the key (MIK-8023) rather than sealing the store (MIK-8052).
    /// Its decode never fails; a bad entry is dropped on its own.
    #[serde(
        default,
        skip_serializing_if = "crate::gateway::gateway_writes::WriteRecord::is_empty"
    )]
    pub(super) gateway_writes: crate::gateway::gateway_writes::WriteRecord,
}

impl Record {
    /// Store the model; a terminal task drops its input round's continuation
    /// and answers with it, so nothing a settled task can no longer use stays.
    pub(super) fn set_model(&mut self, task: &Task) {
        self.model = task.snapshot();
        if matches!(
            task.status(),
            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
        ) {
            self.input_round = None;
        }
    }
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
    pub(super) fn admitted_with_targets(
        task: &Task,
        binding: &crate::idempotency::admission::TaskBinding,
        publication: crate::idempotency::admission::TaskPublication,
        backend: &str,
        targets: Vec<Target>,
    ) -> Self {
        let version = if targets.is_empty() {
            RECORD_VERSION
        } else {
            TARGET_VERSION
        };
        Self {
            record: Record {
                version,
                dispatched: false,
                upstream: None,
                input_round: None,
                targets,
                output_free: false,
                error_author: None,
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
                gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
            },
            publication: Some(publication),
        }
    }

    /// [`Self::admitted_with_targets`] for a call that records none.
    #[cfg(test)]
    pub(super) fn admitted(
        task: &Task,
        binding: &crate::idempotency::admission::TaskBinding,
        publication: crate::idempotency::admission::TaskPublication,
        backend: &str,
    ) -> Self {
        Self::admitted_with_targets(task, binding, publication, backend, Vec::new())
    }

    #[cfg(test)]
    pub(super) fn for_test(task: &Task, owner: &str, identity: u64) -> Self {
        Self {
            publication: None,
            record: Record {
                version: RECORD_VERSION,
                dispatched: false,
                upstream: None,
                input_round: None,
                targets: Vec::new(),
                output_free: false,
                error_author: None,
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
                gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
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
    /// The calls that produced this snapshot's result. A legacy row recorded
    /// none; its one call is recovered from its upstream descriptor when it has
    /// a consistent one, and is otherwise not known (empty).
    pub(crate) targets: Vec<Target>,
    /// Whether the row was written by a gateway that records targets. An empty
    /// list on such a row means nothing was dispatched; on an older row it
    /// means the provenance is unavailable.
    pub(crate) targets_recorded: bool,
    /// The row holds only the gateway's own bounded failure, no backend output.
    pub(crate) output_free: bool,
    /// Who wrote a Failed row's stored error; see `Record::error_author`.
    pub(crate) error_author: Option<ErrorAuthor>,
    /// The owner's digest as the record persisted it, read in the same piece
    /// as the rest of the snapshot (the events source carries it).
    pub(crate) owner_digest: String,
    /// The members of the stored result the gateway wrote (MIK-7993): a read
    /// restores them into its own record, so its receipt leaves them out.
    pub(crate) gateway_writes: crate::gateway::gateway_writes::WriteRecord,
}

impl CommittedTask {
    /// Whether serving this row hands the caller backend output: a result,
    /// a backend error or a backend's input requests. A working or
    /// cancelled row, or one holding only the gateway's own bounded
    /// failure, serves none. Delivery checks and read attribution both
    /// key on it, so they cannot disagree on a status.
    pub(crate) fn serves_backend_output(&self) -> bool {
        !self.output_free
            && matches!(
                self.task.status(),
                TaskStatus::Completed | TaskStatus::Failed | TaskStatus::InputRequired
            )
    }

    /// The committed view of `record`, read in one piece so a caller that
    /// authorizes delivery checks the snapshot it returns.
    pub(super) fn of(task: Task, record: &Record) -> Self {
        Self {
            targets: if record.version >= TARGET_VERSION {
                record.targets.clone()
            } else {
                legacy_targets(&task, record)
            },
            task,
            revision: record.revision,
            targets_recorded: record.version >= TARGET_VERSION,
            output_free: record.output_free,
            error_author: record.error_author,
            owner_digest: record.admission.principal_digest.clone(),
            gateway_writes: record.gateway_writes.clone(),
        }
    }

    /// The stored error when the peer wrote it (MIK-7887.RECEIPT.1): only a
    /// Failed row whose error the gateway established as the peer's. A gateway
    /// error, a substitute, or an older row whose author is unknown has none.
    pub(crate) fn backend_error(&self) -> Option<&crate::protocol::JsonRpcError> {
        (!self.output_free && self.error_author == Some(ErrorAuthor::Peer))
            .then(|| self.task.error())
            .flatten()
    }

    /// The stored result when it is backend output. A row holding only the
    /// gateway's own sentence (a bounded failure, an interrupted or abandoned
    /// round) has none: nothing the backend said was delivered with it.
    pub(crate) fn backend_result(&self) -> Option<&serde_json::Value> {
        let result = self.task.result()?;
        let gateway_authored = result
            .get("_meta")
            .is_some_and(|meta| meta.get(EXECUTION_OUTCOME_KEY).is_some());
        (!self.output_free && !gateway_authored).then_some(result)
    }
}

/// Who wrote a failed task's stored error (MIK-7887.RECEIPT.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ErrorAuthor {
    /// The peer's own error, passed unchanged by every screen and record.
    Peer,
    /// Anything else: a gateway refusal, a substitute, a withheld or replaced
    /// error.
    Gateway,
}

/// The `_meta` key only the gateway's own interrupted results carry.
pub(super) const EXECUTION_OUTCOME_KEY: &str = "io.mcp-gateway/executionOutcome";

/// The one call a legacy row (before [`TARGET_VERSION`]) made, read from its
/// own upstream descriptor: the backend tool the trusted dispatch path
/// captured, bound to this row by its operation digest (MIK-7686). A plan's
/// descriptor never speaks for the plan, and a row without a consistent one
/// has no recoverable provenance.
fn legacy_targets(task: &Task, record: &Record) -> Vec<Target> {
    // A row older than the descriptor cannot have captured one; a descriptor
    // found there is forged or downgraded (the loader and store.rs agree).
    if record.version < UPSTREAM_VERSION
        || matches!(task.tool(), "gateway_execute" | "gateway_run_playbook")
    {
        return Vec::new();
    }
    record
        .upstream
        .iter()
        .filter(|upstream| upstream.consistent_with(&record.admission))
        .map(|upstream| Target {
            server: upstream.backend.clone(),
            tool: upstream.tool.clone(),
        })
        .collect()
}

#[cfg(test)]
#[path = "record_legacy_tests.rs"]
mod legacy_tests;
