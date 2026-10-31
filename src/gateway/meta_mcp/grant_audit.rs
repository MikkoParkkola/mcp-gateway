// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D3-a: identity grant decisions are audited, one record per decision on a
//! personal capability per outer call (D3-amendment rev 11), with one
//! exception (MIK-7692, operator disposition R3):
//!
//! A read of a finished task re-checks the grants of the calls that produced
//! it (#2461), so a client polling it would write the same decision on every
//! poll. Such a re-check writes no record when the last record written for
//! the same task, caller and target is identical in every recorded field but
//! its timestamp and trace id, and was written less than `REPEAT_WINDOW`
//! ago. A caller is its API key name, grant subject (authority and subject,
//! never the display label) and proven agent id (MIK-7826). Any change
//! (a revoked grant, another reason, another grant id) is written at once,
//! and an unchanged decision is written again once the window has passed.
//! Dispatch decisions are never suppressed; polling itself stays visible in
//! the task and poll logs.
//!
//! `identity_grant_rule` with `Emit::Audit` notes each decision into a
//! task-local slot. The outermost opener (`invoke_tool`, the dispatch tail,
//! the HTTP `/mcp` handler, stdio `tools/call`) selects and writes the
//! records before the answer leaves, failing closed under `FailClosed`.

use crate::error::rpc_codes::INTERNAL_ERROR;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::response::IntoResponse as _;
use serde_json::{Map, Value};

use crate::identity_grants::{IdentityGrantAuditEvent, IdentityGrantDecisionReason};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::TransparencyLogger;
use crate::security::audit::{AuditEnvelope, AuditFailurePolicy, AuditOutcome, AuditWho};
use crate::{Error, Result};

mod repeat;
pub(crate) use repeat::DecisionDedupe;
#[cfg(test)]
pub(super) use repeat::{REPEAT_WINDOW, RepeatLedger};

/// The record kind a grant decision is written as.
const DECISION_KIND: &str = "identity_grant_decision";

/// An open slot: its notes, the request id an HTTP answer is refused
/// under when their write fails (MIK-7663.GH2409.3), and the log they go to.
/// `sealed` once the answer's delivery record has flushed it ([`seal`]).
struct Slot {
    notes: Mutex<Vec<GrantNote>>,
    answer_id: std::sync::OnceLock<RequestId>,
    logger: Arc<TransparencyLogger>,
    sealed: std::sync::atomic::AtomicBool,
}

tokio::task_local! {
    /// The open slot's notes, owned by the outermost opener.
    static GRANT_SLOT: Arc<Slot>;
    /// Set while a finished task's stored delivery is re-checked: the
    /// suppression store and the task-and-caller half of the repeat key.
    static REPEAT_SCOPE: (Arc<DecisionDedupe>, String);
}

/// How long a re-check record waits for the repeat check and its append
/// together. The append inside is also held to the log's own bound (F20),
/// whichever is shorter.
const LEDGER_WAIT: Duration = Duration::from_secs(5);

/// Run `check` as a re-check of a finished task's delivery: decisions it
/// notes may be suppressed as repeats (see the module docs).
pub(super) fn in_repeat_scope<T>(
    store: &Arc<DecisionDedupe>,
    task_and_caller: String,
    check: impl FnOnce() -> T,
) -> T {
    REPEAT_SCOPE.sync_scope((Arc::clone(store), task_and_caller), check)
}

/// A re-check note's suppression key and decision fingerprint.
#[derive(Clone)]
pub(super) struct RepeatMark {
    store: Arc<DecisionDedupe>,
    key: String,
    decision: String,
}

impl std::fmt::Debug for RepeatMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepeatMark")
            .field("key", &self.key)
            .field("decision", &self.decision)
            .finish_non_exhaustive()
    }
}

impl PartialEq for RepeatMark {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.decision == other.decision
    }
}

impl Eq for RepeatMark {}

/// One grant decision noted inside a slot, keyed by the check's own inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GrantNote {
    /// The backend the check was asked about.
    pub(super) server: String,
    /// The tool the check was asked about.
    pub(super) tool: String,
    /// `trace::current()` when the note was taken; `None` outside an invocation.
    pub(super) trace_id: Option<String>,
    /// Whether the grant allowed the call.
    pub(super) allowed: bool,
    /// The record's domain fields, projected: the subject without its label.
    pub(super) fields: Map<String, Value>,
    /// The evaluated subject id, for the envelope's `who`.
    pub(super) subject: Option<String>,
    /// Set on a finished task's re-check: how a repeat is recognised.
    pub(super) repeat: Option<RepeatMark>,
}

impl GrantNote {
    /// Project `event` into a note. The subject keeps `authority` and
    /// `subject` only: its label is an email and never reaches the log.
    fn project(server: &str, tool: &str, event: &IdentityGrantAuditEvent) -> Self {
        let mut fields = Map::new();
        fields.insert("kind".into(), DECISION_KIND.into());
        fields.insert("timestamp".into(), event.timestamp.to_rfc3339().into());
        fields.insert(
            "reason".into(),
            serde_json::to_value(&event.reason).unwrap_or_default(),
        );
        fields.insert("capability".into(), event.capability.clone().into());
        fields.insert(
            "scope".into(),
            serde_json::to_value(&event.scope).unwrap_or_default(),
        );
        if let Some(tool) = &event.tool {
            fields.insert("tool".into(), tool.clone().into());
        }
        if let Some(grant_id) = &event.grant_id {
            fields.insert("grant_id".into(), grant_id.clone().into());
        }
        if let Some(agent_id) = &event.agent_id {
            fields.insert("agent_id".into(), agent_id.clone().into());
        }
        if let Some(subject) = &event.subject {
            fields.insert(
                "subject".into(),
                serde_json::json!({ "authority": subject.authority, "subject": subject.subject }),
            );
        }
        Self {
            server: server.to_string(),
            tool: tool.to_string(),
            trace_id: crate::gateway::trace::current(),
            allowed: event.allowed,
            fields,
            subject: event.subject.as_ref().map(|s| s.subject.clone()),
            repeat: None,
        }
    }

    /// Every recorded field but the timestamp, and the outcome.
    fn fingerprint(&self) -> String {
        let mut fields = self.fields.clone();
        fields.remove("timestamp");
        format!("{}|{}", self.allowed, Value::Object(fields))
    }

    fn envelope(&self) -> AuditEnvelope {
        let mut who = AuditWho::from_subject(self.subject.as_deref().unwrap_or("anonymous"));
        // `who` names the same (authority, subject) pair the domain
        // `subject` field records, not the subject alone.
        who.authority = self
            .fields
            .get("subject")
            .and_then(|subject| subject["authority"].as_str())
            .map(str::to_string);
        AuditEnvelope {
            trace_id: self.trace_id.clone(),
            otel_trace_id: None,
            outcome: if self.allowed {
                AuditOutcome::Ok
            } else {
                AuditOutcome::Denied(-32004)
            },
            who,
        }
    }
}

/// The notes that become records: every traced note, and the last untraced
/// note of a `(server, tool)` with no traced note.
pub(super) fn select_records(notes: &[GrantNote]) -> Vec<&GrantNote> {
    let same = |a: &GrantNote, b: &GrantNote| a.server == b.server && a.tool == b.tool;
    notes
        .iter()
        .enumerate()
        .filter(|&(i, note)| {
            note.trace_id.is_some()
                || (!notes.iter().any(|n| same(n, note) && n.trace_id.is_some())
                    && !notes[i + 1..].iter().any(|n| same(n, note)))
        })
        .map(|(_, note)| note)
        .collect()
}

/// Owns a slot's notes: whatever is still pending when it drops (a cancelled
/// call) is written on a spawned task through the bounded append.
struct SlotGuard {
    slot: Arc<Slot>,
    logger: Arc<TransparencyLogger>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let pending = std::mem::take(&mut *self.slot.notes.lock().expect("grant slot lock"));
        if !pending.is_empty() {
            spawn_write(&self.logger, pending);
        }
    }
}

/// Write `notes` on a spawned task, bounded; never on the caller's thread.
fn spawn_write(logger: &Arc<TransparencyLogger>, notes: Vec<GrantNote>) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::error!(
            count = notes.len(),
            "grant decision records lost: no runtime to write them"
        );
        return;
    };
    let logger = Arc::clone(logger);
    handle.spawn(async move {
        if let Err(error) = write_records(&logger, &notes).await {
            tracing::error!(%error, "grant decision records could not be written");
        }
    });
}

/// Append one record per selected note, bounded (F20). Every record is
/// attempted; the first failure is reported after the batch.
async fn write_records(
    logger: &Arc<TransparencyLogger>,
    notes: &[GrantNote],
) -> std::io::Result<()> {
    #[cfg(test)]
    seams::at_write_start().await;
    let mut first_failure = None;
    for note in select_records(notes) {
        // Held across the append: check, write and remember are one step.
        // The wait and the append share one deadline, so a queue of re-checks
        // behind slow writes fails like a slow append does (F20).
        let started = tokio::time::Instant::now();
        let deadline = LEDGER_WAIT;
        let mut ledger = None;
        if let Some(mark) = &note.repeat {
            let Ok(guard) = tokio::time::timeout(deadline, mark.store.0.lock()).await else {
                first_failure.get_or_insert(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "grant decision record timed out waiting for its repeat check",
                ));
                continue;
            };
            ledger = Some(guard);
        }
        let now = Instant::now();
        if let (Some(mark), Some(ledger)) = (&note.repeat, &ledger)
            && ledger.is_repeat(&mark.key, &mark.decision, now)
        {
            continue;
        }
        let (fields, envelope) = (note.fields.clone(), note.envelope());
        // Only a re-check shares its wait with the append; any other record
        // keeps the log's own bounds unchanged.
        let cap = note
            .repeat
            .as_ref()
            .map(|_| deadline.saturating_sub(started.elapsed()));
        #[cfg(test)]
        if seams::fail_this_append() {
            first_failure.get_or_insert(std::io::Error::other("injected append failure"));
            continue;
        }
        let written = logger
            .append_bounded_within(cap, move |log| {
                log.append_event(fields, &envelope).map(|_| ())
            })
            .await;
        match written {
            // Remembered only once written: a failed write suppresses nothing.
            Ok(()) => {
                if let (Some(mark), Some(ledger)) = (&note.repeat, ledger.as_mut()) {
                    ledger.remember(mark.key.clone(), mark.decision.clone(), now);
                }
            }
            Err(error) => {
                first_failure.get_or_insert(error);
            }
        }
    }
    first_failure.map_or(Ok(()), Err)
}

/// Run `future` inside a grant-decision slot, or inside the one already open.
/// The outermost opener writes the selected notes before returning; the
/// second value is that write's verdict: `AuditUnavailable` under
/// `FailClosed` when it failed. The third is the id the call recorded with
/// [`note_answer_id`], if any.
pub(super) async fn with_grant_slot<F: Future>(
    logger: Option<&Arc<TransparencyLogger>>,
    future: F,
) -> (F::Output, Result<()>, Option<RequestId>) {
    let Some(logger) = logger else {
        return (future.await, Ok(()), None);
    };
    if GRANT_SLOT.try_with(|_| ()).is_ok() {
        return (future.await, Ok(()), None);
    }
    #[cfg(test)]
    BOOKKEEPING.with(|b| b.borrow_mut().slots_opened += 1);
    let guard = SlotGuard {
        slot: Arc::new(Slot {
            notes: Mutex::default(),
            answer_id: std::sync::OnceLock::new(),
            logger: Arc::clone(logger),
            sealed: std::sync::atomic::AtomicBool::new(false),
        }),
        logger: Arc::clone(logger),
    };
    #[cfg(test)]
    seams::on_slot_open(&guard.slot);
    let output = GRANT_SLOT.scope(Arc::clone(&guard.slot), future).await;
    let notes = std::mem::take(&mut *guard.slot.notes.lock().expect("grant slot lock"));
    let answer_id = guard.slot.answer_id.get().cloned();
    // A slot that collected no decision has nothing to write, so no flush
    // task: every `/mcp` request opens a slot, and most decide nothing.
    if notes.is_empty() {
        return (output, Ok(()), answer_id);
    }
    (output, write_owned(logger, notes).await, answer_id)
}

/// Write `notes` and wait for the append. The batch is owned by its own
/// task, so a caller cancelled while the flush waits cannot drop records that
/// were never submitted. `AuditUnavailable` under `FailClosed` when it failed.
async fn write_owned(logger: &Arc<TransparencyLogger>, notes: Vec<GrantNote>) -> Result<()> {
    let writer = Arc::clone(logger);
    #[cfg(test)]
    BOOKKEEPING.with(|b| b.borrow_mut().flushes_spawned += 1);
    let flush = tokio::spawn(async move { write_records(&writer, &notes).await });
    let written = flush
        .await
        .unwrap_or_else(|join| Err(std::io::Error::other(join.to_string())));
    written.or_else(|error| {
        tracing::error!(%error, "grant decision record write failed");
        match logger.failure_policy() {
            AuditFailurePolicy::FailClosed => Err(Error::AuditUnavailable),
            AuditFailurePolicy::BestEffort => Ok(()),
        }
    })
}

/// MIK-8204: append every decision the open slot holds so far, and wait for
/// the append, before work they cause starts elsewhere (a task worker). The
/// log's file order is then cause before effect. Notes are taken out, so the
/// slot's own end-of-request write never repeats them. Outside a slot, or
/// with nothing noted, there is nothing to write.
pub(crate) async fn flush_open_slot() -> Result<()> {
    let Ok((logger, notes)) = GRANT_SLOT.try_with(|slot| {
        let notes = std::mem::take(&mut *slot.notes.lock().expect("grant slot lock"));
        (Arc::clone(&slot.logger), notes)
    }) else {
        return Ok(());
    };
    if notes.is_empty() {
        return Ok(());
    }
    write_owned(&logger, notes).await
}

/// The one warning a failed best-effort withheld record logs (MIK-8340 A5
/// item 9); the upgrade note tells operators to alert on it.
pub(super) const WITHHELD_RECORD_FAILED: &str = "The audit record of a withheld surfaced call could not be written; \
     the call is answered as a name that matches no tool";

/// The `FailClosed` exception of MIK-8340 A5 item 9, for the withheld surfaced
/// call's own grant record ONLY: run `noting`, then write the decisions it
/// noted into the open slot at once and on their own task. Their write never
/// becomes the request's verdict (under `FailClosed` the slot's end-of-request
/// write would answer -32005 and reveal the name exists); a failed write logs
/// [`WITHHELD_RECORD_FAILED`] from the writing task itself, so a caller
/// cancelled while it waits cannot drop the warning. Every note added before
/// `noting` stays in the slot and fails closed as before. Outside a slot
/// `noting` runs alone. Any other use is a new exception and needs its own
/// design decision.
pub(super) async fn note_withheld_best_effort<T>(server: &str, noting: impl FnOnce() -> T) -> T {
    let before = GRANT_SLOT
        .try_with(|slot| slot.notes.lock().expect("grant slot lock").len())
        .ok();
    let output = noting();
    let taken = before.and_then(|before| {
        GRANT_SLOT
            .try_with(|slot| {
                let mut held = slot.notes.lock().expect("grant slot lock");
                let at = before.min(held.len());
                (Arc::clone(&slot.logger), held.split_off(at))
            })
            .ok()
    });
    let Some((logger, notes)) = taken.filter(|(_, notes)| !notes.is_empty()) else {
        return output;
    };
    let owned_server = server.to_owned();
    // Owned by its own task, as `write_owned` is: a cancelled caller cannot
    // drop records that were never submitted, nor the warning of their failure.
    let writer = tokio::spawn(async move {
        if let Err(error) = write_records(&logger, &notes).await {
            tracing::warn!(server = %owned_server, %error, "{WITHHELD_RECORD_FAILED}");
        }
    });
    if let Err(join) = writer.await {
        tracing::warn!(server, error = %join, "{WITHHELD_RECORD_FAILED}");
    }
    output
}

/// Note `event` for `(server, tool)` into the open slot. Outside every slot
/// the call is refused (-32005) and the record still written on a spawned
/// task; under test that panics unless the cell opted in.
pub(super) fn note_grant_decision(
    logger: Option<&Arc<TransparencyLogger>>,
    server: &str,
    tool: &str,
    event: &IdentityGrantAuditEvent,
) -> Result<()> {
    let Some(logger) = logger else {
        return Ok(());
    };
    if matches!(
        event.reason,
        IdentityGrantDecisionReason::PublicCapability
            | IdentityGrantDecisionReason::SharedCapability
    ) {
        return Ok(());
    }
    let mut note = GrantNote::project(server, tool, event);
    note.repeat = REPEAT_SCOPE
        .try_with(|(store, task_and_caller)| RepeatMark {
            store: Arc::clone(store),
            key: format!("{task_and_caller}|{server}|{tool}"),
            decision: note.fingerprint(),
        })
        .ok();
    #[cfg(test)]
    BOOKKEEPING.with(|b| b.borrow_mut().notes_taken += 1);
    match GRANT_SLOT.try_with(|slot| seal::note_unless_sealed(slot, &note)) {
        Ok(true) => return Ok(()),
        Ok(false) => return seal::refuse_late(logger, (server, tool), note),
        Err(_) => {}
    }
    #[cfg(test)]
    assert!(
        UNSLOTTED_ALLOWED.with(std::cell::Cell::get) > 0,
        "identity grant check outside a grant-decision slot"
    );
    tracing::error!(
        server,
        tool,
        "identity grant check outside a grant-decision slot; refused"
    );
    spawn_write(logger, vec![note]);
    Err(Error::AuditUnavailable)
}

/// Signing prepared this call, so `invoke_tool` skipped its own check: its
/// trace goes on the prepared (untraced) note for `(server, tool)`.
pub(super) fn stamp_prepared(server: &str, tool: &str) {
    let Some(trace) = crate::gateway::trace::current() else {
        return;
    };
    let _ = GRANT_SLOT.try_with(|slot| {
        let mut notes = slot.notes.lock().expect("grant slot lock");
        if let Some(note) = notes
            .iter_mut()
            .rev()
            .find(|n| n.trace_id.is_none() && n.server == server && n.tool == tool)
        {
            note.trace_id = Some(trace);
        }
    });
}

/// A `Result` answer, refused with -32005 when the slot's write failed.
pub(crate) async fn slot_result<T>(
    logger: Option<&Arc<TransparencyLogger>>,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    let (output, written, _) = with_grant_slot(logger, future).await;
    written.and(output)
}

/// A JSON-RPC answer paired with `extra`, replaced by -32005 when the
/// slot's write failed.
pub(crate) async fn slot_rpc<'a, X: Send + 'a>(
    logger: Option<&Arc<TransparencyLogger>>,
    id: RequestId,
    future: impl Future<Output = (JsonRpcResponse, X)> + Send + 'a,
) -> (JsonRpcResponse, X) {
    #[cfg(test)]
    if logger.is_none() || GRANT_SLOT.try_with(|_| ()).is_ok() {
        BOOKKEEPING.with(|b| b.borrow_mut().idle_wraps += 1);
    }
    // Erased, so an opener's future type stays shallow (E0275 at the stdio spawn).
    let future: Pin<Box<dyn Future<Output = (JsonRpcResponse, X)> + Send + 'a>> = Box::pin(future);
    match with_grant_slot(logger, future).await {
        ((response, extra), Ok(()), _) => (response, extra),
        // The same answer a failed record gets on the meta path, status data
        // included, so a withheld call's slot cannot tell itself apart
        // (MIK-8361 review F4).
        // It still answers the recorded invocation: its delivery keeps that
        // invocation's trace.
        ((response, extra), Err(error), _) => {
            let mut refusal =
                super::response_security::error_response_preserving_status(id, &error);
            refusal.invocation_trace = response.invocation_trace;
            (refusal, extra)
        }
    }
}

/// Record the id a failed slot write refuses this HTTP answer under, so
/// `slot_http` never reads the answer back. The first id recorded in the
/// open slot wins; with no slot open (no log) nothing is kept or cloned.
pub(crate) fn note_answer_id(id: Option<&RequestId>) {
    if let Some(id) = id {
        let _ = GRANT_SLOT.try_with(|slot| slot.answer_id.set(id.clone()));
    }
}

/// An HTTP answer, replaced by a 503 carrying -32005 under the replaced
/// answer's request id when the slot's write failed.
pub(crate) async fn slot_http<'a, R: axum::response::IntoResponse + Send + 'a>(
    logger: Option<Arc<TransparencyLogger>>,
    future: impl Future<Output = R> + Send + 'a,
) -> axum::response::Response {
    let future: Pin<Box<dyn Future<Output = R> + Send + 'a>> = Box::pin(future);
    let (response, written, answer_id) = with_grant_slot(logger.as_ref(), future).await;
    let Err(error) = written else {
        return response.into_response();
    };
    let response = response.into_response();
    // A judged answer holding a read reservation names its id beside the
    // body: dropped unread, it commits nothing (MIK-7116.MIN.2 row 8), and
    // its pending read record moves to the refusal.
    let held = response
        .extensions()
        .get::<crate::gateway::outbound::HeldAnswerId>()
        .map(|held| held.0.clone());
    let (id, judged) = if let Some(id) = held {
        (id, Some(response))
    } else {
        // The id the route recorded when it parsed the request: the answer
        // is dropped unread, whatever its size (MIK-7663.GH2409.3).
        (answer_id, None)
    };
    let body = match id {
        Some(id) => super::response_security::error_response_preserving_status(id, &error),
        None => JsonRpcResponse::error(None, error.to_rpc_code(), error.to_string()),
    };
    let mut replacement = (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(body),
    )
        .into_response();
    if let Some(mut judged) = judged {
        crate::gateway::outbound::carry_record(&mut judged, &mut replacement);
    }
    replacement
}

impl super::MetaMcp {
    /// D1's own boundary opens a slot too, or reuses the open one (R1).
    pub(super) async fn invoke_tool(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &super::MetaMcpCallerContext<'_>,
    ) -> Result<Value> {
        // Plans and code mode deliver through their own arm: their delivery
        // record names no invocation trace, and states no effect or findings,
        // as no one step's facts describe what the composite delivers.
        crate::gateway::delivery_facts::unvouched();
        let trace_id = crate::gateway::trace::generate();
        // Each step's facts stay in a cell of its own: a step refusal the
        // composite carries on past never marks what the composite delivers.
        let sourced = crate::gateway::delivery_facts::step(
            self.invoke_tool_with_source(args, session_id, caller, trace_id),
        )
        .await;
        match sourced {
            Ok(super::invoke::SourcedOutcome::Live((value, _, _))) => Ok(value),
            // A nested invocation's key never matches a deferred entry
            // (L3), so no request reaches this arm; it maps the frame it
            // would carry rather than inventing around it (E11: no assert).
            Ok(super::invoke::SourcedOutcome::Stored(response)) => {
                match (response.result, response.error) {
                    (Some(value), _) => Ok(value),
                    (None, Some(error)) => Err(Error::json_rpc(error.code, error.message)),
                    (None, None) => Err(Error::json_rpc(
                        INTERNAL_ERROR,
                        "stored replay carried neither result nor error",
                    )),
                }
            }
            Err(error) => Err(error),
        }
    }

    /// [`Self::invoke_tool`] keeping the result's chain source and upstream
    /// chain, for a reply that links it (MIK-8159: a backend tool called by
    /// its own name), or the lift's already-shaped stored answer, delivered
    /// unchanged (MIK-8392 STORED.2 D8). The invocation runs under
    /// `trace_id`.
    pub(super) async fn invoke_tool_with_source(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &super::MetaMcpCallerContext<'_>,
        trace_id: String,
    ) -> Result<super::invoke::SourcedOutcome> {
        let logger = self.transparency_logger.as_ref();
        // Erased: the dispatch futures recurse (a chain step is an
        // invocation), and a concrete type here overflows auto-trait checks.
        let future: Pin<Box<dyn Future<Output = super::invoke::Invoked> + Send + '_>> =
            Box::pin(self.invoke_tool_sourced(args, session_id, caller, trace_id));
        // As `slot_result`, keeping the invocation's own pre-send verdict
        // through a failed slot write, which replaces only the answer.
        let (invoked, written, _) = with_grant_slot(logger, future).await;
        super::dispatch_log::note_round(invoked.pre_send);
        let refused = invoked.pre_send == super::dispatch_log::PreSend::Refused;
        let outcome = written.and(invoked.outcome);
        // #2450: every step that got past the authorization chokepoint is a
        // target of the task's result, whatever it then did: an error, or an
        // audit failure after the call, does not un-dispatch it. Only an
        // authorization refusal proves nothing was attempted. A target is a
        // call planned or attempted, which a stored read re-checks access
        // against, so a step refused before its backend stays one.
        if !matches!(outcome, Err(Error::Forbidden { .. })) {
            super::dispatch_log::note_completed(args);
            // `MIK-8408` H2: the same call, with the plan step label it
            // ran under, for the replay entry's `calls`: the record a stored
            // read takes "this backend ran it" from, so a step refused before
            // its backend is never one.
            if !refused {
                super::invoke::relay::note_replay_call(args);
            }
        }
        outcome
    }

    /// The dispatch check, unless signing prepared this call: then only
    /// the invocation's trace is stamped onto the prepared note.
    pub(super) fn check_or_stamp(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &super::MetaMcpCallerContext<'_>,
        (server, tool): (&str, &str),
    ) -> Result<()> {
        if caller
            .signing
            .is_some_and(|context| context.prepared_for(server, tool))
        {
            // Signing ran the policy before the route stage could record this
            // request's verdict (stdio): refuse a withheld name here.
            super::visible::memo::refuse_withheld(server, tool)?;
            stamp_prepared(server, tool);
            Ok(())
        } else {
            self.check_invocation_policy(args, session_id, caller)
        }
    }

    /// The tail the request thread and the task worker share: one slot, so a
    /// plan's decisions flush once, after the whole plan.
    pub(super) async fn dispatch_below_gate_shaped(
        &self,
        target: super::DispatchTarget<'_>,
        shape: super::ResultShape,
        confirmed_in_band: bool,
    ) -> JsonRpcResponse {
        // MIK-7996: held to this dispatch's last write, on every exit path.
        let _session = self.hold_session(target.session_id);
        let logger = self.transparency_logger.as_ref();
        // A slot opens only with a log and none open (the HTTP handler opens
        // one first): otherwise the wrap would box and clone for nothing.
        let opens_slot = logger.is_some() && GRANT_SLOT.try_with(|_| ()).is_err();
        let id = opens_slot.then(|| target.id.clone());
        let answer: Pin<Box<dyn Future<Output = JsonRpcResponse> + Send + '_>> =
            Box::pin(self.dispatch_below_gate_shaped_in_slot(target, shape, confirmed_in_band));
        match id {
            Some(id) => slot_rpc(logger, id, async { (answer.await, ()) }).await.0,
            None => answer.await,
        }
    }
}

#[cfg(test)]
thread_local! {
    static BOOKKEEPING: std::cell::RefCell<GrantBookkeeping> =
        std::cell::RefCell::new(GrantBookkeeping::default());
    static UNSLOTTED_ALLOWED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test-only opt-in: while held, a check outside every slot takes the
/// fail-closed fallback instead of panicking.
#[cfg(test)]
pub(super) struct UnslottedCheckAllowed;

#[cfg(test)]
impl Drop for UnslottedCheckAllowed {
    fn drop(&mut self) {
        UNSLOTTED_ALLOWED.with(|n| n.set(n.get() - 1));
    }
}

#[cfg(test)]
pub(super) fn allow_unslotted_check_for_test() -> UnslottedCheckAllowed {
    UNSLOTTED_ALLOWED.with(|n| n.set(n.get() + 1));
    UnslottedCheckAllowed
}

/// Test-only: slots opened, notes taken and flush tasks spawned on this
/// thread.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct GrantBookkeeping {
    pub(super) slots_opened: usize,
    pub(super) notes_taken: usize,
    pub(super) flushes_spawned: usize,
    /// `slot_rpc` calls that opened no slot (no log, or one already open):
    /// a box and an id clone spent on nothing (MIK-8014 design item 3).
    pub(super) idle_wraps: usize,
}

#[cfg(test)]
pub(super) fn grant_bookkeeping_for_test() -> GrantBookkeeping {
    BOOKKEEPING.with(|b| *b.borrow())
}

#[path = "grant_audit_seal.rs"]
mod seal;
pub(crate) use seal::seal_open_slot;

#[cfg(test)]
#[path = "grant_audit_seams.rs"]
pub(crate) mod seams;

#[cfg(all(test, feature = "webui"))]
mod kind_pin_tests {
    /// The decision set reads grant decisions back by this kind: one rename
    /// here would silently stop its delivery.
    #[test]
    fn the_decision_set_reads_the_kind_written_here() {
        assert_eq!(super::DECISION_KIND, crate::decisions::GRANT_DECISION_KIND);
    }
}
