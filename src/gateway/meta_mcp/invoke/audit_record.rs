// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One meta call's invocation record: built where the call ends as an owned
//! value, counted and its log entry built in the request's scopes, then
//! appended (inline, or by the request's audit owner's job).

use super::*;
/// What a delivered call notes about its reads once its record is written:
/// the dispatch's reading and whether a backend answered. `None` notes nothing.
pub(crate) type DeliveredReading =
    Option<(Option<crate::security::tenant_reads::ReadAttribution>, bool)>;

/// The scan's verdict on the answer a record describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AnswerVerdict {
    /// Delivered as dispatched, or rewritten but still delivered.
    Delivered,
    /// Refused by the response firewall.
    Refused,
}

/// One call's invocation record, built where the call finished and owned
/// until it is written: everything read from the call's scopes and its
/// caller is taken here, so the write needs neither.
pub(crate) struct InvocationRecord {
    withheld: Option<AuditOutcome>,
    /// The class of the dispatch's own result, before any scan verdict.
    answered: Option<AuditOutcome>,
    denial: Option<crate::security::security_metrics::DenialReason>,
    firewall: bool,
    response_hash: Option<String>,
    /// The delivered value, kept only for a cache or replay attribution.
    delivered: Option<Value>,
    succeeded: bool,
    args: Value,
    session_id: Option<String>,
    trace_id: String,
    who: AuditWho,
    credential_kind: crate::security::audit::CredentialKind,
    recorded: Option<super::super::super::grant_audit::RecordedSet>,
    reading: DeliveredReading,
    notes: DispatchNotes,
}

/// What an audit job hands back to the request that awaits it: the write's
/// verdict, and what only the request can settle with it (the replay facts
/// for its lease, the delivered reading for its read scope).
pub(crate) struct Appended {
    written: Result<()>,
    facts: Option<super::super::super::admission::ReplayAudit>,
    args: Value,
    reading: DeliveredReading,
}

impl Appended {
    /// Nothing was appended (no log, or no class), so nothing failed.
    fn unwritten(args: &Value, reading: DeliveredReading) -> Self {
        Self {
            written: Ok(()),
            facts: None,
            args: args.clone(),
            reading,
        }
    }
}

/// A counted record, with its log entry built or with nothing to append.
pub(crate) enum Prepared {
    Done(Appended),
    Append(Box<Entry>),
}

/// One invocation record's log entry, built and owned: the append needs
/// nothing more from the request.
pub(crate) struct Entry {
    log: std::sync::Arc<crate::security::TransparencyLogger>,
    args: Value,
    session_id: Option<String>,
    who: AuditWho,
    trace_id: String,
    facts: super::super::super::admission::ReplayAudit,
    attribution: Map<String, Value>,
    decision: Box<crate::security::decision_record::Decision>,
    recorded: Option<super::super::super::grant_audit::RecordedSet>,
    reading: DeliveredReading,
}

impl MetaMcp {
    /// Record `result` and hand it on, or withhold it when the record cannot be
    /// written under [`AuditFailurePolicy::FailClosed`] (D1-f). Under an open
    /// [`super::super::audit_owner`] (HTTP `/mcp`) `result` passes straight on and the
    /// owner writes the record after the answer's scan (D2.3).
    ///
    /// `request_hash` covers `args` as the caller sent them, gateway directives
    /// included; `response_hash` covers the value returned to the caller
    /// (D1-d.1). A failed call has no response hash. `notes` carries
    /// the backend failure code a call converted to a tool result, and the
    /// tenant attribution its gates saw.
    #[expect(
        clippy::too_many_arguments,
        reason = "one call's finished parts, before they become one owned record"
    )]
    pub(in crate::gateway::meta_mcp::invoke) async fn audit_invocation(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
        trace_id: &str,
        result: Result<Value>,
        notes: DispatchNotes,
        reading: DeliveredReading,
    ) -> Result<Value> {
        let mut notes = notes;
        let withheld = super::super::denial::withheld(args, notes.not_found);
        // A withheld target's record carries the memo's code, so its check.
        if withheld.is_some()
            && let Some(refusal) = args
                .get("server")
                .and_then(Value::as_str)
                .zip(args.get("tool").and_then(Value::as_str))
                .and_then(|(server, tool)| {
                    crate::gateway::meta_mcp::visible::memo::denial(server, tool)
                })
        {
            notes.refused_by_memo(refusal);
        }
        let record = InvocationRecord {
            withheld,
            answered: AuditOutcome::from_result(&result),
            denial: crate::security::security_metrics::meta_denial(&result),
            firewall: matches!(result, Err(Error::ResponseFirewallRefused)),
            response_hash: result.as_ref().ok().map(sha256_of),
            delivered: notes.cached.and(result.as_ref().ok()).cloned(),
            succeeded: result.is_ok(),
            args: args.clone(),
            session_id: session_id.map(str::to_owned),
            trace_id: trace_id.to_owned(),
            who: AuditWho::from_caller(caller),
            credential_kind: caller.credential_kind,
            recorded: super::super::super::grant_audit::open_slot_recorded(),
            reading,
            notes,
        };
        let Some(record) = super::super::audit_owner::defer(record) else {
            return result;
        };
        // Boxed: the record and its write would grow every dispatch future.
        Box::pin(self.write_record(record, AnswerVerdict::Delivered, caller.execution))
            .await
            .and(result)
    }

    /// Write `record` once, under the verdict of the answer's scan, and settle
    /// it on the caller's side (`lease`, the delivered reading). `Err` only
    /// when the write failed under fail-closed.
    pub(crate) async fn write_record(
        &self,
        record: InvocationRecord,
        verdict: AnswerVerdict,
        lease: Option<&super::super::super::admission::SyncLease>,
    ) -> Result<()> {
        let prepared = self.prepare_record(record, verdict);
        let appended = self.append_prepared(prepared).await;
        self.settle_record(appended, lease)
    }

    /// Count `record` and build its log entry, under the verdict of the
    /// answer's scan, in the request's own context: the counters, the denial
    /// metric and the decision read what the request's scopes hold (the
    /// recorder, the token on the call). A refused answer is classed as
    /// `Err(ResponseFirewallRefused)`: `denied`, no response hash, a block and
    /// a firewall catch on the counters. Only the append is left to do.
    pub(crate) fn prepare_record(
        &self,
        record: InvocationRecord,
        verdict: AnswerVerdict,
    ) -> Prepared {
        let InvocationRecord {
            withheld,
            mut answered,
            mut denial,
            mut firewall,
            mut response_hash,
            mut delivered,
            succeeded,
            args,
            session_id,
            trace_id,
            who,
            credential_kind,
            recorded,
            reading,
            mut notes,
        } = record;
        if verdict == AnswerVerdict::Refused {
            let refusal: Result<Value> = Err(Error::ResponseFirewallRefused);
            answered = AuditOutcome::from_result(&refusal);
            denial = crate::security::security_metrics::meta_denial(&refusal);
            (firewall, response_hash, delivered) = (true, None, None);
            notes.refused_by_answer_scan();
        }
        let reading = (verdict == AnswerVerdict::Delivered && succeeded)
            .then_some(reading)
            .flatten();
        let (args, session_id, trace_id) = (&args, session_id.as_deref(), trace_id.as_str());
        // D4: counted before the log check, so auth off still counts.
        // The record's class is worked out once, the refusal
        // rule applied, and both counts take it.
        let class = withheld.or(answered).map(|outcome| notes.outcome(outcome));
        super::super::denial::count_meta_denial(withheld.is_some(), class, denial);
        self.count_invocation(args, &who, firewall, &notes, class);
        let Some(log) = self.transparency_logger.as_ref() else {
            return Prepared::Done(Appended::unwritten(args, reading));
        };
        let Some(outcome) = class else {
            return Prepared::Done(Appended::unwritten(args, reading));
        };
        // Boxed: held across the write, it would grow every dispatch future.
        let decision = Box::new(notes.decided(self, outcome, credential_kind));
        // The tool's own arguments, as the firewall walks them.
        let arguments = crate::gateway::meta_mcp_helpers::parse_tool_arguments(args);
        let tenants = self.request_tenants(arguments.as_ref().unwrap_or(&Value::Null));
        let mut attribution = notes.attribution(self, tenants, delivered.as_ref());
        if let Some(id) = notes.upstream_task {
            attribution.insert("task_id".into(), id.into());
        }
        let facts = super::super::super::admission::ReplayAudit::new(outcome, response_hash)
            .with_request_hash(sha256_of(args));
        Prepared::Append(Box::new(Entry {
            log: std::sync::Arc::clone(log),
            args: args.clone(),
            session_id: session_id.map(str::to_owned),
            who,
            trace_id: trace_id.to_owned(),
            facts,
            attribution,
            decision,
            recorded,
            reading,
        }))
    }

    /// Append a prepared record: the audit job, which reads none of the
    /// request's scopes, so it can run to its end on its own.
    pub(crate) async fn append_prepared(&self, prepared: Prepared) -> Appended {
        let entry = match prepared {
            Prepared::Done(appended) => return appended,
            Prepared::Append(entry) => *entry,
        };
        let Entry {
            log,
            args,
            session_id,
            who,
            trace_id,
            facts,
            attribution,
            decision,
            recorded,
            reading,
        } = entry;
        let written = self
            .write_invocation(
                &log,
                &args,
                session_id.as_deref(),
                who,
                &trace_id,
                &facts,
                attribution,
                decision,
                recorded,
            )
            .await;
        Appended {
            written,
            facts: Some(facts),
            args,
            reading,
        }
    }

    /// Settle an appended record on the caller's side, once its job ended.
    /// Returns the write's verdict.
    pub(crate) fn settle_record(
        &self,
        appended: Appended,
        lease: Option<&super::super::super::admission::SyncLease>,
    ) -> Result<()> {
        let Appended {
            written,
            facts,
            args,
            reading,
        } = appended;
        // #2472: a replay of this execution is recorded with these facts, but
        // only once they describe what was delivered (#2521): a failed write
        // withholds the value, so a replay must not record it as delivered.
        if written.is_ok()
            && let (Some(lease), Some(facts)) = (lease, facts)
        {
            lease.note_audit(facts);
        }
        if written.is_ok() {
            self.note_reading(&args, reading);
        }
        written
    }

    // Only a delivered call counts: its own reading, and the tenants its
    // arguments name when a backend answered it, with or without a log.
    fn note_reading(&self, args: &Value, reading: DeliveredReading) {
        if let Some((reading, responded)) = reading {
            self.note_delivered_reading(args, reading, responded);
        }
    }

    /// Write one meta invocation record with `facts` (outcome and response
    /// hash) and `attribution`. `Err` only when the write failed under
    /// [`AuditFailurePolicy::FailClosed`] (D1-f).
    #[allow(clippy::too_many_arguments)]
    #[expect(
        clippy::too_many_arguments,
        reason = "the record's parts, each owned by a different stage of the call"
    )]
    pub(super) async fn write_invocation(
        &self,
        log: &std::sync::Arc<crate::security::TransparencyLogger>,
        args: &Value,
        session_id: Option<&str>,
        who: AuditWho,
        trace_id: &str,
        facts: &super::super::super::admission::ReplayAudit,
        attribution: Map<String, Value>,
        decision: Box<crate::security::decision_record::Decision>,
        recorded: Option<super::super::super::grant_audit::RecordedSet>,
    ) -> Result<()> {
        let server = args
            .get("server")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let tool = args.get("tool").and_then(Value::as_str).unwrap_or_default();
        let outcome = facts.outcome();
        let response_hash = facts.response_hash().map(str::to_string);
        // See `CorrelationKey::ladder`.
        let otel_trace_id = args
            .get("_meta")
            .and_then(crate::protocol::trace::TraceContext::from_meta)
            .and_then(|tc| tc.trace_id().map(str::to_string));
        let key = CorrelationKey::ladder(otel_trace_id.as_deref(), session_id, trace_id);
        let envelope = AuditEnvelope {
            trace_id: Some(trace_id.to_string()),
            otel_trace_id: otel_trace_id.clone(),
            outcome,
            who,
        };
        // F20: on the blocking pool, bounded; a stalled disk answers 503
        // instead of pinning a runtime worker.
        let (key_id, key_source) = (key.id.to_string(), key.source);
        // A replay records the hash its first execution's record
        // carried; only facts with none are hashed from `args` here.
        let request_hash = facts
            .request_hash()
            .map_or_else(|| sha256_of(args), str::to_owned);
        let (srv, tl) = (server.to_string(), tool.to_string());
        // The open slot's set, taken by the caller where the slot is open: the
        // blocking op below has no task-locals.
        let call_trace = trace_id.to_string();
        let written = log
            .append_bounded(move |log| {
                let landed = log.log_invocation_attributed(
                    CorrelationKey {
                        id: &key_id,
                        source: key_source,
                    },
                    &envelope,
                    InvocationTarget::meta(&srv, &tl),
                    &request_hash,
                    response_hash.as_deref(),
                    attribution,
                    Some(decision.as_ref()),
                );
                // Inside the op, after the write returned Ok: a caller timeout
                // cannot skip it, and a failed write never adds the id. The
                // call's grant decisions read this set in their own later append.
                if landed.is_ok()
                    && let Some(recorded) = &recorded
                {
                    recorded.add(&call_trace);
                }
                landed
            })
            .await;
        match written {
            Ok(()) => Ok(()),
            Err(error) if log.failure_policy() == AuditFailurePolicy::FailClosed => {
                tracing::error!(server, tool, trace_id, %error, "invocation audit write failed; result withheld");
                Err(Error::AuditUnavailable)
            }
            Err(error) => {
                tracing::warn!(server, tool, trace_id, %error, "Transparency log write failed (non-fatal)");
                Ok(())
            }
        }
    }
}
