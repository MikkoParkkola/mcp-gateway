// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2420: the invocation record for a meta-route `tools/call` the router
//! refuses before the meta layer runs. The meta layer's writer (D1-d) never
//! sees these calls, so without this the scope pre-check and the request
//! firewall refused on `/mcp` without a trace in the chain, while the same
//! refusals on `/mcp/{name}` were recorded (D2-a).

use crate::error::rpc_codes::INVALID_PARAMS;
use std::collections::BTreeSet;

use axum::http::StatusCode;
use serde_json::Value;

use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::authz::ToolTarget;
use crate::gateway::meta_mcp::invoke::audit::DispatchNotes;
use crate::identity_grants::GrantSubject;
use crate::protocol::RequestId;
use crate::security::audit::{
    AuditEnvelope, AuditFailurePolicy, AuditOutcome, AuditWho, InvocationRoute, InvocationTarget,
};
use crate::security::transparency_log::CorrelationKey;

use super::AppState;
use super::helpers::build_error_response;

/// The called name and its arguments as a `tools/call` request carries
/// them, read before the request is parsed: no name and empty arguments
/// when absent, as every intake refusal records them.
pub(crate) fn call_name_and_arguments(request: &Value) -> (&str, &Value) {
    static EMPTY: std::sync::LazyLock<Value> =
        std::sync::LazyLock::new(|| Value::Object(serde_json::Map::new()));
    let params = request.get("params");
    let name = params
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&EMPTY);
    (name, arguments)
}

/// The target a pre-dispatch refusal records, spelled as the request names
/// it: a `gateway_invoke`'s own server and tool, otherwise no server and the
/// called name. A surfaced name stays unmapped: mapping it touches the
/// backend, which these refusals come before.
pub(super) fn request_target<'t>(arguments: &'t Value, called: &'t str) -> (&'t str, &'t str) {
    if called != "gateway_invoke" {
        return ("", called);
    }
    let named = |key: &str| arguments.get(key).and_then(Value::as_str);
    (
        named("server").unwrap_or_default(),
        named("tool").unwrap_or_default(),
    )
}

/// Where a signing refusal was decided, which says who names its kind.
#[derive(Clone, Copy)]
pub(crate) enum SigningSite {
    /// The signing check, inside the route's note scope: its check noted
    /// the kind, so a refusal reaching the writer unnoted is `unrecorded`.
    Check,
    /// The intake's early refusals under the every-call scope, before any
    /// note scope opens: a signing envelope that cannot be restored (an
    /// unusable id, a changed origin) and a malformed nonce. Both refuse the
    /// request's form, so they are `syntax`, as the check notes the nonce.
    Intake,
}

/// Every fact the one writer needs from its caller beyond the refusal
/// itself, each stated at the call site (no default): what a failed write
/// does to the answer, where the decision kind comes from, and the id the
/// answer carries. Who called is the [`Refused`]'s own required field.
#[derive(Clone)]
struct RefusalContext {
    policy: IfUnwritten,
    kind: KindSource,
    id: AnswerId,
}

/// What a failed record write does to the refusal's answer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IfUnwritten {
    /// The log decides: under a fail-closed log the refusal is answered as
    /// the log being unavailable, so no refusal goes unrecorded quietly.
    FollowLog,
    /// Answered as decided; the failed write is logged and counted by the
    /// log itself. Only where the answer must not reveal an outage.
    AnswerAnyway,
}

/// Where a refusal's decision kind comes from.
#[derive(Clone, Copy)]
enum KindSource {
    /// A gate inside the route's note scope noted it; a refusal reaching the
    /// writer unnoted records `unrecorded`.
    NoteScope,
    /// Decided before any note scope opens: this kind, unless a gate noted
    /// one after all.
    Site(crate::security::decision_record::DecisionKind),
}

/// The id a refusal is answered under, read from the request as sent.
#[derive(Clone, Debug)]
pub(crate) enum AnswerId {
    Present(RequestId),
    /// The request has no `id` member.
    Absent,
    /// An `id` member that is not a JSON-RPC id.
    Unreadable,
    /// Not answered by the writer's caller: the call goes on and is answered
    /// later under its own id (a withheld target).
    Later,
}

impl AnswerId {
    /// The id `request` carries, as the answer will name it.
    pub(crate) fn of(request: &Value) -> Self {
        match request.get("id") {
            None => Self::Absent,
            Some(raw) => {
                serde_json::from_value(raw.clone()).map_or(Self::Unreadable, Self::Present)
            }
        }
    }

    /// The id to put in the answer frame: none when absent or unreadable.
    fn frame_id(self) -> Option<RequestId> {
        match self {
            Self::Present(id) => Some(id),
            Self::Absent | Self::Unreadable | Self::Later => None,
        }
    }
}

impl SigningSite {
    /// Where a signing refusal decided at this site takes its kind from.
    const fn kind(self) -> KindSource {
        match self {
            Self::Check => KindSource::NoteScope,
            Self::Intake => {
                KindSource::Site(crate::security::decision_record::DecisionKind::Syntax)
            }
        }
    }
}

/// What the writer settled for a refusal: how its caller answers it.
enum Settled {
    /// Recorded under this trace: answered as decided, naming the receipt.
    Recorded(String),
    /// No log, or a failed write the policy answers anyway: answered as
    /// decided, with no receipt.
    Unrecorded,
    /// The write failed under [`IfUnwritten::FollowLog`] and a fail-closed
    /// log: answered as the log being unavailable.
    Unavailable,
}

/// What a signing refusal records: the outcome its error maps to, the
/// target as the request names it, and the kind `site` implies when no
/// check noted one.
fn signing_refusal<'t>(
    error: crate::Error,
    (server, tool): (&'t str, &'t str),
    (id, site): (AnswerId, SigningSite),
) -> Refusal<'t> {
    let code = error.to_rpc_code();
    Refusal {
        outcome: AuditOutcome::from_result(&Err(error)).unwrap_or(AuditOutcome::Error(code)),
        server,
        tool: Some(tool),
        tenants: BTreeSet::new(),
        // A signing refusal is part of the signing contract: never answered
        // as decided when a fail-closed log could not record it, whatever
        // the transport or the id.
        context: RefusalContext {
            policy: IfUnwritten::FollowLog,
            kind: site.kind(),
            id,
        },
    }
}

/// A stdio signing refusal, written by the writer `/mcp` uses. Stdio has no
/// router state, so the meta layer and its own log stand in for it. Counted
/// once like any refused call, then answered as before: the error's code and
/// words, or the log's unavailability when it fails closed and the record
/// could not be written.
pub(crate) async fn answer_stdio_signing_refusal(
    meta: &crate::gateway::meta_mcp::MetaMcp,
    who: AuditWho,
    (arguments, called, session_id): (&Value, &str, &str),
    (id, site): (AnswerId, SigningSite),
    error: crate::Error,
) -> crate::protocol::JsonRpcResponse {
    use crate::protocol::JsonRpcResponse;
    let code = error.to_rpc_code();
    let message = crate::gateway::meta_mcp::signing::wire_error_message(&error);
    let refusal = signing_refusal(error, request_target(arguments, called), (id, site));
    let id = refusal.context.id.clone().frame_id();
    crate::security::security_metrics::meta_refused(code);
    let refused = Refused {
        arguments,
        who,
        session_id,
        firewall: false,
        trace: None,
    }
    .traced_for_grant();
    match refused
        .settle(meta, meta.transparency_logger.as_ref(), refusal)
        .await
    {
        Settled::Unavailable => {
            let unavailable = crate::Error::AuditUnavailable;
            JsonRpcResponse::gateway_error(id, unavailable.to_rpc_code(), unavailable.to_string())
        }
        Settled::Recorded(_) | Settled::Unrecorded => {
            JsonRpcResponse::gateway_error(id, code, message)
        }
    }
}

/// A meta-route call about to be refused before dispatch.
pub(super) struct Refused<'a> {
    /// The `tools/call` arguments as sent: the object the meta writer hashes
    /// (D1-d.1), so a refused and an admitted call hash alike.
    arguments: &'a Value,
    /// Built as the meta layer builds it (`AuditWho::from_caller`): the same
    /// credential kind, principal, key name and verified subject.
    who: AuditWho,
    session_id: &'a str,
    /// The request firewall refused it, for the web UI's counters.
    firewall: bool,
    /// The trace the route stage authorized the refused target under.
    trace: Option<String>,
}

/// What a refusal records: its outcome and the target resolved before it.
struct Refusal<'t> {
    outcome: AuditOutcome,
    server: &'t str,
    tool: Option<&'t str>,
    tenants: BTreeSet<String>,
    context: RefusalContext,
}

impl<'a> Refused<'a> {
    pub(super) fn of(
        arguments: &'a Value,
        client: Option<&AuthenticatedClient>,
        grant_subject: Option<&GrantSubject>,
        session_id: &'a str,
        record_key: &crate::gateway::record_principal::RecordPrincipalKey,
    ) -> Self {
        Self {
            arguments,
            who: AuditWho::from_request(client, grant_subject, record_key),
            session_id,
            firewall: false,
            trace: None,
        }
    }

    /// Record the refusal under `trace`, the one its decision note carries.
    pub(super) fn with_trace(mut self, trace: Option<String>) -> Self {
        self.trace = trace;
        self
    }

    /// Signing refuses before the dispatch mints the call's trace, so a
    /// signing refusal takes its trace now and hands it to its call's grant
    /// decisions in the open slot: the decisions and the record then name one
    /// call, which Activity lists once.
    fn traced_for_grant(self) -> Self {
        let trace = self
            .trace
            .clone()
            .or_else(crate::gateway::trace::current)
            .unwrap_or_else(crate::gateway::trace::generate);
        crate::gateway::meta_mcp::grant_audit::stamp_refused(&trace);
        self.with_trace(Some(trace))
    }

    /// Mark this refusal as the request firewall's.
    #[cfg(feature = "firewall")]
    pub(super) const fn firewall(mut self) -> Self {
        self.firewall = true;
        self
    }

    /// Record the refusal of `target` as `denied` with `code`, then answer it; under
    /// [`AuditFailurePolicy::FailClosed`] a failed write answers 503 instead
    /// (D1-f).
    pub(super) async fn answer(
        self,
        state: &AppState,
        target: ToolTarget<'_>,
        id: RequestId,
        code: i32,
        message: String,
        status: StatusCode,
    ) -> axum::response::Response {
        // Every caller answers the whole request with this refusal: the
        // route authorization, the request firewall, a refused step.
        crate::gateway::delivery_facts::raise(
            crate::gateway::delivery_facts::ResponseEffect::Refused,
        );
        // MIK-7116.MIN.1: the tenants the refused request named; nothing was
        // fetched, so there is no response side and no data class.
        let tenants = state.meta_mcp.request_tenants(target.arguments);
        let refusal = Refusal {
            outcome: AuditOutcome::Denied(code),
            server: target.server,
            tool: Some(target.tool),
            tenants,
            context: RefusalContext {
                policy: IfUnwritten::FollowLog,
                kind: KindSource::NoteScope,
                id: AnswerId::Present(id),
            },
        };
        self.record(state, refusal, code, message, status).await
    }

    /// MIK-7660 AC3: record a call refused for malformed retry fields as
    /// `invalid`, then answer it -32602/400. It is refused before any target
    /// is resolved, so the record names no server, no tool and no tenant.
    pub(super) async fn answer_malformed(
        self,
        state: &AppState,
        id: RequestId,
        message: String,
    ) -> axum::response::Response {
        let refusal = Refusal {
            outcome: AuditOutcome::Invalid(INVALID_PARAMS),
            server: "",
            tool: None,
            tenants: BTreeSet::new(),
            context: RefusalContext {
                policy: IfUnwritten::FollowLog,
                kind: KindSource::Site(crate::security::decision_record::DecisionKind::Syntax),
                id: AnswerId::Present(id),
            },
        };
        self.record(
            state,
            refusal,
            INVALID_PARAMS,
            message,
            StatusCode::BAD_REQUEST,
        )
        .await
    }

    /// MIK-8382: record a keyed call with no execution principal refused at
    /// the `/mcp` intake as `invalid` with the error's code (the direct
    /// route's D2-a record of the same refusal), then answer it with HTTP 400.
    /// The intake runs before any target is mapped, so the record names the
    /// target as the request spells it: `gateway_invoke`'s server and tool,
    /// else no server and the called name.
    pub(super) async fn answer_intake(
        self,
        state: &AppState,
        (server, tool): (&str, &str),
        id: AnswerId,
        error: &crate::Error,
    ) -> axum::response::Response {
        let code = error.to_rpc_code();
        // The predicate needs an `id` member; a request without a usable one
        // is still answered, with no id, and recorded best-effort, as it has
        // been since before signing refusals shared this writer.
        let policy = match id {
            AnswerId::Present(_) => IfUnwritten::FollowLog,
            AnswerId::Absent | AnswerId::Unreadable | AnswerId::Later => IfUnwritten::AnswerAnyway,
        };
        let refusal = Refusal {
            outcome: AuditOutcome::Invalid(code),
            server,
            tool: Some(tool),
            tenants: BTreeSet::new(),
            context: RefusalContext {
                policy,
                // No execution principal: the caller's identity standing,
                // which no decision kind names yet.
                kind: KindSource::Site(crate::security::decision_record::DecisionKind::Unrecorded),
                id,
            },
        };
        self.record(
            state,
            refusal,
            code,
            error.to_string(),
            StatusCode::BAD_REQUEST,
        )
        .await
    }

    /// A signing refusal decided before admission (a nonce, or the invocation
    /// policy run at signing time): recorded with the code and outcome its
    /// error carries and the kind its site names, then answered as before,
    /// with the error's own code and words and HTTP 400, with or without an
    /// id; 503 when a fail-closed log could not record it.
    pub(super) async fn answer_signing(
        self,
        state: &AppState,
        called: &str,
        site: (AnswerId, SigningSite),
        error: crate::Error,
    ) -> axum::response::Response {
        let code = error.to_rpc_code();
        let message = crate::gateway::meta_mcp::signing::wire_error_message(&error);
        let refusal = signing_refusal(error, request_target(self.arguments, called), site);
        self.traced_for_grant()
            .record(state, refusal, code, message, StatusCode::BAD_REQUEST)
            .await
    }

    /// MIK-8361: record a requested target the caller may not see, refused
    /// by `code` at the route, which then takes the missing name's path. The
    /// record names the real reason, as every refusal's does; it is written
    /// best-effort (a failed write is counted, never answered), so an outage
    /// cannot tell a withheld name from a missing one (D3-a narrowed).
    ///
    /// The written record's trace, for the answer's delivery record.
    pub(super) async fn note_withheld(
        &self,
        state: &AppState,
        target: ToolTarget<'_>,
        code: i32,
    ) -> Option<String> {
        let tenants = state.meta_mcp.request_tenants(target.arguments);
        let refusal = Refusal {
            outcome: AuditOutcome::Denied(code),
            server: target.server,
            tool: Some(target.tool),
            tenants,
            context: RefusalContext {
                // D3-a narrowed: an outage must not tell a withheld name
                // from a missing one.
                policy: IfUnwritten::AnswerAnyway,
                kind: KindSource::NoteScope,
                id: AnswerId::Later,
            },
        };
        crate::security::security_metrics::meta_refused(code);
        match self
            .settle(&state.meta_mcp, state.transparency_log.as_ref(), refusal)
            .await
        {
            Settled::Recorded(trace) => Some(trace),
            // AnswerAnyway never settles Unavailable; a failed write was
            // logged with its trace id by `settle`.
            Settled::Unrecorded | Settled::Unavailable => None,
        }
    }

    /// Count, record and answer one refusal on `/mcp`, under its context's
    /// id and failure policy.
    async fn record(
        self,
        state: &AppState,
        refusal: Refusal<'_>,
        code: i32,
        message: String,
        status: StatusCode,
    ) -> axum::response::Response {
        // D4: every meta-route refusal decided before dispatch is counted
        // here, with or without a log; the meta layer never sees it.
        crate::security::security_metrics::meta_refused(code);
        let id = refusal.context.id.clone().frame_id();
        match self
            .settle(&state.meta_mcp, state.transparency_log.as_ref(), refusal)
            .await
        {
            Settled::Recorded(trace) => {
                let mut response = build_error_response(id, code, message, self.session_id, status);
                // Only a written record names a receipt; the frame's trace
                // may be the ambient one.
                #[cfg(feature = "webui")]
                response
                    .extensions_mut()
                    .insert(super::helpers::RefusalRecorded(trace.clone()));
                super::helpers::trace_error_frame(&mut response, trace);
                response
            }
            Settled::Unrecorded => build_error_response(id, code, message, self.session_id, status),
            Settled::Unavailable => {
                let error = crate::Error::AuditUnavailable;
                build_error_response(
                    id,
                    error.to_rpc_code(),
                    error.to_string(),
                    self.session_id,
                    StatusCode::SERVICE_UNAVAILABLE,
                )
            }
        }
    }

    /// The one place a refusal's failed write meets its policy: write the
    /// record, then settle how it is answered.
    async fn settle(
        &self,
        meta: &crate::gateway::meta_mcp::MetaMcp,
        log: Option<&std::sync::Arc<crate::security::TransparencyLogger>>,
        refusal: Refusal<'_>,
    ) -> Settled {
        let policy = refusal.context.policy;
        let (server, tool) = (refusal.server, refusal.tool.unwrap_or_default());
        let fails_closed =
            log.is_some_and(|log| log.failure_policy() == AuditFailurePolicy::FailClosed);
        match self.write(meta, log, refusal).await {
            None => Settled::Unrecorded,
            Some(Ok(trace)) => Settled::Recorded(trace),
            Some(Err(error)) if policy == IfUnwritten::FollowLog && fails_closed => {
                tracing::error!(%error, server, tool, "meta-route refusal audit write failed; answering unavailable");
                Settled::Unavailable
            }
            Some(Err(error)) => {
                // Counted by the log's own `mcp_audit_append_failures_total`;
                // named here with its trace id so the operator sees the gap.
                let trace_id = crate::gateway::trace::current().unwrap_or_default();
                tracing::warn!(%error, trace_id, server, tool, "refusal record write failed (non-fatal)");
                Settled::Unrecorded
            }
        }
    }

    /// The refusal record, written under the returned trace; `None` with no
    /// transparency log.
    async fn write(
        &self,
        meta: &crate::gateway::meta_mcp::MetaMcp,
        log: Option<&std::sync::Arc<crate::security::TransparencyLogger>>,
        refusal: Refusal<'_>,
    ) -> Option<Result<String, crate::Error>> {
        let mut noted = crate::gateway::meta_mcp::invoke::audit::take_route_noted();
        if !noted.has_refusal()
            && let KindSource::Site(kind) = refusal.context.kind
        {
            noted.refused(kind, None);
        }
        // The class every writer gives a refusal the gateway noted (the
        // meta writer's rule), so the counters and the record agree.
        let outcome = noted.refused_outcome(refusal.outcome);
        // Every router refusal is written here, with or without a
        // log, so the web UI's counters move here once per refused call.
        meta.count_call(
            refusal.server,
            refusal.tool,
            &self.who,
            crate::counters::Outcome::Audited {
                outcome,
                firewall: self.firewall,
                cache_hit: false,
            },
            // A router refusal: no send began.
            None,
        );
        let log = log?;
        let otel_trace_id = self
            .arguments
            .get("_meta")
            .and_then(crate::protocol::trace::TraceContext::from_meta)
            .and_then(|tc| tc.trace_id().map(str::to_string));
        // The trace the refusal's decision note was taken under, when the route
        // stage minted one (a step's authorization), so the two are one call.
        let trace_id = self
            .trace
            .clone()
            .or_else(crate::gateway::trace::current)
            .unwrap_or_else(crate::gateway::trace::generate);
        let envelope = AuditEnvelope {
            trace_id: Some(trace_id.clone()),
            otel_trace_id: otel_trace_id.clone(),
            outcome,
            who: self.who.clone(),
        };
        let request_hash = format!(
            "sha256:{}",
            crate::hashing::canonical_json_sha256(self.arguments)
        );
        let server = refusal.server.to_string();
        let tool = refusal.tool.map(str::to_string);
        let attribution = DispatchNotes::default().attribution(meta, refusal.tenants, None);
        let decision = Box::new(
            noted.decision(
                crate::security::decision_record::Decided::Fresh,
                crate::security::decision_record::Refused::of(outcome),
                meta.live_config().as_deref(),
                self.who
                    .credential_kind
                    .unwrap_or(crate::security::audit::CredentialKind::None),
            ),
        );
        let session = self.session_id.to_string();
        let recorded = trace_id.clone();
        // Taken here: the blocking append below has no task-locals. Run only
        // after the append returned Ok, so a failed write marks nothing.
        let landed = crate::gateway::meta_mcp::grant_audit::invocation_landing();
        // The meta writer's correlation ladder; a modern call's session is
        // `""`, so it falls to the minted trace id (MIK-7640).
        let written = log
            .append_bounded(move |log| {
                let key =
                    CorrelationKey::ladder(otel_trace_id.as_deref(), Some(&session), &trace_id);
                let appended = log.log_invocation_attributed(
                    key,
                    &envelope,
                    InvocationTarget {
                        route: InvocationRoute::Meta,
                        server: &server,
                        tool: tool.as_deref(),
                    },
                    &request_hash,
                    None,
                    attribution,
                    Some(decision.as_ref()),
                );
                if appended.is_ok() {
                    landed.land(&trace_id);
                }
                appended
            })
            .await;
        Some(written.map(|()| recorded).map_err(Into::into))
    }
}

#[cfg(tp1)]
#[cfg(test)]
#[path = "meta_refusal_audit_tests.rs"]
mod tests;
