// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One egress scan (design `docs/internal/design/2026-10-08-one-egress-scan.md`):
//! every frame carrying a backend's text passes here before a client reads
//! it, on every route, once. It decides which parts a frame has and how each
//! is screened, so no caller picks a method list or a mutation policy.

use serde_json::Value;

use super::super::MetaMcp;
use crate::protocol::{JsonRpcError, JsonRpcResponse};
use crate::security::response_policy::{ResponseCorrelation, ResponsePolicyTarget};

/// The delivery refusal a screened-out frame becomes, on every route.
pub(crate) const REFUSAL: &str = "Response blocked by security firewall";

/// Whether a result part still owes the content checks (inspection and
/// context integrity). Every call site states it: a `tools/call` result met
/// them at dispatch, with the tool's own capability flags, on every route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentChecks {
    /// Dispatch ran them on this result; running them again audits it twice.
    Dispatched,
    /// Nothing ran them yet: this scan does.
    Here,
}

impl ContentChecks {
    /// The usual answer for a frame answering `method`.
    pub(crate) fn for_method(method: &str) -> Self {
        if method == "tools/call" {
            Self::Dispatched
        } else {
            Self::Here
        }
    }
}

/// The firewall a route is judged by. Without the `firewall` feature it is
/// uninhabited, so every `Option` of it is `None` and the code that carries
/// one compiles in every build.
#[cfg(feature = "firewall")]
pub(crate) type Firewall = crate::security::firewall::Firewall;
#[cfg(not(feature = "firewall"))]
pub(crate) type Firewall = std::convert::Infallible;

/// Where a frame is going: whether it owes the content checks, and the policy
/// targets and correlation its firewall verdict is evaluated under.
pub(crate) struct Egress<'a> {
    /// Whether a result part still owes the content checks (an error part
    /// always meets them: no dispatch gate reads errors).
    pub(crate) content: ContentChecks,
    /// The targets the firewall evaluates; never empty.
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    pub(crate) targets: &'a [ResponsePolicyTarget],
    pub(crate) correlation: &'a ResponseCorrelation<'a>,
    /// The caller's key name, for context integrity's subject.
    pub(crate) api_key_name: Option<&'a str>,
    /// The firewall instance that judges this route: the router's on the
    /// direct route (its own audit and rules, MIK-7669), the Meta-MCP's on
    /// every other.
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    pub(crate) firewall: Option<&'a Firewall>,
}

/// What the scan did to a frame, in increasing strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EgressOutcome {
    /// Nothing acted on it.
    Delivered,
    /// A finding was redacted in place; the frame is delivered. Only the
    /// firewall redacts, so a build without it never constructs this.
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    Rewritten,
    /// A policy refused it; the frame is now the delivery refusal.
    Refused,
}

impl MetaMcp {
    /// Screen every part `frame` carries, once. A frame already scanned
    /// (`egress_scanned`: an earlier exit, or a discovery answer inspected on
    /// its canonical value) is left as it is. A refusal replaces the frame with
    /// [`REFUSAL`], keeping its id.
    pub(crate) fn scan_egress(
        &self,
        frame: &mut JsonRpcResponse,
        at: &Egress<'_>,
    ) -> EgressOutcome {
        if frame.egress_scanned {
            return EgressOutcome::Delivered;
        }
        // Both parts, when a peer sent both: neither may ride past the other.
        let mut outcome = EgressOutcome::Delivered;
        if let Some(result) = frame.result.as_mut() {
            outcome = outcome.max(self.scan_result(result, at));
        }
        if outcome != EgressOutcome::Refused
            && let Some(error) = frame.error.as_mut()
        {
            outcome = outcome.max(self.scan_error(error, at));
        }
        if outcome == EgressOutcome::Refused {
            *frame = JsonRpcResponse::delivery_refusal_error(frame.id.take(), -32600, REFUSAL);
        }
        frame.egress_scanned = true;
        outcome
    }
}

impl MetaMcp {
    /// A result part: content checks unless dispatch already ran them, then
    /// the firewall under the part's own policy. A redaction rebuilds the
    /// relay receipt from what is delivered.
    fn scan_result(&self, result: &mut Value, at: &Egress<'_>) -> EgressOutcome {
        // A `tools/call` result passed the content gates at dispatch, on
        // every route, with the tool's own capability flags; running them
        // again would audit it twice. Every other answer meets them here.
        if at.content == ContentChecks::Here && self.content_refuses(at, result) {
            return EgressOutcome::Refused;
        }
        let snapshot = self.relay_snapshot(result);
        let outcome = firewall_result(result, at);
        let shape = super::relay::AnswerShape::of(at.correlation.external_tool);
        self.restage_if_changed(snapshot, Some(&*result), shape);
        outcome
    }

    /// An error part: its message and data meet the content checks and the
    /// firewall as one artifact. A redaction is written back; one that leaves
    /// no text message refuses.
    fn scan_error(&self, error: &mut JsonRpcError, at: &Egress<'_>) -> EgressOutcome {
        let fields = serde_json::json!({"message": error.message, "data": error.data});
        if self.content_refuses(at, &fields) {
            return EgressOutcome::Refused;
        }
        #[cfg(feature = "firewall")]
        if let Some(firewall) = at.firewall {
            use crate::security::response_policy::{ResponseArtifactKind, ResponseMutationPolicy};
            let mut artifact = fields.clone();
            let verdict = firewall.check_response_artifact(
                &mut artifact,
                at.targets,
                at.correlation,
                ResponseArtifactKind::FinalResponse,
                ResponseMutationPolicy::Redact,
            );
            // Rewritten only when the redactor changed a field: a finding it
            // let through untouched leaves the backend's error as sent.
            if firewall_outcome(verdict) == EgressOutcome::Refused {
                return EgressOutcome::Refused;
            }
            if artifact == fields {
                return EgressOutcome::Delivered;
            }
            let Some(message) = artifact["message"].as_str() else {
                return EgressOutcome::Refused;
            };
            message.clone_into(&mut error.message);
            if error.data.is_some() {
                error.data = artifact.as_object_mut().and_then(|a| a.remove("data"));
            }
            return EgressOutcome::Rewritten;
        }
        EgressOutcome::Delivered
    }

    /// The content inspection and context integrity on every decoded string
    /// and key of `value`: decoded, not serialized, so escaping cannot hide a
    /// quoted credential or a newline-split instruction.
    fn content_refuses(&self, at: &Egress<'_>, value: &Value) -> bool {
        let mut text = String::new();
        decoded_text(value, &mut text);
        let (server, tool) = (at.correlation.external_server, at.correlation.external_tool);
        let trace_id = at.correlation.session_id;
        if self
            .inspect_backend_text((server, tool, trace_id), &text)
            .is_err()
        {
            return true;
        }
        // A carrier it withheld or transformed cannot map back onto the
        // frame's fields, so enforcement refuses the whole frame.
        let carrier = serde_json::json!({"content": [{"type": "text", "text": text}]});
        self.context_integrity_enforces((server, tool), at.api_key_name, trace_id, &carrier)
    }
}

/// The firewall on a result part under the part's own policy, without
/// the relay receipt: a task settles its receipt itself.
pub(crate) fn firewall_result(result: &mut Value, at: &Egress<'_>) -> EgressOutcome {
    #[cfg(feature = "firewall")]
    if let Some(firewall) = at.firewall {
        use crate::security::response_policy::{ResponseArtifactKind, ResponseMutationPolicy};
        let verdict = firewall.check_response_artifact(
            result,
            at.targets,
            at.correlation,
            ResponseArtifactKind::FinalResponse,
            ResponseMutationPolicy::for_result(result),
        );
        return firewall_outcome(verdict);
    }
    #[cfg(not(feature = "firewall"))]
    let _ = (result, at);
    EgressOutcome::Delivered
}

/// A firewall verdict as an outcome: a refusal or a missing target refuses,
/// a finding it let through was redacted.
#[cfg(feature = "firewall")]
fn firewall_outcome(
    verdict: Result<
        crate::security::firewall::FirewallVerdict,
        crate::security::response_policy::InvalidResponseTargets,
    >,
) -> EgressOutcome {
    use crate::security::firewall::FirewallAction;
    match verdict {
        Ok(v) if v.allowed && v.action != FirewallAction::Block => {
            if v.findings.is_empty() {
                EgressOutcome::Delivered
            } else {
                EgressOutcome::Rewritten
            }
        }
        _ => EgressOutcome::Refused,
    }
}

/// Every string value and object key in `value`, one per line, appended to
/// `out`.
pub(super) fn decoded_text(value: &Value, out: &mut String) {
    match value {
        Value::String(text) => {
            out.push('\n');
            out.push_str(text);
        }
        Value::Array(items) => items.iter().for_each(|item| decoded_text(item, out)),
        Value::Object(members) => {
            for (key, item) in members {
                out.push('\n');
                out.push_str(key);
                decoded_text(item, out);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

impl MetaMcp {
    /// The egress scan of a backend error held outside a frame (a task's
    /// recovered failure, before it is stored): `server`/`tool` the target.
    pub(crate) fn scan_backend_error(
        &self,
        (server, tool, trace_id): (&str, &str, &str),
        api_key_name: Option<&str>,
        error: &mut JsonRpcError,
    ) -> EgressOutcome {
        let targets = [ResponsePolicyTarget {
            server: server.to_owned(),
            tool: tool.to_owned(),
        }];
        let correlation = ResponseCorrelation {
            session_id: trace_id,
            caller: api_key_name.unwrap_or("anonymous"),
            external_server: server,
            external_tool: tool,
            subject: None,
        };
        let at = Egress {
            content: ContentChecks::Here,
            targets: &targets,
            correlation: &correlation,
            api_key_name,
            firewall: self.firewall.as_deref(),
        };
        self.scan_error(error, &at)
    }

    /// Whether `e`, when it carries a backend's JSON-RPC error, passes the
    /// scan untouched; any other error is the gateway's own.
    pub(crate) fn backend_error_screens_clean(
        &self,
        server: &str,
        tool: &str,
        e: &crate::Error,
    ) -> bool {
        let crate::Error::JsonRpc {
            code,
            message,
            data,
        } = e
        else {
            return true;
        };
        let mut error = JsonRpcError {
            code: *code,
            message: message.clone(),
            data: data.clone(),
        };
        self.scan_backend_error((server, tool, tool), None, &mut error) == EgressOutcome::Delivered
    }
}

/// The screen a notification sink carries (MIK-8161): each notification a
/// backend streams during a call meets the egress scan's content checks and
/// firewall on its params before it is queued for the client.
struct NotificationEgress {
    meta: std::sync::Arc<MetaMcp>,
    caller: String,
    session_id: String,
    /// The caller and session the dispatch bound once it authenticated them;
    /// the labels above until then.
    bound: std::sync::OnceLock<(String, String)>,
}

impl crate::transport::notification_sink::NotificationScreen for NotificationEgress {
    fn bind(&self, caller: &str, session_id: &str) {
        let _ = self.bound.set((caller.to_owned(), session_id.to_owned()));
    }

    fn admit(&self, notification: &mut crate::protocol::JsonRpcNotification) -> bool {
        let (caller, session_id) = self.bound.get().map_or(
            (self.caller.as_str(), self.session_id.as_str()),
            |(c, s)| (c.as_str(), s.as_str()),
        );
        let method = notification.method.clone();
        let targets = [ResponsePolicyTarget {
            server: "gateway".to_owned(),
            tool: method.clone(),
        }];
        let correlation = ResponseCorrelation {
            session_id,
            caller,
            external_server: "gateway",
            external_tool: &method,
            subject: None,
        };
        let at = Egress {
            content: ContentChecks::Here,
            targets: &targets,
            correlation: &correlation,
            api_key_name: None,
            firewall: self.meta.firewall.as_deref(),
        };
        self.meta.scan_notification(notification, &at) != EgressOutcome::Refused
    }
}

impl MetaMcp {
    /// The notification screen for one client's scope: `caller` and
    /// `session_id` label its verdicts.
    pub(crate) fn notification_screen(
        self: &std::sync::Arc<Self>,
        caller: &str,
        session_id: &str,
    ) -> std::sync::Arc<dyn crate::transport::notification_sink::NotificationScreen> {
        std::sync::Arc::new(NotificationEgress {
            meta: std::sync::Arc::clone(self),
            caller: caller.to_owned(),
            session_id: session_id.to_owned(),
            bound: std::sync::OnceLock::new(),
        })
    }

    /// A notification's method and params, one artifact: content checks,
    /// then the firewall under `Redact`. A redaction of the params stays in
    /// place; one that would change the method, or a refusal, withholds it.
    fn scan_notification(
        &self,
        notification: &mut crate::protocol::JsonRpcNotification,
        at: &Egress<'_>,
    ) -> EgressOutcome {
        let fields = serde_json::json!({
            "method": notification.method,
            "params": notification.params,
        });
        if self.content_refuses(at, &fields) {
            return EgressOutcome::Refused;
        }
        #[cfg(feature = "firewall")]
        if let Some(firewall) = at.firewall {
            use crate::security::response_policy::{ResponseArtifactKind, ResponseMutationPolicy};
            let mut artifact = fields.clone();
            let verdict = firewall.check_response_artifact(
                &mut artifact,
                at.targets,
                at.correlation,
                ResponseArtifactKind::Notification,
                ResponseMutationPolicy::Redact,
            );
            if firewall_outcome(verdict) == EgressOutcome::Refused
                || artifact["method"] != fields["method"]
            {
                return EgressOutcome::Refused;
            }
            if artifact == fields {
                return EgressOutcome::Delivered;
            }
            // JSON-RPC omits absent params rather than sending `null`.
            notification.params = artifact
                .as_object_mut()
                .and_then(|a| a.remove("params"))
                .filter(|params| !params.is_null());
            return EgressOutcome::Rewritten;
        }
        EgressOutcome::Delivered
    }
}

/// A frame cleared for a client writer. `build_http_response` takes only this,
/// so every exit decides: a frame the egress scan saw, or one the gateway
/// built with no backend text in it.
#[must_use]
pub(crate) struct Egressed(JsonRpcResponse);

impl Egressed {
    /// A frame the egress scan marked. One it never saw is refused rather
    /// than written, so an exit that skips the scan fails closed.
    pub(crate) fn of(frame: JsonRpcResponse) -> Self {
        if frame.egress_scanned {
            return Self(frame);
        }
        tracing::error!("a frame that skipped the egress scan reached a writer; refused");
        Self(JsonRpcResponse::delivery_refusal_error(
            frame.id, -32600, REFUSAL,
        ))
    }

    /// A frame the gateway built carrying no backend text: a refusal before
    /// dispatch, a parse or version error, a gateway notice.
    pub(crate) fn gateway_own(frame: JsonRpcResponse) -> Self {
        Self(frame)
    }

    /// The frame to write.
    pub(crate) fn frame(&self) -> &JsonRpcResponse {
        &self.0
    }
}

/// The targets a stored task is judged under: the calls that produced it, so
/// a rule on the original tool governs every later read; the gateway's task
/// read when the row recorded none.
fn stored_targets(task: &crate::gateway::task_service::CommittedTask) -> Vec<ResponsePolicyTarget> {
    let recorded: Vec<_> = task
        .targets
        .iter()
        .map(|t| ResponsePolicyTarget {
            server: t.server.clone(),
            tool: t.tool.clone(),
        })
        .collect();
    if recorded.is_empty() {
        vec![ResponsePolicyTarget {
            server: "gateway".to_owned(),
            tool: "tasks/get".to_owned(),
        }]
    } else {
        recorded
    }
}

impl MetaMcp {
    /// A stored task's output, about to be read again (`tasks/get`, a
    /// `notifications/tasks` frame): the egress scan's result step under its
    /// recorded targets, so a policy tightened since settlement covers every
    /// read. Its content gates ran when its call was dispatched.
    pub(crate) fn scan_stored_task(
        &self,
        task: &crate::gateway::task_service::CommittedTask,
        value: &mut Value,
    ) -> EgressOutcome {
        let targets = stored_targets(task);
        let (server, tool) = (targets[0].server.as_str(), targets[0].tool.as_str());
        let correlation = ResponseCorrelation {
            session_id: "task-read",
            caller: "task",
            external_server: server,
            external_tool: tool,
            subject: None,
        };
        let at = Egress {
            content: ContentChecks::Dispatched,
            targets: &targets,
            correlation: &correlation,
            api_key_name: None,
            firewall: self.firewall.as_deref(),
        };
        firewall_result(value, &at)
    }

    /// [`Self::scan_stored_task`] on a `tasks/get` answer: a refusal becomes
    /// the delivery refusal, and the frame is marked so delivery skips it.
    pub(crate) fn scan_task_read(
        &self,
        task: &crate::gateway::task_service::CommittedTask,
        frame: &mut JsonRpcResponse,
    ) {
        let refused = frame
            .result
            .as_mut()
            .is_some_and(|value| self.scan_stored_task(task, value) == EgressOutcome::Refused);
        if refused {
            *frame = JsonRpcResponse::delivery_refusal_error(frame.id.take(), -32600, REFUSAL);
        }
        frame.egress_scanned = true;
    }
}

impl MetaMcp {
    /// Inspect a `gateway_list_tools` / `gateway_search_tools` result once, on
    /// the canonical value before it is serialised into `content[].text`
    /// (OWASP ASI01 tool-poisoning, #2350): the content checks and the
    /// firewall, the whole egress scan of a result. Detectors see the raw
    /// strings: an escaped copy hides a quoted key or a split injection phrase
    /// from them. A refusal refuses the call; otherwise credentials are
    /// redacted in place. The discovery arm then marks its response
    /// (`JsonRpcResponse::egress_scanned`, set after the meta-tool match,
    /// never on a direct-name route), and every later exit skips only a marked
    /// response: the mark, not the tool name, proves this pass ran. Every Ok
    /// path of the three discovery handlers must call this.
    ///
    /// # Errors
    /// [`crate::Error::ResponseFirewallRefused`] when the scan refuses.
    pub(in crate::gateway) fn inspect_discovery_value(
        &self,
        value: &mut Value,
    ) -> crate::Result<()> {
        let targets = [ResponsePolicyTarget {
            server: "gateway".to_owned(),
            tool: "tools/list".to_owned(),
        }];
        let correlation = ResponseCorrelation {
            session_id: "meta:tools/list",
            caller: "meta-mcp",
            external_server: "gateway",
            external_tool: "tools/list",
            subject: None,
        };
        let at = Egress {
            content: ContentChecks::Here,
            targets: &targets,
            correlation: &correlation,
            api_key_name: None,
            firewall: self.firewall.as_deref(),
        };
        if self.content_refuses(&at, value) || firewall_result(value, &at) == EgressOutcome::Refused
        {
            tracing::warn!("Egress scan: discovery response refused");
            return Err(crate::Error::ResponseFirewallRefused);
        }
        Ok(())
    }
}

impl MetaMcp {
    /// The content checks on a value the gateway built from a backend's text
    /// before dispatch (a key refusal naming its schema's parameters), which
    /// no dispatch gate reads.
    pub(crate) fn content_refuses_value(
        &self,
        (server, tool): (&str, &str),
        session_id: Option<&str>,
        value: &Value,
    ) -> bool {
        let targets = [ResponsePolicyTarget {
            server: server.to_owned(),
            tool: tool.to_owned(),
        }];
        let correlation = ResponseCorrelation {
            session_id: session_id.unwrap_or(tool),
            caller: "gateway",
            external_server: server,
            external_tool: tool,
            subject: None,
        };
        let at = Egress {
            content: ContentChecks::Here,
            targets: &targets,
            correlation: &correlation,
            api_key_name: None,
            firewall: self.firewall.as_deref(),
        };
        self.content_refuses(&at, value)
    }
}
