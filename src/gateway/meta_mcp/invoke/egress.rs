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

/// Where a frame is going: the method it answers and the policy targets and
/// correlation its firewall verdict is evaluated under.
pub(crate) struct Egress<'a> {
    /// The method the frame answers (the client's, not a meta-tool's).
    pub(crate) method: &'a str,
    /// The targets the firewall evaluates; never empty.
    pub(crate) targets: &'a [ResponsePolicyTarget],
    pub(crate) correlation: &'a ResponseCorrelation<'a>,
    /// The caller's key name, for context integrity's subject.
    pub(crate) api_key_name: Option<&'a str>,
}

/// What the scan did to a frame, in increasing strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EgressOutcome {
    /// Nothing acted on it.
    Delivered,
    /// A finding was redacted in place; the frame is delivered.
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
        if at.method != "tools/call" && self.content_refuses(at, result) {
            return EgressOutcome::Refused;
        }
        let snapshot = self.relay_snapshot(result);
        let outcome = self.firewall_result(result, at);
        let shape = super::relay::AnswerShape::of(at.correlation.external_tool);
        self.restage_if_changed(snapshot, Some(&*result), shape);
        outcome
    }

    /// The firewall on a result part under the part's own policy, without
    /// the relay receipt: a task settles its receipt itself.
    pub(crate) fn firewall_result(&self, result: &mut Value, at: &Egress<'_>) -> EgressOutcome {
        #[cfg(feature = "firewall")]
        if let Some(firewall) = &self.firewall {
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

    /// An error part: its message and data meet the content checks and the
    /// firewall as one artifact. A redaction is written back; one that leaves
    /// no text message refuses.
    fn scan_error(&self, error: &mut JsonRpcError, at: &Egress<'_>) -> EgressOutcome {
        let fields = serde_json::json!({"message": error.message, "data": error.data});
        if self.content_refuses(at, &fields) {
            return EgressOutcome::Refused;
        }
        #[cfg(feature = "firewall")]
        if let Some(firewall) = &self.firewall {
            use crate::security::response_policy::{ResponseArtifactKind, ResponseMutationPolicy};
            let mut artifact = fields;
            let verdict = firewall.check_response_artifact(
                &mut artifact,
                at.targets,
                at.correlation,
                ResponseArtifactKind::FinalResponse,
                ResponseMutationPolicy::Redact,
            );
            let outcome = firewall_outcome(verdict);
            if outcome != EgressOutcome::Rewritten {
                return outcome;
            }
            let Some(message) = artifact["message"].as_str() else {
                return EgressOutcome::Refused;
            };
            message.clone_into(&mut error.message);
            if error.data.is_some() {
                error.data = artifact.as_object_mut().and_then(|a| a.remove("data"));
            }
            return outcome;
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
        let (_, effect) =
            self.apply_context_integrity(server, tool, at.api_key_name, trace_id, carrier);
        effect == super::super::response_security::GateEffect::Enforced
    }
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
            method: tool,
            targets: &targets,
            correlation: &correlation,
            api_key_name,
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
}

impl crate::transport::notification_sink::NotificationScreen for NotificationEgress {
    fn admit(&self, notification: &mut crate::protocol::JsonRpcNotification) -> bool {
        let method = notification.method.clone();
        let Some(params) = notification.params.as_mut() else {
            return true;
        };
        let targets = [ResponsePolicyTarget {
            server: "gateway".to_owned(),
            tool: method.clone(),
        }];
        let correlation = ResponseCorrelation {
            session_id: &self.session_id,
            caller: &self.caller,
            external_server: "gateway",
            external_tool: &method,
            subject: None,
        };
        let at = Egress {
            method: &method,
            targets: &targets,
            correlation: &correlation,
            api_key_name: None,
        };
        self.meta.scan_notification(params, &at) != EgressOutcome::Refused
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
        })
    }

    /// A notification's params: content checks, then the firewall under
    /// `Redact`; a redaction stays in place, a refusal withholds it.
    fn scan_notification(&self, params: &mut Value, at: &Egress<'_>) -> EgressOutcome {
        if self.content_refuses(at, params) {
            return EgressOutcome::Refused;
        }
        #[cfg(feature = "firewall")]
        if let Some(firewall) = &self.firewall {
            use crate::security::response_policy::{ResponseArtifactKind, ResponseMutationPolicy};
            let verdict = firewall.check_response_artifact(
                params,
                at.targets,
                at.correlation,
                ResponseArtifactKind::Notification,
                ResponseMutationPolicy::Redact,
            );
            return firewall_outcome(verdict);
        }
        EgressOutcome::Delivered
    }
}
