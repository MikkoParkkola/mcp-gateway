// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Context-integrity guard for the non-`tools/call` content paths.
//!
//! `resources/read` and `prompts/get` return backend-authored content to the
//! agent exactly as `tools/call` does, but they do not run through the invoke
//! pipeline, so until MIK-7116 they never reached the kernel: no
//! classification, no summarising transform, no `_context_integrity` audit
//! record. This is the shared point for both — a new content path routes
//! through here rather than growing its own copy of the policy.

use serde_json::{Value, json};

use super::MetaMcp;
use crate::context_integrity::{
    ContextIntegrityDecisionKind, ContextIntegrityEvaluation, ContextIntegrityInput,
    ContextProvenance, ContextTrustBoundary,
};

/// The MCP envelope a guarded payload is rebuilt into when the kernel refuses
/// to pass it through whole. The transform delivers a bare string, and the
/// two paths spell "one piece of text" differently.
pub(super) enum GuardedEnvelope<'a> {
    /// `resources/read` — `{"contents": [...]}`, entries keyed by URI.
    Resource { uri: &'a str },
    /// `prompts/get` — `{"messages": [...]}`.
    Prompt,
}

impl GuardedEnvelope<'_> {
    fn rebuild(&self, text: &str) -> Value {
        // Rebuilt, never patched. The kernel has just judged this payload
        // untrusted, so any field carried over from the backend is one the
        // enforcement never inspected.
        match self {
            Self::Resource { uri } => json!({
                "contents": [{"uri": uri, "mimeType": "text/plain", "text": text}]
            }),
            Self::Prompt => json!({
                "messages": [{"role": "user", "content": {"type": "text", "text": text}}]
            }),
        }
    }
}

impl MetaMcp {
    /// Run backend-authored content through the context-integrity kernel and
    /// return what the agent is allowed to see, carrying the audit record.
    ///
    /// A read of a resource or a prompt is a read: `read_only`, low action
    /// risk. `subject` is the caller identity when the path resolves one —
    /// these handlers take no caller context today, so the audit record names
    /// the origin without attributing it (MIK-7116.MIN.1 is a signature
    /// change through the router, tracked separately).
    pub(super) fn guard_backend_content(
        &self,
        server: &str,
        producer: &str,
        invocation_id: &str,
        subject: Option<&str>,
        envelope: &GuardedEnvelope<'_>,
        result: Value,
    ) -> Value {
        let mut provenance = ContextProvenance::tool_result(
            server,
            producer,
            invocation_id,
            ContextTrustBoundary::RemoteToolOutput,
        );
        provenance.subject = subject.map(str::to_string);
        provenance.origin = Some(format!("{server}:{producer}"));

        let evaluation = self.context_integrity_kernel.read().evaluate(
            ContextIntegrityInput::read_only_tool_result(provenance, result.clone()),
        );

        // Clean content on an Allow decision leaves as it arrived: an audit
        // record on every uneventful document read is noise that buries the
        // records that matter.
        if evaluation.classification.findings.is_empty()
            && evaluation.policy.would_decision == ContextIntegrityDecisionKind::Allow
        {
            return result;
        }

        let delivered = if evaluation.policy.enforcement_applied {
            envelope.rebuild(&delivered_text(&evaluation))
        } else {
            result
        };
        attach_audit(delivered, &evaluation)
    }
}

/// The text the kernel allows through: its transform when there is one, the
/// refusal rationale when the decision withholds content entirely.
fn delivered_text(evaluation: &ContextIntegrityEvaluation) -> String {
    let Some(delivered) = evaluation.transformed.delivered.as_ref() else {
        return format!(
            "Content withheld by ContextIntegrityKernel: {}",
            evaluation.policy.rationale
        );
    };
    delivered
        .as_str()
        .map_or_else(|| delivered.to_string(), str::to_string)
}

fn attach_audit(mut result: Value, evaluation: &ContextIntegrityEvaluation) -> Value {
    let metadata = evaluation.audit_metadata();
    if let Some(obj) = result.as_object_mut() {
        obj.insert("_context_integrity".to_string(), metadata);
        result
    } else {
        json!({"structuredContent": result, "_context_integrity": metadata})
    }
}
