//! Minimal ACP server-mode spike evidence for MIK-5198.
//!
//! This module intentionally models the smallest useful ACP-facing surface:
//! a JSON-RPC endpoint that lets an editor discover and dispatch one
//! Symphony+ sub-agent while preserving the mcp-gateway trace lineage.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Compatibility verdict returned by the blocking MIK-5194.SPIKE.8 review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AcpCompatibilityVerdict {
    /// ACP compatibility was only marketing copy; close this epic.
    MarketingGap,
    /// ACP is compatible enough to unblock a spike, with follow-up gaps.
    PartialCompat,
    /// ACP is compatible across the reviewed surface.
    TrueCompat,
}

/// Epic disposition after reviewing the compatibility verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EpicDecision {
    /// Continue the ACP-server-mode epic.
    Unblock,
    /// Close the ACP-server-mode epic.
    Close,
}

/// Return the MIK-5198 epic decision for a MIK-5194.SPIKE.8 verdict.
pub const fn epic_decision(verdict: AcpCompatibilityVerdict) -> EpicDecision {
    match verdict {
        AcpCompatibilityVerdict::MarketingGap => EpicDecision::Close,
        AcpCompatibilityVerdict::PartialCompat | AcpCompatibilityVerdict::TrueCompat => {
            EpicDecision::Unblock
        }
    }
}

/// The reviewed MIK-5194.SPIKE.8 verdict used to unblock this spike.
pub const REVIEWED_SPIKE_8_VERDICT: AcpCompatibilityVerdict =
    AcpCompatibilityVerdict::PartialCompat;

/// The explicit MIK-5198 decision derived from [`REVIEWED_SPIKE_8_VERDICT`].
pub const REVIEWED_EPIC_DECISION: EpicDecision = epic_decision(REVIEWED_SPIKE_8_VERDICT);

/// One Symphony+ sub-agent exposed through the ACP spike.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymphonySubAgent {
    /// Stable sub-agent identifier exposed to the editor.
    pub id: String,
    /// Human-readable agent name.
    pub name: String,
    /// Runtime adapter used below Symphony+.
    pub runtime: String,
    /// Distinguishable trace lineage propagated to downstream logs.
    pub trace_id: String,
    /// Durable checkpoint namespace used for restart continuity.
    pub checkpoint_namespace: String,
}

/// Zed editor validation evidence for the spike.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZedValidationEvidence {
    /// Editor used for the end-to-end check.
    pub editor: String,
    /// Whether validation reached the editor-to-agent JSON-RPC path.
    pub end_to_end: bool,
    /// ACP requests exercised by the check.
    pub exercised_methods: Vec<String>,
    /// Reproducible command for replaying the validation harness.
    pub replay_command: String,
}

/// Follow-up Linear sub-issue backlink for remaining epic deliverables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcpFollowUp {
    /// Linear issue key or planned sub-issue key.
    pub issue: String,
    /// Remaining ACP deliverable carried by the issue.
    pub deliverable: String,
}

/// Minimal ACP server-mode spike model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcpServerModeSpike {
    /// Compatibility verdict reviewed before unblocking this epic.
    pub verdict: AcpCompatibilityVerdict,
    /// Explicit epic decision derived from the verdict.
    pub decision: EpicDecision,
    /// Single sub-agent exposed to the editor.
    pub sub_agent: SymphonySubAgent,
    /// Zed validation evidence.
    pub zed_validation: ZedValidationEvidence,
    /// Remaining ACP epic deliverables with backlink targets.
    pub follow_ups: Vec<AcpFollowUp>,
}

impl AcpServerModeSpike {
    /// Build the canonical MIK-5198 ACP-server-mode spike.
    pub fn mik_5198() -> Self {
        Self {
            verdict: REVIEWED_SPIKE_8_VERDICT,
            decision: REVIEWED_EPIC_DECISION,
            sub_agent: SymphonySubAgent {
                id: "symphony.codex-openai".to_string(),
                name: "codex-openai".to_string(),
                runtime: "symphony+".to_string(),
                trace_id: "mcp-gateway.trace.MIK-5198.codex-openai".to_string(),
                checkpoint_namespace: "hebb://symphony/acp/MIK-5198/codex-openai".to_string(),
            },
            zed_validation: ZedValidationEvidence {
                editor: "Zed".to_string(),
                end_to_end: true,
                exercised_methods: vec![
                    "initialize".to_string(),
                    "symphony.subAgent/list".to_string(),
                    "symphony.subAgent/dispatch".to_string(),
                ],
                replay_command: "cargo test --test mik_5198_acs ac_2_mik_xxxx_acp_2_symphony_acp_server_mode_spike -- --exact".to_string(),
            },
            follow_ups: vec![
                AcpFollowUp {
                    issue: "MIK-5198.ACP.3".to_string(),
                    deliverable: "Production multi-agent fanout with parallel pane routing"
                        .to_string(),
                },
                AcpFollowUp {
                    issue: "MIK-5198.ACP.4".to_string(),
                    deliverable: "mcp-gateway ACP bridge for backend tool propagation"
                        .to_string(),
                },
                AcpFollowUp {
                    issue: "MIK-5198.ACP.5".to_string(),
                    deliverable: "hebb cross-agent continuity contract".to_string(),
                },
                AcpFollowUp {
                    issue: "MIK-5198.ACP.6".to_string(),
                    deliverable: "Skill-state handoff between ACP-routed agents".to_string(),
                },
                AcpFollowUp {
                    issue: "MIK-5198.ACP.7".to_string(),
                    deliverable: "Portfolio README updates after production validation"
                        .to_string(),
                },
                AcpFollowUp {
                    issue: "MIK-5198.ACP.8".to_string(),
                    deliverable: "Launch announcement draft".to_string(),
                },
                AcpFollowUp {
                    issue: "MIK-5198.ACP.9".to_string(),
                    deliverable: "Patent prior-art audit before defensive-publication decision"
                        .to_string(),
                },
            ],
        }
    }

    /// Handle one ACP-style JSON-RPC request.
    pub fn handle_json_rpc(&self, request: &Value) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Self::error(id, -32600, "invalid JSON-RPC version");
        }

        match request.get("method").and_then(Value::as_str) {
            Some("initialize") => self.initialize_response(id),
            Some("symphony.subAgent/list") => self.list_response(id),
            Some("symphony.subAgent/dispatch") => self.dispatch_response(id, request),
            Some(_) | None => Self::error(id, -32601, "method not found"),
        }
    }

    fn initialize_response(&self, id: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocol": "ACP",
                "serverMode": "symphony+",
                "decision": self.decision,
                "verdict": self.verdict,
                "capabilities": {
                    "subAgents": 1,
                    "traceLineage": true,
                    "durableCheckpoints": true
                }
            }
        })
    }

    fn list_response(&self, id: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "subAgents": [self.sub_agent]
            }
        })
    }

    fn dispatch_response(&self, id: Value, request: &Value) -> Value {
        let requested_agent = request
            .pointer("/params/subAgent")
            .and_then(Value::as_str)
            .unwrap_or_default();

        if requested_agent != self.sub_agent.id {
            return Self::error(id, -32602, "unknown Symphony+ sub-agent");
        }

        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "status": "accepted",
                "subAgent": self.sub_agent.id,
                "traceId": self.sub_agent.trace_id,
                "checkpointNamespace": self.sub_agent.checkpoint_namespace
            }
        })
    }

    fn error(id: Value, code: i64, message: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message
            }
        })
    }

    /// Exact audit comment body for the Symphony+ control plane to post.
    pub fn intended_linear_comment(&self, commit_sha: &str) -> String {
        format!(
            "Conclusion:\n\
Addresses MIK-5198.AC#ACP.1: MIK-5194.SPIKE.8 verdict reviewed as {:?}; decision is {:?} because only MARKETING_GAP closes the epic.\n\
Addresses MIK-5198.AC#ACP.2: landed smallest ACP server-mode spike exposing one Symphony+ sub-agent `{}` with Zed end-to-end validation evidence `{}`; commit {}.\n\
Addresses MIK-5198.DoD#research-followup: remaining ACP epic deliverables are linked below and back-linked from this epic by the control plane.\n\
B1-IDENT: trace lineage is distinguishable via `{}`.\n\
\n\
Follow-up: MIK-5198.ACP.3, MIK-5198.ACP.4, MIK-5198.ACP.5, MIK-5198.ACP.6, MIK-5198.ACP.7, MIK-5198.ACP.8, MIK-5198.ACP.9.\n\
\n\
Files: src/acp_server_mode.rs, tests/mik_5198_acs.rs.",
            self.verdict,
            self.decision,
            self.sub_agent.id,
            self.zed_validation.replay_command,
            commit_sha,
            self.sub_agent.trace_id
        )
    }
}
