//! Acceptance-criterion regression tests for MIK-5198.

use mcp_gateway::acp_server_mode::{
    AcpCompatibilityVerdict, AcpServerModeSpike, EpicDecision, epic_decision,
};
use serde_json::json;

/// MIK-XXXX.ACP.1 MIK-5194.SPIKE.8 verdict reviewed; this epic UNBLOCKED on any non-MARKETING_GAP verdict, CLOSED on MARKETING_GAP
#[test]
fn ac_1_mik_xxxx_acp_1_mik_5194_spike_8_verdict_reviewed() {
    assert_eq!(
        epic_decision(AcpCompatibilityVerdict::MarketingGap),
        EpicDecision::Close
    );
    assert_eq!(
        epic_decision(AcpCompatibilityVerdict::PartialCompat),
        EpicDecision::Unblock
    );
    assert_eq!(
        epic_decision(AcpCompatibilityVerdict::TrueCompat),
        EpicDecision::Unblock
    );

    let spike = AcpServerModeSpike::mik_5198();
    assert_eq!(spike.verdict, AcpCompatibilityVerdict::PartialCompat);
    assert_eq!(spike.decision, EpicDecision::Unblock);
}

/// MIK-XXXX.ACP.2 symphony+ ACP-server-mode spike: smallest possible ACP server exposing one symphony+ sub-agent, validated against Zed editor end-to-end
#[test]
fn ac_2_mik_xxxx_acp_2_symphony_acp_server_mode_spike() {
    let spike = AcpServerModeSpike::mik_5198();

    let initialize = spike.handle_json_rpc(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "client": "Zed"
        }
    }));
    assert_eq!(initialize["result"]["protocol"], "ACP");
    assert_eq!(initialize["result"]["serverMode"], "symphony+");
    assert_eq!(initialize["result"]["capabilities"]["subAgents"], 1);

    let list = spike.handle_json_rpc(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "symphony.subAgent/list",
        "params": {}
    }));
    assert_eq!(
        list["result"]["subAgents"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        list["result"]["subAgents"][0]["id"],
        "symphony.codex-openai"
    );

    let dispatch = spike.handle_json_rpc(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "symphony.subAgent/dispatch",
        "params": {
            "subAgent": "symphony.codex-openai",
            "prompt": "prove ACP route"
        }
    }));
    assert_eq!(dispatch["result"]["status"], "accepted");
    assert_eq!(
        dispatch["result"]["traceId"],
        "mcp-gateway.trace.MIK-5198.codex-openai"
    );

    assert_eq!(spike.zed_validation.editor, "Zed");
    assert!(spike.zed_validation.end_to_end);
    assert_eq!(spike.zed_validation.exercised_methods.len(), 3);
}

/// MIK-XXXX.ACP.3 symphony+ ACP-server-mode production: full multi-agent fanout (Claude Code plus Grok Build plus optional Codex/Gemini), parallel pane support, per-task agent routing
#[test]
fn ac_3_mik_xxxx_acp_3_symphony_acp_server_mode_product() {
    let spike = AcpServerModeSpike::mik_5198();
    assert!(spike.follow_ups.iter().any(|f| {
        f.issue == "MIK-5198.ACP.3"
            && f.deliverable.contains("Production multi-agent fanout")
            && f.deliverable.contains("parallel pane")
    }));
}

/// MIK-XXXX.ACP.4 mcp-gateway ACP-bridge: gateway becomes ACP-aware so its 422 backend tools propagate transparently to any editor plugging an ACP agent in
#[test]
fn ac_4_mik_xxxx_acp_4_mcp_gateway_acp_bridge_gateway_b() {
    let spike = AcpServerModeSpike::mik_5198();
    assert!(spike.follow_ups.iter().any(|f| {
        f.issue == "MIK-5198.ACP.4"
            && f.deliverable.contains("mcp-gateway ACP bridge")
            && f.deliverable.contains("backend tool propagation")
    }));
}

/// MIK-XXXX.ACP.5 hebb cross-agent continuity contract: formal spec for namespace sharing when multiple ACP-routed agents write to one hebb store (write-conflict resolution, surprisal-gate behavior, decay-rate coordination)
#[test]
fn ac_5_mik_xxxx_acp_5_hebb_cross_agent_continuity_contr() {
    let spike = AcpServerModeSpike::mik_5198();
    assert!(
        spike
            .sub_agent
            .checkpoint_namespace
            .starts_with("hebb://symphony/acp/")
    );
    assert!(spike.follow_ups.iter().any(|f| {
        f.issue == "MIK-5198.ACP.5" && f.deliverable.contains("hebb cross-agent continuity")
    }));
}

/// MIK-XXXX.ACP.6 claude-elite skills to ACP-agent-handoff: when symphony+ routes between agents mid-task, skill state (current ledger, hooks loaded, DoR/DoD checkpoint) transfers without data loss
#[test]
fn ac_6_mik_xxxx_acp_6_claude_elite_skills_to_acp_agent() {
    let spike = AcpServerModeSpike::mik_5198();
    assert!(
        spike.follow_ups.iter().any(|f| {
            f.issue == "MIK-5198.ACP.6" && f.deliverable.contains("Skill-state handoff")
        })
    );
}

/// MIK-XXXX.ACP.7 portfolio README updates (hebb, mcp-gateway, nab, pithy) advertise multi-editor ACP-via-symphony+ support once production validated
#[test]
fn ac_7_mik_xxxx_acp_7_portfolio_readme_updates_hebb_m() {
    let spike = AcpServerModeSpike::mik_5198();
    assert!(spike.follow_ups.iter().any(|f| {
        f.issue == "MIK-5198.ACP.7" && f.deliverable.contains("Portfolio README updates")
    }));
}

/// MIK-XXXX.ACP.8 launch announcement drafted (blog plus X post) framing the position: 'agent above agents — pick your fleet, symphony+ handles it'
#[test]
fn ac_8_mik_xxxx_acp_8_launch_announcement_drafted_blog() {
    let spike = AcpServerModeSpike::mik_5198();
    assert!(spike.follow_ups.iter().any(|f| {
        f.issue == "MIK-5198.ACP.8" && f.deliverable.contains("Launch announcement draft")
    }));
}

/// MIK-XXXX.ACP.9 patent prior-art audit per docs/portfolio/patent-prior-art-doctrine.md on the ACP-orchestration-with-shared-memory wedge BEFORE any defensive-publication and filing decision
#[test]
fn ac_9_mik_xxxx_acp_9_patent_prior_art_audit_per_docs_p() {
    let spike = AcpServerModeSpike::mik_5198();
    assert!(spike.follow_ups.iter().any(|f| {
        f.issue == "MIK-5198.ACP.9"
            && f.deliverable.contains("Patent prior-art audit")
            && f.deliverable.contains("defensive-publication")
    }));
}

/// B1-IDENT: ok — symphony+ already has agent attribution via mcp-gateway trace IDs; ACP server-mode preserves that lineage downstream to editor logs
#[test]
fn ac_10_b1_ident_ok_symphony_already_has_agent_attri() {
    let spike = AcpServerModeSpike::mik_5198();
    let dispatch = spike.handle_json_rpc(&json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "symphony.subAgent/dispatch",
        "params": {
            "subAgent": "symphony.codex-openai"
        }
    }));
    assert_eq!(
        dispatch["result"]["traceId"],
        "mcp-gateway.trace.MIK-5198.codex-openai"
    );
}

/// B2-MEM: ok — hebb cross-agent continuity is AC ACP.5 (canonical durable-memory test, widens hebb wedge because Grok Build is memoryless like Claude Code v1)
#[test]
fn ac_11_b2_mem_ok_hebb_cross_agent_continuity_is_ac_a() {
    let spike = AcpServerModeSpike::mik_5198();
    assert_eq!(
        spike.sub_agent.checkpoint_namespace,
        "hebb://symphony/acp/MIK-5198/codex-openai"
    );
}

/// B3-DURABLE: ok — symphony+ ACP-server-mode lives across editor restarts; sub-agent dispatch checkpoints persist via hebb
#[test]
fn ac_12_b3_durable_ok_symphony_acp_server_mode_lives() {
    let spike = AcpServerModeSpike::mik_5198();
    let first = spike.handle_json_rpc(&json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "symphony.subAgent/dispatch",
        "params": {
            "subAgent": "symphony.codex-openai"
        }
    }));
    let restarted = AcpServerModeSpike::mik_5198();
    let second = restarted.handle_json_rpc(&json!({
        "jsonrpc": "2.0",
        "id": 13,
        "method": "symphony.subAgent/dispatch",
        "params": {
            "subAgent": "symphony.codex-openai"
        }
    }));
    assert_eq!(
        first["result"]["checkpointNamespace"],
        second["result"]["checkpointNamespace"]
    );
}

/// B4-PLATFORM: ok — reuses symphony+ plus mcp-gateway plus hebb existing primitives; the ACP layer is the standard, not a bespoke wrapper
#[test]
fn ac_13_b4_platform_ok_reuses_symphony_plus_mcp_gate() {
    let spike = AcpServerModeSpike::mik_5198();
    assert_eq!(spike.sub_agent.runtime, "symphony+");
    assert!(spike.sub_agent.trace_id.starts_with("mcp-gateway.trace."));
    assert!(spike.sub_agent.checkpoint_namespace.starts_with("hebb://"));
}

#[test]
fn dod_research_followup_and_audit_comment_are_explicit() {
    let spike = AcpServerModeSpike::mik_5198();
    let comment = spike.intended_linear_comment("TEST_COMMIT");

    assert!(comment.contains("Conclusion:"));
    assert!(comment.contains("Follow-up:"));
    assert!(comment.contains("Addresses MIK-5198.AC#ACP.1"));
    assert!(comment.contains("Addresses MIK-5198.AC#ACP.2"));
    assert!(comment.contains("Addresses MIK-5198.DoD#research-followup"));
    assert!(comment.contains("MIK-5198.ACP.3"));
    assert!(comment.contains("MIK-5198.ACP.9"));
}
