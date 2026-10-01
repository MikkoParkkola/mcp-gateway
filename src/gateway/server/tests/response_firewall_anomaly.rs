// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7324.COV.3: `Gateway::response_firewall` builds the firewall both
//! transports enforce with. When the config turns anomaly detection on, the
//! firewall it builds must carry a transition tracker, or anomaly blocking is
//! silently off. Learned through `check_request`, never trained by hand.

use std::sync::Arc;

use serde_json::json;

use crate::backend::BackendRegistry;
use crate::config::Config;
use crate::gateway::meta_mcp::MetaMcp;
use crate::security::firewall::Firewall;

async fn built_firewall(anomaly_detection: bool) -> Arc<Firewall> {
    let mut config = Config::default();
    let fw = &mut config.security.firewall;
    fw.enabled = true;
    fw.anomaly_detection = anomaly_detection;
    fw.anomaly_threshold = 0.7;
    fw.anomaly_block_threshold = Some(0.95);
    fw.anomaly_min_observations = 20;
    let gateway = super::super::Gateway::new(config)
        .await
        .expect("the config is valid");
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    gateway.response_firewall(&meta)
}

fn allowed(fw: &Firewall, tool: &str) -> bool {
    fw.check_request("caller-1", "srv", tool, &json!({}), "caller", "caller-1")
        .allowed
}

/// 25 rounds of a->b, then a->c: never seen, so it scores 1.0.
fn never_seen_transition_is_allowed(fw: &Firewall) -> bool {
    for _ in 0..25 {
        assert!(
            allowed(fw, "tool_a") && allowed(fw, "tool_b"),
            "teaching calls are admitted"
        );
    }
    assert!(allowed(fw, "tool_a"));
    allowed(fw, "tool_c")
}

#[tokio::test]
async fn anomaly_detection_on_builds_a_firewall_that_blocks_a_never_seen_transition() {
    let fw = built_firewall(true).await;
    assert!(
        !never_seen_transition_is_allowed(&fw),
        "the built firewall must carry the transition tracker"
    );
}

/// Control: the same sequence with detection off is admitted, so the block
/// above comes from the tracker `response_firewall` wired in.
#[tokio::test]
async fn anomaly_detection_off_builds_a_firewall_that_admits_it() {
    let fw = built_firewall(false).await;
    assert!(never_seen_transition_is_allowed(&fw));
}
