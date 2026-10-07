// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7916 option (1b), red stage.

use std::sync::Arc;

use serde_json::Value;

use crate::backend::BackendRegistry;
use crate::config::WebhookConfig;
use crate::gateway::WebhookRegistry;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};

fn tools_of(response: &JsonRpcResponse) -> Value {
    response.result.as_ref().expect("a result")["tools"].clone()
}

#[test]
fn a_repeat_list_builds_computes_and_compares_nothing() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_webhook_registry(Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        WebhookConfig::default(),
    ))));
    let first = meta.handle_tools_list(RequestId::Number(1));
    let (cards, compares) = crate::trust::memo_counters();
    let second = meta.handle_tools_list(RequestId::Number(2));
    let (cards_after, compares_after) = crate::trust::memo_counters();
    assert_eq!(cards_after - cards, 0, "no trust card computed");
    assert_eq!(compares_after - compares, 0, "no tool compared");
    assert_eq!(tools_of(&second), tools_of(&first), "the same descriptors");
}
