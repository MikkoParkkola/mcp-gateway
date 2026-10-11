// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8341 D3s: over stdio too, a playbook run carrying retry fields is
//! refused with the playbook's own -32602 before anything runs. Red on base:
//! the run proceeds (and fails for another reason).

use std::sync::Arc;

use serde_json::json;

use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::MetaMcp;

#[tokio::test]
async fn a_stdio_playbook_run_carrying_retry_fields_is_refused() {
    for (field, value) in [("inputResponses", json!({})), ("requestState", json!(""))] {
        let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
        let definition = serde_json::from_value(json!({
            "playbook": "1.0", "name": "one", "description": "one step",
            "steps": [{"name": "s0", "tool": "read", "server": "alpha", "arguments": {}}]
        }))
        .expect("the playbook deserialises");
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(definition);
        meta.set_playbook_engine(engine);
        let meta = Arc::new(meta);
        let policy = Arc::new(crate::security::ToolPolicy::default());
        let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
            &crate::mtls::MtlsConfig::default(),
        ));
        let mut params = json!({"name": "gateway_run_playbook", "arguments": {"name": "one"}});
        params[field] = value;
        let request = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": params});
        let body =
            super::super::Gateway::dispatch_single(&meta, &policy, &mtls, &request, "stdio-8341")
                .await
                .expect("a request is answered");
        assert_eq!(body["error"]["code"], -32602, "{field}: {body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("no continuation to resume")),
            "{field}: not the playbook's refusal: {body}"
        );
    }
}
