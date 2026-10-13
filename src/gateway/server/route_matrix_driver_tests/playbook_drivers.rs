// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Playbook drivers for the route-check matrix.

use super::{
    Arc, AtomicUsize, Counting, JsonRpcResponse, Ordering, Path, RequestId, Value, arm_firewall,
    audited_firewall_with, json, stdio_meta, stdio_send_under, text_result,
};

/// MIK-8362: `runs` `gateway_run_playbook` calls of the playbook `definition`
/// (steps on `alpha`) over one stdio Meta-MCP whose firewall config `tune`
/// adjusts and whose tool policy is `policy`. Returns each answer and the
/// backend's sends.
pub(crate) async fn stdio_playbook_runs(
    audit: &Path,
    tune: impl FnOnce(&mut crate::security::firewall::FirewallConfig),
    (definition, policy): (Value, crate::security::ToolPolicyConfig),
    runs: usize,
) -> (Vec<Value>, usize) {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Counting {
        calls: Arc::clone(&calls),
        answer: text_result("ok"),
    });
    stdio_playbook_over(backend, calls, audit, tune, (definition, policy, runs)).await
}

/// [`stdio_playbook_runs`] over a backend whose first `tools/call` fails with a
/// transport error and whose later ones answer `ok`: an engine retry
/// (`on_error: retry`) is the only thing that sends the step a second time.
pub(crate) async fn stdio_playbook_flaky(
    audit: &Path,
    tune: impl FnOnce(&mut crate::security::firewall::FirewallConfig),
    (definition, runs): (Value, usize),
) -> (Vec<Value>, usize) {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(FailsFirst {
        calls: Arc::clone(&calls),
    });
    let policy = crate::security::ToolPolicyConfig::default();
    stdio_playbook_over(backend, calls, audit, tune, (definition, policy, runs)).await
}

async fn stdio_playbook_over(
    backend: Arc<dyn crate::transport::Transport>,
    calls: Arc<AtomicUsize>,
    audit: &Path,
    tune: impl FnOnce(&mut crate::security::firewall::FirewallConfig),
    (definition, policy, runs): (Value, crate::security::ToolPolicyConfig, usize),
) -> (Vec<Value>, usize) {
    let params = json!({ "name": "gateway_run_playbook", "arguments": { "name": "steps" } });
    stdio_params_over(
        (backend, calls),
        audit,
        tune,
        (Some(definition), policy, vec![params; runs]),
    )
    .await
}

/// Each of `params` as a stdio `tools/call` over `backend`, with the playbook
/// `definition` (if any) registered, under the firewall `tune` adjusts and the
/// tool policy `policy`. Returns each answer and the backend's sends.
pub(crate) async fn stdio_params_over(
    (backend, calls): (Arc<dyn crate::transport::Transport>, Arc<AtomicUsize>),
    audit: &Path,
    tune: impl FnOnce(&mut crate::security::firewall::FirewallConfig),
    (definition, policy, params): (Option<Value>, crate::security::ToolPolicyConfig, Vec<Value>),
) -> (Vec<Value>, usize) {
    let firewall = audited_firewall_with(audit, tune);
    let arm = arm_firewall(firewall);
    let definition =
        definition.map(|value| serde_json::from_value(value).expect("the playbook deserialises"));
    let gateway_meta = stdio_meta(
        move |meta| {
            arm(meta);
            if let Some(definition) = definition {
                let mut engine = crate::playbook::PlaybookEngine::new();
                engine.register(definition);
                meta.set_playbook_engine(engine);
            }
        },
        backend,
    )
    .await;
    let mut answers = Vec::new();
    for params in params {
        answers.push(
            stdio_send_under(
                &gateway_meta,
                params,
                crate::security::ToolPolicy::from_config(&policy),
            )
            .await,
        );
    }
    (answers, calls.load(Ordering::SeqCst))
}

/// [`stdio_params_over`] on the counting backend answering `ok`.
pub(crate) async fn stdio_params_counted(
    audit: &Path,
    tune: impl FnOnce(&mut crate::security::firewall::FirewallConfig),
    (definition, policy, params): (Option<Value>, crate::security::ToolPolicyConfig, Vec<Value>),
) -> (Vec<Value>, usize) {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Counting {
        calls: Arc::clone(&calls),
        answer: text_result("ok"),
    });
    super::stdio_params_over((backend, calls), audit, tune, (definition, policy, params)).await
}

/// A backend serving `read` whose first `tools/call` fails and whose later
/// ones answer `ok`, counting every send (the failed one included).
struct FailsFirst {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for FailsFirst {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        if method == "tools/list" {
            let body =
                json!({ "tools": [{ "name": "read", "inputSchema": { "type": "object" } }] });
            return Ok(JsonRpcResponse::success(RequestId::Number(1), body));
        }
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(crate::Error::json_rpc(-32001, "flaky backend"));
        }
        Ok(JsonRpcResponse::success(
            RequestId::Number(1),
            text_result("ok"),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// The playbook `steps` with one `read` step on `alpha` per name in `tools`
/// (a step per entry, in order).
pub(crate) fn playbook_of(tools: &[&str]) -> Value {
    let steps: Vec<Value> = tools
        .iter()
        .enumerate()
        .map(|(index, tool)| {
            json!({ "name": format!("s{index}"), "tool": tool, "server": "alpha",
                "arguments": {} })
        })
        .collect();
    json!({ "playbook": "1.0", "name": "steps", "description": "steps", "steps": steps })
}
