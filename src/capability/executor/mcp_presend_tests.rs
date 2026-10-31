// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability call is one delivery that can carry several backend calls: its
//! prepare round and its main call go to the capability's own child backend.
//! A later round refused in that backend's own send, before any byte leaves,
//! is not "nothing was sent" once an earlier round entered the transport.
//!
//! Production children carry no secret rules, so the child is seeded through
//! the pool's own `acquire` with a backend that has one; the call then finds it
//! under the same key, config, fingerprint and timeout and does not replace it.

use std::hash::{Hash as _, Hasher as _};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::{Value, json};

use super::tests::{caller, capability};
use super::{Workdir, principal};
use crate::backend::Backend;
use crate::capability::definition::ProcessConfig;
use crate::capability::executor::CapabilityExecutor;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::delivery_facts;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget};

/// A child that answers the prepare tool and records the name of every
/// `tools/call` that reaches it.
struct Recording {
    tools: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Recording {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        if method == "tools/call" {
            let name = params
                .as_ref()
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            self.tools.lock().push(name);
        }
        Ok(JsonRpcResponse::success(
            RequestId::Number(1),
            json!({"content": [], "structuredContent": {"program_name": "prog-ls"}}),
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

/// What the delivery knew when the capability call ended.
struct Ended {
    error: crate::Error,
    unsent: bool,
    nothing_sent: bool,
    refused_before_send: bool,
}

/// R13: `analyze` sends its prepare round (`import_binary`) and then refuses
/// its main call (`echo`, which the child's argument rule cannot apply
/// without a resolver) in `outbound`. The refusal is recorded, but the prepare
/// round is still counted, so the delivery is not unsent and the key is kept.
#[tokio::test]
async fn a_later_round_refused_in_its_send_after_an_earlier_send_is_not_unsent() {
    let executor = CapabilityExecutor::new();
    let cap = capability();
    let context = caller("a");
    let Some(ProcessConfig::Mcp(config)) = cap.providers.process.get("primary") else {
        panic!("not an mcp provider");
    };
    let timeout = Duration::from_secs(cap.primary_provider().map_or(30, |p| p.timeout));
    // As `execute_mcp` fingerprints a capability with no declared env and no
    // bound roots.
    let env_fp = {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        Vec::<(&String, String)>::new().hash(&mut hasher);
        Vec::<(String, String)>::new().hash(&mut hasher);
        hasher.finish()
    };
    let who = principal(&cap, &context, false).expect("the caller names its child");

    let tools = Arc::new(Mutex::new(Vec::new()));
    let backend = Arc::new(Backend::new(
        &format!("capability:{}", cap.name),
        BackendConfig {
            secrets: vec![CredentialRule {
                name: "api".to_string(),
                credential_type: CredentialType::ApiKey,
                value: "child-secret-a7f3".to_string(),
                inject_as: InjectTarget::Argument,
                inject_key: "api_key".to_string(),
                tools: vec!["echo".to_string()],
            }],
            timeout,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::ZERO,
    ));
    backend.set_transport_for_test(Arc::new(Recording {
        tools: Arc::clone(&tools),
    }));
    let workdir = Workdir::create().expect("a private work directory");
    let seeded = executor
        .mcp_children
        .acquire(
            &cap,
            config,
            &who,
            (env_fp, timeout),
            |_| true,
            || Ok((backend, workdir)),
        )
        .expect("the child is seeded");
    drop(seeded);

    let params = json!({"operation": "analyze", "binary_path": "/bin/ls"});
    let ended = delivery_facts::scope(async {
        let error = executor
            .execute_mcp(&cap, config, &params, &context)
            .await
            .expect_err("the main call is refused in its send");
        Ended {
            unsent: delivery_facts::unsent(&error),
            nothing_sent: delivery_facts::nothing_sent(),
            refused_before_send: delivery_facts::refused_before_send_seen(),
            error,
        }
    })
    .await;

    assert_eq!(
        tools.lock().as_slice(),
        ["import_binary"],
        "premise: only the prepare round reached the seeded child (a replaced \
         child or a sent main call fails here)"
    );
    assert!(
        matches!(ended.error, crate::Error::Config(_)),
        "premise: the main call was refused in `outbound`: {:?}",
        ended.error
    );
    assert!(
        ended.refused_before_send,
        "premise: the refusal was not recorded as made before the send"
    );
    assert!(
        !ended.nothing_sent,
        "premise: the prepare round was not counted as a send"
    );
    assert!(
        !ended.unsent,
        "a refusal after an earlier round entered the transport read as unsent, \
         so the call's key would be released"
    );
}
