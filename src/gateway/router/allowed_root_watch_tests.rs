// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! I7: capability watch polling under a root rule. A poll of a config
//! backend's tool is judged like any call: an outside path is refused before
//! the backend sees it, and an inside path reaches it as checked. The
//! router's firewall is built as `response_firewall` builds it, from config
//! with the registries wired. Batch 5g.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{Value, json};

use super::AppState;
use crate::backend::Backend;
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig};
use crate::events::watch_source::{Charge, CredentialUse, Target};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::{Firewall, FirewallAction, FirewallConfig, FirewallRule};
use crate::transport::Transport;

const KEY: &str = "k-watch";

/// Records the `tools/call` params the backend received.
struct Recorder(Mutex<Vec<Value>>);

#[async_trait]
impl Transport for Recorder {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        if method == "tools/call" {
            self.0
                .lock()
                .expect("recorder")
                .push(params.unwrap_or_default());
        }
        let answer = json!({"content": [{"type": "text", "text": "ok"}]});
        Ok(JsonRpcResponse::success(RequestId::Number(1), answer))
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

fn auth() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key_sha256: Some(crate::config::api_key_digest_spec(KEY.as_bytes())),
            name: KEY.to_string(),
            backends: vec!["*".to_string()],
            ..Default::default()
        }],
        ..Default::default()
    }
}

struct Watch {
    state: Arc<AppState>,
    seen: Arc<Recorder>,
    dir: tempfile::TempDir,
    _store: tempfile::TempDir,
}

async fn watch() -> Watch {
    let dir = tempfile::tempdir().expect("tempdir");
    for sub in ["safe", "outside"] {
        std::fs::create_dir(dir.path().join(sub)).expect("mkdir");
    }
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth()).await;
    let seen = Arc::new(Recorder(Mutex::new(Vec::new())));
    let backend = Arc::new(Backend::new(
        "fs",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(5),
    ));
    backend.set_transport_for_test(Arc::clone(&seen) as Arc<dyn Transport>);
    assert!(state.backends.register(backend));
    let rule = FirewallRule {
        tool_match: "read_file".to_string(),
        action: FirewallAction::Block,
        reason: None,
        scan: Vec::new(),
        servers: None,
        keys: None,
        except: None,
        allowed_roots: Some(vec![dir.path().join("safe").to_string_lossy().into_owned()]),
        path_args: Some(vec!["path".to_string()]),
    };
    let config = FirewallConfig {
        rules: vec![rule],
        ..FirewallConfig::default()
    };
    let slot = Arc::new(parking_lot::RwLock::new(None));
    let firewall = Firewall::from_config(config, None)
        .with_continuations(state.meta_mcp.continuation())
        .with_registries(Arc::clone(&state.backends), slot);
    Arc::get_mut(&mut state)
        .expect("the fixture state is not shared yet")
        .firewall = Some(Arc::new(firewall));
    Watch {
        state,
        seen,
        dir,
        _store: store,
    }
}

async fn poll(w: &Watch, path: &str) -> Result<Value, String> {
    let client = w
        .state
        .auth_config
        .client_for_key(KEY, crate::gateway::auth::principal_of(KEY).storage_form())
        .expect("the key is live");
    let target = Target {
        capability: "read_file".into(),
        backend: "fs".into(),
        read_only: true,
        credential: CredentialUse::Keyed,
        input_schema: json!({}),
    };
    super::watch_poll::poll_capability(
        &w.state,
        &client,
        "subscriber",
        Charge::Holder,
        &target,
        json!({"path": path}),
    )
    .await
    .map_err(|refused| format!("{refused:?}"))
}

/// I7: an outside poll is refused and never reaches `fs`; an inside poll
/// reaches it with exactly the checked path.
#[tokio::test]
async fn i7_watch_polls_are_confined() {
    let w = watch().await;
    let path = |rel: &str| w.dir.path().join(rel).to_string_lossy().into_owned();
    let refused = poll(&w, &path("outside/f")).await;
    assert!(refused.is_err(), "I7: outside polled: {refused:?}");
    assert!(
        w.seen.0.lock().expect("recorder").is_empty(),
        "I7: the backend saw it"
    );
    let inside = path("safe/f");
    poll(&w, &inside)
        .await
        .expect("I7: an inside poll is allowed");
    let sent = w.seen.0.lock().expect("recorder").clone();
    assert_eq!(sent.len(), 1, "I7: {sent:?}");
    assert_eq!(
        sent[0]["arguments"]["path"],
        json!(inside),
        "I7: arrived as checked"
    );
}
