// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7962.COLD.1, reader 3: the admission check reads the tool cache and
//! nothing else. Under agent auth a cold backend is not admitted, and the
//! check never reaches the backend's wire to warm it.
use super::*;
use crate::gateway::authz::ToolAuthorizer;
use pretty_assertions::assert_eq;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Answers `tools/list` with one tool, counting every request.
struct CountingLister(AtomicUsize);

#[async_trait::async_trait]
impl crate::transport::Transport for CountingLister {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            json!({"tools": [{"name": "query", "inputSchema": {"type": "object"}}]}),
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

#[tokio::test]
async fn admission_reads_a_cold_cache_and_never_fills_it() {
    use crate::gateway::oauth::{AgentIdentity, Scope};

    let (mut state, _store) = test_router_app_state_with_agent_auth_enabled().await;
    let wire = Arc::new(CountingLister(AtomicUsize::new(0)));
    // The same cold fixture as the discovery cells: a test transport on a
    // default backend, cache never filled.
    let backend = Arc::new(Backend::new(
        "cold",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);
    {
        let state_mut = Arc::get_mut(&mut state).expect("sole owner during setup");
        assert!(state_mut.backends.register(Arc::clone(&backend)));
    }
    let agent = AgentIdentity {
        quota_principal: None,
        client_id: "agent-1".to_string(),
        agent_name: "runner".to_string(),
        scopes: vec![Scope::parse("tools:cold:*").expect("scope must parse")],
        raw_scopes: vec!["tools:cold:*".to_string()],
    };
    let authorizer = super::authorization::RouterAuthorizer {
        state: &state,
        client: None,
        oauth_agent_identity: Some(&agent),
        cert_identity: None,
        principal: None,
    };

    assert!(
        !authorizer.admits_backend("cold"),
        "a cold backend is not admitted under agent auth"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        wire.0.load(Ordering::SeqCst),
        0,
        "the admission check must never reach the backend's wire"
    );

    backend
        .get_tools()
        .await
        .expect("the listing fills the cache");
    assert!(
        authorizer.admits_backend("cold"),
        "control: once a permitted tool is cached, the backend is admitted"
    );
}
