// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A surfaced replay across a real reload: the deferred and the pre-admitted repeat both keep the admitted server.

use super::StagedReceipts;
use crate::backend::{Backend, BackendRegistry, PoolKey};
use crate::config::{Config, FailsafeConfig};
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::gateway::meta_mcp::MetaMcpCallerContext as Caller;
use crate::gateway::meta_mcp::admission::{ReplayOrigin, SyncAdmission};
use crate::gateway::meta_mcp::catalogue_per_caller_tests::{identity, install_minting};
use crate::gateway::meta_mcp::visible::{deferred::deferred_replay_key, memo};
use crate::gateway::meta_mcp::{AdmissionOwner, Authentication, MetaMcp};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::{JsonRpcResponse, RequestId, mrtr::RetryFields};
use crate::security::firewall::Firewall;
use crate::security::transparency_log::temp::TempLog;
use serde_json::{Value, json};
use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost. It closes with the \
    count of crates sent to the cooperative press and a note about the broken ladder by the barn.";

struct Wire(&'static str, Arc<AtomicUsize>);
#[async_trait::async_trait]
impl crate::transport::Transport for Wire {
    async fn request(&self, method: &str, _: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let body = match method {
            "tools/list" => json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]}),
            "tools/call" => {
                self.1.fetch_add(1, Ordering::SeqCst);
                json!({"content": [{"type": "text", "text": format!("{}: {PROSE}", self.0)}], "isError": false})
            }
            _ => panic!("unexpected method {method}"),
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), body))
    }
    async fn notify(&self, _: &str, _: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

struct Fixture {
    meta: MetaMcp,
    live: Arc<LiveConfig>,
    calls: [Arc<AtomicUsize>; 2],
    who: VerifiedIdentity,
    dir: tempfile::TempDir,
    log: TempLog,
}
impl Fixture {
    fn new(per_user: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(BackendRegistry::new());
        let calls = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
        let mut config: Config = crate::yaml::from_str(
            r#"
backends:
  alpha: {http_url: 'https://alpha.example/mcp'}
  beta: {http_url: 'https://beta.example/mcp'}
meta_mcp:
  surfaced_tools: [{server: alpha, tool: read}]
security:
  firewall:
    rules: [{match: '*', action: allow}]
    collusion: {action: block, sources: ['alpha:*']}
"#,
        )
        .unwrap();
        if per_user {
            config.backends.get_mut("alpha").unwrap().identity_propagation = Some(
                crate::yaml::from_str("strategy: signed_assertion\naudience: alpha\nrequired: true\nsession_mode: per_user").unwrap());
        }
        let ttl = Duration::from_secs(300);
        let failsafe = FailsafeConfig::default();
        for (name, count) in ["alpha", "beta"].into_iter().zip(&calls) {
            let backend_config = config.backends[name].clone();
            let backend = Arc::new(Backend::new(name, backend_config, &failsafe, ttl));
            let wire = Arc::new(Wire(name, Arc::clone(count)));
            backend.set_transport_for_test(wire.clone());
            if per_user && name == "alpha" {
                backend.set_pooled_transport_for_test(
                    &PoolKey::PerUser {
                        binding: "123@alpha".into(),
                    },
                    wire,
                );
            }
            assert!(registry.register(backend));
        }
        let firewall = Arc::new(
            Firewall::from_config(config.security.firewall.clone(), None).keyed_for_test(),
        );
        let mut meta = MetaMcp::new(Arc::clone(&registry))
            .with_surfaced_tools(config.meta_mcp.surfaced_tools.clone());
        meta.set_firewall(Some(Arc::clone(&firewall)));
        meta.share_keyring_with_for_test(&firewall);
        meta.set_multi_user(true);
        meta.enable_idempotency(Arc::new(crate::idempotency::IdempotencyCache::new()), ttl);
        let log = TempLog::new();
        install_minting(&mut meta, &log);
        write_config(&dir, &config);
        let live = Arc::new(LiveConfig::new(config));
        meta.set_live_config(Arc::clone(&live));
        let path = dir.path().join("gateway.yaml");
        let reload = ReloadContext::new(path, Arc::clone(&live), registry, failsafe, ttl).unwrap();
        meta.set_reload_context(Arc::new(reload));
        Self {
            meta,
            live,
            calls,
            who: identity("123"),
            dir,
            log,
        }
    }
    fn caller<'a>(&'a self, retry: &'a RetryFields) -> Caller<'a> {
        Caller {
            retry,
            caller_key: Some("alice"),
            verified_identity: Some(&self.who),
            credential_principal: Some("reload-replay-principal"),
            authentication: Authentication::Authenticated,
            credential_kind: crate::security::audit::CredentialKind::OidcBearer,
            ..crate::gateway::meta_mcp::anonymous_caller()
        }
    }
    fn counts(&self, expected: [usize; 2]) {
        let actual = self.calls.each_ref().map(|n| n.load(Ordering::SeqCst));
        assert_eq!(actual, expected);
    }
    fn records(&self) -> Vec<Value> {
        std::fs::read_to_string(self.log.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|e| e.get("tool").is_some() && e["event"] != "response_delivery_attempt")
            .collect()
    }
    async fn reload(&self) {
        let mut config = (*self.live.get()).clone();
        config.meta_mcp.surfaced_tools[0].server = "beta".into();
        write_config(&self.dir, &config);
        let result = self.meta.reload_config().await.unwrap();
        assert_eq!(result["status"], "ok", "{result}");
        assert_eq!(result["restart_required"], false, "{result}");
    }
    fn receipt(&self, staged: StagedReceipts) {
        assert_eq!(staged.receipts.len(), 1);
        assert_eq!(staged.receipts[0].server, "alpha");
        assert_eq!(staged.receipts[0].tool, "read");
        staged.commit(true, &self.live.generation());
    }
    fn replay_record(&self, first: &Value) {
        let records = self.records();
        assert_eq!(records.len(), 2, "{records:?}");
        let replay = &records[1];
        assert_eq!(replay["server"], "alpha");
        assert_eq!(replay["tool"], "read");
        assert_eq!(replay["decision"]["decided"], "replayed");
        for key in ["outcome", "request_hash", "response_hash"] {
            assert!(!first[key].is_null(), "missing {key}: {first}");
            assert_eq!(replay[key], first[key], "{key}: {replay}");
        }
    }
    async fn execute(&self, retry: &RetryFields, id: i64) -> (JsonRpcResponse, StagedReceipts) {
        memo::with_visibility_memo(self.meta.collecting_staged(async {
            let caller = self.caller(retry);
            let SyncAdmission::Owned(lease) = admit(&self.meta, &caller, id).unwrap() else {
                panic!("first call must own admission")
            };
            let caller = Caller {
                execution: Some(&lease),
                ..caller
            };
            let answer = dispatch(&self.meta, caller, id).await;
            lease.complete_secured(&answer);
            answer
        }))
        .await
    }
}
fn write_config(dir: &tempfile::TempDir, config: &Config) {
    crate::gateway::test_helpers::write_owner_only(
        dir.path().join("gateway.yaml"),
        crate::yaml::to_string(config).unwrap(),
    )
    .unwrap();
}
fn keyed(key: &str) -> RetryFields {
    RetryFields {
        idempotency_key: Some(key.into()),
        ..Default::default()
    }
}
fn admit(meta: &MetaMcp, caller: &Caller<'_>, id: i64) -> crate::Result<SyncAdmission> {
    meta.admit_meta_sync_for_test(
        AdmissionOwner::for_test(caller.owner_principal()),
        caller,
        "read",
        &json!({}),
        Some("session"),
        &RequestId::Number(id),
    )
}
async fn dispatch(meta: &MetaMcp, caller: Caller<'_>, id: i64) -> JsonRpcResponse {
    meta.handle_tools_call_ref(
        RequestId::Number(id),
        "read",
        Cow::Owned(json!({})),
        Some("session"),
        caller,
    )
    .await
}
fn answer(response: &JsonRpcResponse, id: i64, server: &str) {
    assert!(response.error.is_none(), "{response:?}");
    assert_eq!(response.id, Some(RequestId::Number(id)));
    let result = response.result.as_ref().expect("a successful result");
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(result["content"][0]["text"], format!("{server}: {PROSE}"));
}

#[tokio::test]
async fn replay3_deferred_surfaced_replay_survives_real_reload() {
    let f = Fixture::new(true);
    let retry = keyed("replay3");
    let (first, staged) = f.execute(&retry, 1).await;
    answer(&first, 1, "alpha");
    f.counts([1, 0]);
    f.receipt(staged);
    let records = f.records();
    assert_eq!(records.len(), 1);
    let (_, staged) = memo::with_visibility_memo(f.meta.collecting_staged(async {
        let caller = f.caller(&retry);
        let SyncAdmission::Replay(response, audit, target, steps, bindings, slot) =
            admit(&f.meta, &caller, 2).unwrap()
        else {
            panic!("repeat must replay")
        };
        let target_ref = target.as_ref().unwrap();
        assert_eq!(
            (&*target_ref.server, &*target_ref.tool, target_ref.origin),
            ("alpha", "read", ReplayOrigin::Named)
        );
        assert!(
            f.meta
                .stored_replay_defers(&f.meta.unscoped_for_test(), "alpha", "read")
        );
        let deferred = f
            .meta
            .defer_or_serve_replay(
                "read",
                &json!({}),
                &caller,
                target,
                (steps, bindings, slot),
                (response, audit),
            )
            .await;
        assert!(deferred.is_none());
        f.reload().await;
        let replay = dispatch(&f.meta, caller, 2).await;
        answer(&replay, 2, "alpha");
        f.counts([1, 0]);
        // A take outside this SAME open memo would pass vacuously.
        assert!(
            memo::surfaced_snapshot(|| f.meta.surfaced_state_live()).is_some(),
            "memo must be open"
        );
        let key = deferred_replay_key("alpha", "read", &retry).unwrap();
        assert!(memo::take_deferred_replay(&key).is_none());
        f.replay_record(&records[0]);
        assert_eq!(
            f.meta.surfaced_state_live().map.unscoped("read"),
            Some("beta")
        );
        assert_eq!(f.meta.surfaced_server_unscoped("read"), Some("alpha"));
    }))
    .await;
    f.receipt(staged);
    let (fresh, staged) = f.execute(&keyed("fresh-beta"), 3).await;
    answer(&fresh, 3, "beta");
    f.counts([1, 1]);
    staged.commit(true, &f.live.generation());
}

#[tokio::test]
async fn reload5_real_reload_preserves_admitted_replay_and_refuses_late_retry() {
    let f = Fixture::new(false);
    let retry = keyed("reload5");
    let (first, staged) = f.execute(&retry, 1).await;
    answer(&first, 1, "alpha");
    f.counts([1, 0]);
    f.receipt(staged);
    let records = f.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["server"], "alpha");
    assert_eq!(records[0]["tool"], "read");

    let (_, staged) = memo::with_visibility_memo(f.meta.collecting_staged(async {
        let caller = f.caller(&retry);
        let SyncAdmission::Replay(response, audit, target, steps, bindings, slot) =
            admit(&f.meta, &caller, 2).unwrap()
        else {
            panic!("repeat admitted before reload must replay")
        };
        let target_ref = target.as_ref().unwrap();
        assert_eq!(
            (&*target_ref.server, &*target_ref.tool, target_ref.origin),
            ("alpha", "read", ReplayOrigin::Named)
        );
        f.reload().await;
        assert_eq!(
            f.meta.surfaced_state_live().map.unscoped("read"),
            Some("beta")
        );
        assert_eq!(f.meta.surfaced_server_unscoped("read"), Some("alpha"));
        let (response, facts) = f
            .meta
            .defer_or_serve_replay(
                "read",
                &json!({}),
                &caller,
                target,
                (steps, bindings, slot),
                (response, audit),
            )
            .await
            .expect("plain alpha must serve the admitted replay directly");
        assert_eq!(facts.server.as_deref(), Some("alpha"));
        assert_eq!(facts.tool.as_deref(), Some("read"));
        let replay = f
            .meta
            .audit_replay(
                "read",
                &json!({}),
                Some("session"),
                &caller,
                response,
                facts,
            )
            .await;
        answer(&replay, 2, "alpha");
        f.counts([1, 0]);
        f.replay_record(&records[0]);
    }))
    .await;
    f.receipt(staged);

    // A fresh request resolves beta; this staged row stops at failed admission.
    memo::with_visibility_memo(async {
        let caller = f.caller(&retry);
        assert_eq!(f.meta.surfaced_server_unscoped("read"), Some("beta"));
        let Err(error) = admit(&f.meta, &caller, 3) else {
            panic!("retry admitted after reload must refuse the changed target")
        };
        let crate::Error::JsonRpc { code, message, .. } = error else {
            panic!("expected a JSON-RPC admission refusal, got {error:?}")
        };
        assert_eq!(code, 409);
        assert_eq!(
            message,
            "Idempotency key belongs to another execution or representation"
        );
        f.counts([1, 0]);
    })
    .await;
}
