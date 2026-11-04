// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The secret check as a deferred task's query runs it: a matched check
//! renews the dispatch's values through the backend before the poll, and a
//! rotation during the poll withholds the terminal answer it brought back.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::NativeUpstreamTasks;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, EnvOverlay, FailsafeConfig, LiveEnv, ResolvedEnvFiles};
use crate::gateway::task_service::{UpstreamAnswer, UpstreamHandle, UpstreamRecovery};
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget};
use crate::secrets::SecretResolver;
use crate::security::dispatched::Dispatched;
use crate::security::needles::{NeedleSet, scrub_text};

const VALUE: &str = "poll-side-secret-91c4";
const ROTATED: &str = "poll-side-rotated-91c4";
/// The needle grace here: short, so a seeded value can be let retire.
const GRACE: Duration = Duration::from_secs(60);

/// A peer that answers `tasks/get` with a completed task echoing `VALUE`,
/// first publishing `rotate` into the gateway's env when it holds one.
struct Peer {
    env: Arc<LiveEnv>,
    rotate: Option<Arc<EnvOverlay>>,
    seen: parking_lot::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Peer {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.seen.lock().push(method.to_owned());
        let result = if method == "server/discover" {
            json!({"capabilities": {"extensions": {
                "io.modelcontextprotocol/tasks": {}
            }}})
        } else {
            if let Some(next) = &self.rotate {
                self.env.set(Arc::clone(next));
            }
            json!({"taskId": "t1", "status": "completed", "result": {
                "content": [{"type": "text", "text": format!("echo {VALUE}")}]
            }})
        };
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            crate::protocol::RequestId::Number(1),
            result,
        ))
    }
    async fn request_with_task_capability(
        &self,
        method: &str,
        params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.request(method, params).await
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

fn overlay(dir: &tempfile::TempDir, name: &str, value: &str) -> Arc<EnvOverlay> {
    let path = dir.path().join(name);
    crate::gateway::test_helpers::write_owner_only(&path, format!("POLL_CHECK_KEY={value}\n"))
        .expect("the env file is written");
    Arc::new(EnvOverlay::from_paths(&[path]))
}

/// A registered `peer` whose one header rule resolves `VALUE` from its env,
/// with an empty needle set, its env, and the peer.
fn adapter(
    dir: &tempfile::TempDir,
    rotate: bool,
) -> (NativeUpstreamTasks, Arc<NeedleSet>, Arc<Peer>) {
    let env = Arc::new(LiveEnv::new(
        overlay(dir, "now.env", VALUE),
        ResolvedEnvFiles::default(),
    ));
    let peer = Arc::new(Peer {
        env: Arc::clone(&env),
        rotate: rotate.then(|| overlay(dir, "next.env", ROTATED)),
        seen: parking_lot::Mutex::default(),
    });
    let backend = Arc::new(Backend::new(
        "peer",
        BackendConfig {
            secrets: vec![CredentialRule {
                name: "api".to_owned(),
                credential_type: CredentialType::ApiKey,
                value: "{env.POLL_CHECK_KEY}".to_owned(),
                inject_as: InjectTarget::Header,
                inject_key: "X-Api-Key".to_owned(),
                tools: vec!["*".to_owned()],
            }],
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(5),
    ));
    backend.stamp_secret_resolver(Arc::new(SecretResolver::new().with_env(env)));
    // Stamped before registration, so the registry keeps this set (and its
    // short grace) and seeds the resolved value into it.
    let needles = Arc::new(NeedleSet::with_grace(GRACE));
    backend.stamp_needles(Arc::clone(&needles));
    backend.set_transport_for_test(Arc::clone(&peer) as Arc<dyn crate::transport::Transport>);
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend), "fixture registration");
    (
        NativeUpstreamTasks::new(registry, &["peer".to_owned()]),
        needles,
        peer,
    )
}

fn handle() -> UpstreamHandle {
    UpstreamHandle {
        backend: "peer".to_owned(),
        handle: "t1".to_owned(),
        tool: "read".to_owned(),
        arguments: json!({}),
        fingerprint: Some(Dispatched::of("peer", &[("api".to_owned(), VALUE.to_owned())]).stored()),
    }
}

fn redacted(needles: &NeedleSet) -> bool {
    let mut text = format!("echo {VALUE}");
    scrub_text(needles, &mut text);
    !text.contains(VALUE)
}

/// The query production runs reaches the backend's renewal. Registration
/// seeds the resolved value, so the row lets that seed retire first (past
/// its grace): only the query's renewal can put the value back.
#[tokio::test(start_paused = true)]
async fn a_matched_query_renews_the_dispatchs_value_before_its_poll() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (adapter, needles, peer) = adapter(&dir, false);
    assert!(redacted(&needles), "premise: registration seeded the value");
    tokio::time::advance(GRACE + Duration::from_secs(1)).await;
    assert!(!redacted(&needles), "premise: the seeded value retired");
    let answer = adapter.query(&handle(), Duration::from_secs(5)).await;
    assert!(
        matches!(answer, UpstreamAnswer::Completed(_)),
        "an unchanged secret settles"
    );
    assert!(peer.seen.lock().iter().any(|m| m == "tasks/get"));
    assert!(redacted(&needles), "the query renewed the dispatch's value");
}

/// A secret rotated while the poll was out withholds the terminal answer the
/// poll brought back: the check runs again on it.
#[tokio::test]
async fn a_rotation_during_the_poll_withholds_its_terminal_answer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (adapter, _needles, peer) = adapter(&dir, true);
    let answer = adapter.query(&handle(), Duration::from_secs(5)).await;
    assert!(peer.seen.lock().iter().any(|m| m == "tasks/get"), "premise");
    match answer {
        UpstreamAnswer::Substituted(error) => {
            assert_eq!(error.message, super::secrets::WITHHELD);
        }
        _ => panic!("the terminal answer after a rotation was not withheld"),
    }
}

/// A task whose secret no longer matches is withheld before its poll:
/// nothing is sent to the peer, so its log never meets the old value, and
/// the answer is the withheld one.
#[tokio::test]
async fn a_mismatched_task_is_withheld_without_a_poll() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (adapter, _needles, peer) = adapter(&dir, false);
    let mut rotated = handle();
    rotated.fingerprint =
        Some(Dispatched::of("peer", &[("api".to_owned(), ROTATED.to_owned())]).stored());
    let answer = adapter.query(&rotated, Duration::from_secs(5)).await;
    assert!(
        !peer.seen.lock().iter().any(|m| m == "tasks/get"),
        "a mismatched task was polled: {:?}",
        peer.seen.lock()
    );
    match answer {
        UpstreamAnswer::Substituted(error) => assert_eq!(error.message, super::secrets::WITHHELD),
        _ => panic!("a mismatched task was not withheld"),
    }
}
