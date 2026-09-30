// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COLLUDE.1 2a-i: relay detection on the direct route (`/mcp/{backend}`),
//! test plan rows A1-A14 (design `2026-09-28-asi10-verbatim-relay.md` §13.1).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use crate::backend::Backend;
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::idempotency::IdempotencyCache;
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::{CollusionAction, CollusionConfig, Firewall, FirewallConfig};
use crate::transport::Transport;

/// Ordinary prose, long enough for several fingerprints, with nothing any
/// other scanner reacts to.
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost. It closes with the \
    count of crates sent to the cooperative press and a note about the broken ladder by the barn.";

/// How backend `alpha` answers `read`.
#[derive(Clone)]
enum Read {
    /// `content[0].text` = this text.
    Text(String),
    /// A JSON-RPC error carrying [`PROSE`] in its message, no result.
    Error,
    /// Both a result and an error, as a non-conformant backend may send.
    Both,
    /// A result carrying a backend-supplied context-integrity verdict.
    Classified(&'static str),
}

/// Backend `alpha`: `read` answers per [`Read`]; `send` counts deliveries.
struct Alpha {
    read: Arc<Mutex<Read>>,
    reads: Arc<AtomicUsize>,
    sends: Arc<AtomicUsize>,
}

fn text_result(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": false})
}

#[async_trait::async_trait]
impl Transport for Alpha {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            let tools: Vec<Value> = ["read", "send"]
                .iter()
                .map(|n| json!({"name": n, "description": "A tool.", "inputSchema": {"type": "object"}}))
                .collect();
            return Ok(JsonRpcResponse::success(id, json!({ "tools": tools })));
        }
        let name = params
            .as_ref()
            .and_then(|p| p["name"].as_str())
            .unwrap_or_default();
        if name == "send" {
            self.sends.fetch_add(1, Ordering::SeqCst);
            return Ok(JsonRpcResponse::success(id, text_result("sent")));
        }
        self.reads.fetch_add(1, Ordering::SeqCst);
        let read = self.read.lock().unwrap().clone();
        Ok(match read {
            Read::Text(text) => JsonRpcResponse::success(id, text_result(&text)),
            Read::Error => JsonRpcResponse::error(Some(id), -32000, PROSE),
            Read::Both => {
                let mut r = JsonRpcResponse::error(Some(id), -32000, "partial");
                r.result = Some(text_result(PROSE));
                r
            }
            Read::Classified(class) => {
                let mut result = text_result(PROSE);
                result["_context_integrity"] = json!({"classification": {"data_classes": [class]}});
                JsonRpcResponse::success(id, result)
            }
        })
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

struct Fixture {
    state: Arc<super::AppState>,
    read: Arc<Mutex<Read>>,
    reads: Arc<AtomicUsize>,
    sends: Arc<AtomicUsize>,
    _store: tempfile::TempDir,
}

/// What a fixture varies.
struct Setup {
    action: CollusionAction,
    auth: bool,
    passthrough: bool,
    window_secs: u64,
    sources: Vec<String>,
    non_egress: Vec<String>,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            action: CollusionAction::Block,
            auth: true,
            passthrough: false,
            window_secs: 600,
            sources: vec!["alpha:read".to_string()],
            non_egress: Vec::new(),
        }
    }
}

fn key(secret: &[u8], name: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(secret)),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec!["alpha".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
    }
}

async fn fixture(setup: Setup) -> Fixture {
    let auth = AuthConfig {
        enabled: setup.auth,
        api_keys: vec![key(b"a", "alice"), key(b"b", "bob")],
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    };
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let (reads, sends) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let read = Arc::new(Mutex::new(Read::Text(PROSE.to_string())));
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig {
            passthrough: setup.passthrough,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Alpha {
        read: Arc::clone(&read),
        reads: Arc::clone(&reads),
        sends: Arc::clone(&sends),
    }));
    assert!(state_mut.backends.register(Arc::clone(&backend)));
    let config = FirewallConfig {
        // A rule may not soften a relay block.
        rules: serde_yaml::from_str("[{match: \"*\", action: allow}]").unwrap(),
        collusion: CollusionConfig {
            action: setup.action,
            window_secs: setup.window_secs,
            sources: setup.sources,
            non_egress: setup.non_egress,
            ..CollusionConfig::default()
        },
        ..FirewallConfig::default()
    };
    state_mut.firewall = Some(Arc::new(Firewall::from_config(config, None)));
    let mut meta = MetaMcp::new(Arc::clone(&state_mut.backends));
    meta.enable_idempotency(Arc::new(IdempotencyCache::new()), Duration::from_secs(300));
    state_mut.meta_mcp = Arc::new(meta);
    Fixture {
        state,
        read,
        reads,
        sends,
        _store: store,
    }
}

impl Fixture {
    fn sends(&self) -> usize {
        self.sends.load(Ordering::SeqCst)
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    fn answer_read(&self, read: Read) {
        *self.read.lock().unwrap() = read;
    }

    /// POST one `tools/call` to `/mcp/alpha` as bearer `who` (`None`: no
    /// credential); the HTTP status and the body.
    async fn call(&self, who: Option<&str>, body: &Value) -> (u16, String) {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp/alpha")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header(
                "mcp-name",
                body["params"]["name"].as_str().unwrap_or_default(),
            );
        if let Some(who) = who {
            request = request.header("authorization", format!("Bearer {who}"));
        }
        let request = request
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let response = create_router(Arc::clone(&self.state))
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn read(&self, who: Option<&str>) -> String {
        self.call(who, &call("read", &json!({}), None, None))
            .await
            .1
    }

    async fn send(&self, who: Option<&str>, text: &str) -> (u16, String) {
        self.call(who, &call("send", &json!({"text": text}), None, None))
            .await
    }
}

/// A `tools/call` body; `key` sets an idempotency key, `note` a `_meta.note`.
fn call(name: &str, arguments: &Value, key: Option<&str>, note: Option<&str>) -> Value {
    let mut meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                          "io.modelcontextprotocol/clientCapabilities": {}});
    if let Some(key) = key {
        meta[IDEMPOTENCY_KEY_META] = json!(key);
    }
    if let Some(note) = note {
        meta["note"] = json!(note);
    }
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": name, "arguments": arguments, "_meta": meta}})
}

fn assert_refused(fx: &Fixture, (status, body): &(u16, String), sends: usize) {
    assert!(
        body.contains("-32002") && body.contains("Relay detection"),
        "{body}"
    );
    assert_eq!(*status, 403, "{body}");
    assert_eq!(fx.sends(), sends, "the backend was called: {body}");
}

fn assert_sent(fx: &Fixture, (_, body): &(u16, String), sends: usize) {
    assert!(body.contains("sent"), "{body}");
    assert_eq!(fx.sends(), sends, "{body}");
}

/// A1: under `block`, B sending what A was delivered is refused before
/// dispatch and before idempotency admission: the same key then runs clean.
#[tokio::test]
async fn a_relay_is_refused_before_dispatch_and_reserves_nothing() {
    let fx = fixture(Setup::default()).await;
    fx.read(Some("a")).await;
    let relay = call("send", &json!({"text": PROSE}), Some("key-a1"), None);
    assert_refused(&fx, &fx.call(Some("b"), &relay).await, 0);
    let clean = call("send", &json!({"text": "hello"}), Some("key-a1"), None);
    assert_sent(&fx, &fx.call(Some("b"), &clean).await, 1);
}

/// A2: under `observe` the relay is reported, not refused.
#[tokio::test]
async fn observe_lets_a_relay_through() {
    let fx = fixture(Setup {
        action: CollusionAction::Observe,
        ..Setup::default()
    })
    .await;
    fx.read(Some("a")).await;
    assert_sent(&fx, &fx.send(Some("b"), PROSE).await, 1);
}

/// A3: `_meta` is forwarded, so it is checked.
#[tokio::test]
async fn a_relay_in_meta_is_refused() {
    let fx = fixture(Setup::default()).await;
    fx.read(Some("a")).await;
    let relay = call("send", &json!({"text": "hello"}), None, Some(PROSE));
    assert_refused(&fx, &fx.call(Some("b"), &relay).await, 0);
}

/// A4: a caller-supplied `_context_integrity` in the arguments is content.
#[tokio::test]
async fn a_relay_in_argument_context_integrity_is_refused() {
    let fx = fixture(Setup::default()).await;
    fx.read(Some("a")).await;
    let args = json!({"_context_integrity": {"note": PROSE}});
    assert_refused(
        &fx,
        &fx.call(Some("b"), &call("send", &args, None, None)).await,
        0,
    );
}

/// A5: B's own copy from the same source excuses B.
#[tokio::test]
async fn a_callers_own_copy_excuses_it() {
    let fx = fixture(Setup::default()).await;
    fx.read(Some("a")).await;
    fx.read(Some("b")).await;
    assert_sent(&fx, &fx.send(Some("b"), PROSE).await, 1);
}

/// A6: an idempotency replay is a delivery: it renews B's own copy after the
/// first one expired.
#[tokio::test]
async fn a_cached_replay_renews_the_callers_copy() {
    let fx = fixture(Setup {
        window_secs: 1,
        ..Setup::default()
    })
    .await;
    let keyed = call("read", &json!({}), Some("key-a6"), None);
    fx.call(Some("b"), &keyed).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    fx.read(Some("a")).await;
    let reads = fx.reads();
    let (_, replay) = fx.call(Some("b"), &keyed).await;
    assert!(replay.contains("orchard"), "{replay}");
    assert_eq!(
        fx.reads(),
        reads,
        "the re-issue must be a cache hit: {replay}"
    );
    assert_sent(&fx, &fx.send(Some("b"), PROSE).await, 1);
}

/// A7: a `non_egress` target is not checked.
#[tokio::test]
async fn a_non_egress_target_is_not_checked() {
    let non_egress = vec!["alpha:send".to_string()];
    let fx = fixture(Setup {
        non_egress,
        ..Setup::default()
    })
    .await;
    fx.read(Some("a")).await;
    assert_sent(&fx, &fx.send(Some("b"), PROSE).await, 1);
}

/// A8: with no identity, `block` refuses every checked egress; `observe`
/// checks under the shared bucket and never refuses.
#[tokio::test]
async fn an_unkeyed_caller_is_refused_under_block_only() {
    let fx = fixture(Setup {
        auth: false,
        ..Setup::default()
    })
    .await;
    let refused = fx.send(None, "hello").await;
    assert_refused(&fx, &refused, 0);
    assert!(refused.1.contains("authenticated caller"), "{}", refused.1);
    let fx = fixture(Setup {
        auth: false,
        action: CollusionAction::Observe,
        ..Setup::default()
    })
    .await;
    fx.read(None).await;
    assert_sent(&fx, &fx.send(None, PROSE).await, 1);
}

/// A9: an error answer delivers no result, so nothing is recorded.
#[tokio::test]
async fn an_error_answer_records_nothing() {
    let fx = fixture(Setup::default()).await;
    fx.answer_read(Read::Error);
    fx.read(Some("a")).await;
    assert_sent(&fx, &fx.send(Some("b"), PROSE).await, 1);
}

/// A10: a passthrough backend is relay-checked too.
#[tokio::test]
async fn a_passthrough_backend_is_checked() {
    let fx = fixture(Setup {
        passthrough: true,
        ..Setup::default()
    })
    .await;
    fx.read(Some("a")).await;
    assert_refused(&fx, &fx.send(Some("b"), PROSE).await, 0);
}

/// A11: with no `sources`, a context-integrity class marks the delivery
/// sensitive; a public one does not.
#[tokio::test]
async fn a_sensitive_class_marks_a_delivery_sensitive() {
    for (class, refused) in [("personal_data", true), ("public", false)] {
        let fx = fixture(Setup {
            sources: Vec::new(),
            ..Setup::default()
        })
        .await;
        fx.answer_read(Read::Classified(class));
        fx.read(Some("a")).await;
        let sent = fx.send(Some("b"), PROSE).await;
        if refused {
            assert_refused(&fx, &sent, 0);
        } else {
            assert_sent(&fx, &sent, 1);
        }
    }
}

/// A12: a response carrying both a result and an error delivers the result,
/// so it is recorded.
#[tokio::test]
async fn a_result_beside_an_error_is_recorded() {
    let fx = fixture(Setup::default()).await;
    fx.answer_read(Read::Both);
    let (_, answer) = fx
        .call(Some("a"), &call("read", &json!({}), None, None))
        .await;
    assert!(
        answer.contains("orchard"),
        "the result reached the caller: {answer}"
    );
    assert_refused(&fx, &fx.send(Some("b"), PROSE).await, 0);
}

/// A13: past the recording cap, the tail is still recorded.
#[tokio::test]
async fn the_tail_of_an_over_cap_result_is_recorded() {
    let fx = fixture(Setup::default()).await;
    let long: String = (0..12_000).map(|i| format!("w{i} ")).collect();
    fx.answer_read(Read::Text(long.clone()));
    fx.read(Some("a")).await;
    let tail = &long[long.len() - 1_000..];
    assert_refused(&fx, &fx.send(Some("b"), tail).await, 0);
    let cuts = fx.state.firewall.as_ref().unwrap().relay_text_cuts();
    assert_eq!(cuts, 1);
}

/// A14: `off` checks nothing.
#[tokio::test]
async fn off_checks_nothing() {
    let fx = fixture(Setup {
        action: CollusionAction::Off,
        ..Setup::default()
    })
    .await;
    fx.read(Some("a")).await;
    assert_sent(&fx, &fx.send(Some("b"), PROSE).await, 1);
}
