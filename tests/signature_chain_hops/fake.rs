// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A dynamic upstream MCP server that signs its chain with test code, in the
//! mode each row asks for, and records what it received and what it sent.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tokio::task::JoinHandle;

use super::oracle::{CHAIN_KEY, content_digest, link_hash, sign};

pub const NONCE_KEY: &str = "io.mcp-gateway/chain-nonce";
pub const TOOL: &str = "echo";
pub const U_SEED: [u8; 32] = [21; 32];
pub const U_ID: &str = "gw-u";
/// A second trusted key, for wrong-origin, wrong-signer and three-hop rows.
pub const V_SEED: [u8; 32] = [22; 32];
pub const V_ID: &str = "gw-v";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Honest,
    TamperedSignature,
    /// Answers a fixed nonce, never the one it was sent.
    FixedNonce,
    /// Serves its first response again on every later call.
    ReplayFirst,
    /// `ts` this many seconds in the past.
    Stale(u64),
    /// Origin signed by `gw-v`, which the downstream does not accept as origin.
    WrongOrigin,
    /// Honest origin, then a second link by `gw-v`: last signer is not `gw-u`.
    WrongLastSigner,
    /// The chain commits to other content than the result it rides on.
    ChangedContent,
    /// `gw-v` origin plus a `gw-u` link whose `prev` names a removed hop.
    DroppedMiddleHop,
    /// `n` honest-looking padded links, for append-size rows.
    Padded {
        links: usize,
        pad: usize,
    },
    NoChain,
    InputRequired,
    TaskHandle,
}

pub struct FakeUpstream {
    pub url: String,
    mode: Arc<Mutex<Mode>>,
    requests: Arc<Mutex<Vec<Value>>>,
    sent: Arc<Mutex<Vec<Value>>>,
    task: JoinHandle<()>,
}

impl Drop for FakeUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

pub fn result_body() -> Value {
    json!({"content": [{"type": "text", "text": "upstream answered"}], "isError": false})
}

fn link(
    gw: &str,
    up: &str,
    prev: Option<String>,
    input: Option<String>,
    out: &str,
    nonce: &str,
    ts: u64,
) -> Value {
    json!({"v": 1, "alg": "ed25519", "domain": "mcp-gateway-chain-v1", "gw": gw, "up": up,
        "src": "live", "in": input, "out": out, "prev": prev, "nonce": nonce, "ts": ts, "sig": ""})
}

/// The chain `mode` puts on `result` for a request carrying `nonce`.
fn chain_for(mode: Mode, result: &Value, nonce: &str) -> Option<Vec<Value>> {
    let out = content_digest(result);
    let fresh = now();
    let origin =
        |gw: &str, seed, nonce: &str, ts| sign(link(gw, "none", None, None, &out, nonce, ts), seed);
    Some(match mode {
        Mode::Honest | Mode::ReplayFirst => vec![origin(U_ID, U_SEED, nonce, fresh)],
        Mode::TamperedSignature => {
            let mut signed = origin(U_ID, U_SEED, nonce, fresh);
            let sig = signed["sig"].as_str().expect("sig").to_owned();
            let flipped = if sig.starts_with('A') {
                sig.replacen('A', "B", 1)
            } else {
                format!("A{}", &sig[1..])
            };
            signed["sig"] = Value::String(flipped);
            vec![signed]
        }
        Mode::FixedNonce => vec![origin(U_ID, U_SEED, "a-nonce-nobody-sent", fresh)],
        Mode::Stale(age) => vec![origin(U_ID, U_SEED, nonce, fresh.saturating_sub(age))],
        Mode::WrongOrigin => vec![origin(V_ID, V_SEED, nonce, fresh)],
        Mode::WrongLastSigner => {
            let first = origin(U_ID, U_SEED, nonce, fresh);
            let second = link(
                V_ID,
                "verified",
                Some(link_hash(&first)),
                Some(out.clone()),
                &out,
                nonce,
                fresh,
            );
            vec![first, sign(second, V_SEED)]
        }
        Mode::ChangedContent => {
            let other =
                content_digest(&json!({"content": [{"type": "text", "text": "something else"}]}));
            vec![sign(
                link(U_ID, "none", None, None, &other, nonce, fresh),
                U_SEED,
            )]
        }
        Mode::DroppedMiddleHop => {
            let first = origin(V_ID, V_SEED, "v-nonce", fresh);
            let removed = link_hash(&json!({"a removed": "hop"}));
            let last = link(
                U_ID,
                "verified",
                Some(removed),
                Some(out.clone()),
                &out,
                nonce,
                fresh,
            );
            vec![first, sign(last, U_SEED)]
        }
        Mode::Padded { links, pad } => {
            let mut chain = vec![sign(
                link(V_ID, "none", None, None, &out, &"p".repeat(pad), fresh),
                V_SEED,
            )];
            for i in 1..links {
                let (gw, seed) = if i + 1 == links {
                    (U_ID, U_SEED)
                } else {
                    (V_ID, V_SEED)
                };
                let hop_nonce = if i + 1 == links {
                    nonce.to_owned()
                } else {
                    "p".repeat(pad)
                };
                let next = link(
                    gw,
                    "verified",
                    Some(link_hash(&chain[i - 1])),
                    Some(out.clone()),
                    &out,
                    &hop_nonce,
                    fresh,
                );
                chain.push(sign(next, seed));
            }
            chain
        }
        Mode::NoChain | Mode::InputRequired | Mode::TaskHandle => return None,
    })
}

impl FakeUpstream {
    pub async fn start(mode: Mode) -> Self {
        let mode = Arc::new(Mutex::new(mode));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let (m, r, s) = (Arc::clone(&mode), Arc::clone(&requests), Arc::clone(&sent));
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
                let (mode, requests, sent) = (Arc::clone(&m), Arc::clone(&r), Arc::clone(&s));
                async move {
                    axum::Json(answer(
                        &request,
                        *mode.lock().expect("mode"),
                        &requests,
                        &sent,
                    ))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        Self {
            url: format!("http://{address}/"),
            mode,
            requests,
            sent,
            task,
        }
    }

    pub fn set_mode(&self, mode: Mode) {
        *self.mode.lock().expect("mode") = mode;
    }

    /// The `tools/call` requests received, in order.
    pub fn calls(&self) -> Vec<Value> {
        let requests = self.requests.lock().expect("requests");
        requests
            .iter()
            .filter(|r| r["method"] == "tools/call")
            .cloned()
            .collect()
    }

    /// The chain nonce each `tools/call` carried, `None` where absent.
    pub fn outbound_nonces(&self) -> Vec<Option<String>> {
        let calls = self.calls();
        calls
            .iter()
            .map(|c| c["params"]["_meta"][NONCE_KEY].as_str().map(str::to_owned))
            .collect()
    }

    /// The results sent back for each `tools/call`, in order.
    pub fn sent(&self) -> Vec<Value> {
        self.sent.lock().expect("sent").clone()
    }
}

fn answer(
    request: &Value,
    mode: Mode,
    requests: &Mutex<Vec<Value>>,
    sent: &Mutex<Vec<Value>>,
) -> Value {
    requests.lock().expect("requests").push(request.clone());
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let result = match request["method"].as_str() {
        Some("initialize") => {
            json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake-upstream", "version": "test"}})
        }
        Some("tools/list") => json!({"tools": [{"name": TOOL, "description": "fake upstream",
            "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": true}}]}),
        Some("tools/call") => call_result(request, mode, sent),
        Some("notifications/initialized") => return json!({}),
        _ => {
            return json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "unknown"}});
        }
    };
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn call_result(request: &Value, mode: Mode, sent: &Mutex<Vec<Value>>) -> Value {
    let mut sent = sent.lock().expect("sent");
    if mode == Mode::ReplayFirst
        && let Some(first) = sent.first().cloned()
    {
        sent.push(first.clone());
        return first;
    }
    let result = match mode {
        Mode::InputRequired => json!({"resultType": "input_required", "inputRequests": {
            "q": {"method": "elicitation/create", "params": {"message": "continue?",
                "requestedSchema": {"type": "object", "properties": {}}}}}, "requestState": "s"}),
        Mode::TaskHandle => {
            json!({"resultType": "task", "task": {"taskId": "t-1", "status": "working"}})
        }
        _ => {
            let nonce = request["params"]["_meta"][NONCE_KEY]
                .as_str()
                .unwrap_or_default();
            let mut result = result_body();
            if let Some(chain) = chain_for(mode, &result, nonce) {
                result["_meta"] = json!({(CHAIN_KEY): chain});
            }
            result
        }
    };
    sent.push(result.clone());
    result
}
